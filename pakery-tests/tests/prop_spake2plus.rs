//! Property-based self-play tests for SPAKE2+ (RFC 9383).
//!
//! Suites: `Spake2PlusRistretto255` (always) and `Spake2PlusP256` (feature
//! `p256`). Registration scalars are derived as
//! `w0/w1 = scalar_from_wide_bytes(SHA-512(pw || label))` — the protocol
//! takes `w0`/`w1` directly and password stretching is the caller's job.
//! All randomness is driven through a `ChaCha20Rng` seeded from a
//! proptest-generated `u64`.
//!
//! Properties (see SECURITY_TESTING.md, "Property-based tests"):
//! 1. Agreement: registration followed by an honest login yields identical
//!    session keys on prover and verifier.
//! 2. Mismatch: a wrong prover password, or a differing context/idProver/
//!    idVerifier, makes the prover reject confirmV (`ConfirmationFailed`);
//!    the verifier never accepts a guessed confirmP.
//! 3. Tamper rejection: flipping any single byte of shareP, shareV,
//!    confirmV, or confirmP causes some receiving step to return `Err` —
//!    never a silently-successful login.
//! 4. Truncation sweep: every strict prefix (and length extensions) of each
//!    protocol message is rejected by its receiving step.

use pakery_core::crypto::{CpaceGroup, Hash};
use pakery_crypto::Sha512Hash;
use pakery_spake2plus::{
    compute_verifier, Prover, Spake2PlusCiphersuite, Spake2PlusError, Verifier,
};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[derive(Debug, Clone)]
struct Inputs {
    password: Vec<u8>,
    context: Vec<u8>,
    id_prover: Vec<u8>,
    id_verifier: Vec<u8>,
}

fn bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max_len)
}

fn inputs() -> impl Strategy<Value = Inputs> {
    (bytes(32), bytes(16), bytes(16), bytes(16)).prop_map(
        |(password, context, id_prover, id_verifier)| Inputs {
            password,
            context,
            id_prover,
            id_verifier,
        },
    )
}

type Scalar<C> = <<C as Spake2PlusCiphersuite>::Group as CpaceGroup>::Scalar;

/// Derive (w0, w1) from a password with domain-separated SHA-512.
fn pw_scalars<C: Spake2PlusCiphersuite>(password: &[u8]) -> (Scalar<C>, Scalar<C>) {
    let mut h0 = Sha512Hash::new();
    h0.update(password);
    h0.update(b"pakery-prop-w0");
    let w0 = <C::Group as CpaceGroup>::scalar_from_wide_bytes(&h0.finalize())
        .expect("SHA-512 output is 64 bytes");
    let mut h1 = Sha512Hash::new();
    h1.update(password);
    h1.update(b"pakery-prop-w1");
    let w1 = <C::Group as CpaceGroup>::scalar_from_wide_bytes(&h1.finalize())
        .expect("SHA-512 output is 64 bytes");
    (w0, w1)
}

/// Property 1: honest registration + login agree on the session key.
fn agreement<C: Spake2PlusCiphersuite>(inp: &Inputs, seed: u64) {
    let (w0, w1) = pw_scalars::<C>(&inp.password);
    let l_bytes = compute_verifier::<C>(&w1);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let (share_p, prover_state) = Prover::<C>::start(
        &w0,
        &w1,
        &inp.context,
        &inp.id_prover,
        &inp.id_verifier,
        &mut rng,
    )
    .unwrap();
    let (share_v, confirm_v, verifier_state) = Verifier::<C>::start(
        &share_p,
        &w0,
        &l_bytes,
        &inp.context,
        &inp.id_prover,
        &inp.id_verifier,
        &mut rng,
    )
    .unwrap();
    let prover_out = prover_state.finish(&share_v, &confirm_v).unwrap();
    let verifier_out = verifier_state.finish(&prover_out.confirm_p).unwrap();

    assert_eq!(
        prover_out.session_key.as_bytes(),
        verifier_out.session_key.as_bytes()
    );
}

/// Property 2: wrong password or differing transcript inputs are rejected
/// by the prover's confirmV check; the verifier rejects a guessed confirmP.
fn mismatch<C: Spake2PlusCiphersuite>(inp: &Inputs, field: usize, seed: u64) {
    // The verifier keeps the registered credentials and the original inputs;
    // the prover logs in with one input changed.
    let mut prover_inp = inp.clone();
    match field {
        0 => prover_inp.password.push(0x5a),
        1 => prover_inp.context.push(0x5a),
        2 => prover_inp.id_prover.push(0x5a),
        _ => prover_inp.id_verifier.push(0x5a),
    }

    let (reg_w0, reg_w1) = pw_scalars::<C>(&inp.password);
    let l_bytes = compute_verifier::<C>(&reg_w1);
    let (login_w0, login_w1) = pw_scalars::<C>(&prover_inp.password);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let (share_p, prover_state) = Prover::<C>::start(
        &login_w0,
        &login_w1,
        &prover_inp.context,
        &prover_inp.id_prover,
        &prover_inp.id_verifier,
        &mut rng,
    )
    .unwrap();
    let (share_v, confirm_v, verifier_state) = Verifier::<C>::start(
        &share_p,
        &reg_w0,
        &l_bytes,
        &inp.context,
        &inp.id_prover,
        &inp.id_verifier,
        &mut rng,
    )
    .unwrap();

    match prover_state.finish(&share_v, &confirm_v) {
        Err(Spake2PlusError::ConfirmationFailed) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("prover accepted a mismatched login"),
    }

    // The honest prover never produced confirmP; an all-zero guess must fail.
    assert!(verifier_state.finish(&vec![0u8; C::NH]).is_err());
}

/// Property 3: one flipped byte in any message makes some step fail.
fn tamper<C: Spake2PlusCiphersuite>(
    inp: &Inputs,
    which: usize,
    seed: u64,
    idx: prop::sample::Index,
    flip: u8,
) {
    let (w0, w1) = pw_scalars::<C>(&inp.password);
    let l_bytes = compute_verifier::<C>(&w1);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let (share_p, prover_state) = Prover::<C>::start(
        &w0,
        &w1,
        &inp.context,
        &inp.id_prover,
        &inp.id_verifier,
        &mut rng,
    )
    .unwrap();

    if which == 0 {
        // Tampered shareP: either the verifier rejects it outright, or the
        // transcripts diverge and the prover rejects confirmV.
        let mut bad = share_p.clone();
        let i = idx.index(bad.len());
        bad[i] ^= flip;
        match Verifier::<C>::start(
            &bad,
            &w0,
            &l_bytes,
            &inp.context,
            &inp.id_prover,
            &inp.id_verifier,
            &mut rng,
        ) {
            Err(_) => {}
            Ok((share_v, confirm_v, _)) => {
                assert!(prover_state.finish(&share_v, &confirm_v).is_err());
            }
        }
        return;
    }

    let (share_v, confirm_v, verifier_state) = Verifier::<C>::start(
        &share_p,
        &w0,
        &l_bytes,
        &inp.context,
        &inp.id_prover,
        &inp.id_verifier,
        &mut rng,
    )
    .unwrap();

    match which {
        1 => {
            let mut bad = share_v.clone();
            let i = idx.index(bad.len());
            bad[i] ^= flip;
            assert!(prover_state.finish(&bad, &confirm_v).is_err());
        }
        2 => {
            let mut bad = confirm_v.clone();
            let i = idx.index(bad.len());
            bad[i] ^= flip;
            assert!(prover_state.finish(&share_v, &bad).is_err());
        }
        _ => {
            let prover_out = prover_state.finish(&share_v, &confirm_v).unwrap();
            let mut bad = prover_out.confirm_p.clone();
            let i = idx.index(bad.len());
            bad[i] ^= flip;
            assert!(verifier_state.finish(&bad).is_err());
        }
    }
}

/// Property 4: strict prefixes and extensions of every message are rejected.
fn truncation<C: Spake2PlusCiphersuite>() {
    let inp = Inputs {
        password: b"truncation-password".to_vec(),
        context: b"context".to_vec(),
        id_prover: b"prover".to_vec(),
        id_verifier: b"verifier".to_vec(),
    };
    let (w0, w1) = pw_scalars::<C>(&inp.password);
    let l_bytes = compute_verifier::<C>(&w1);
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    // A full honest flow, replayed once per truncated message. Each closure
    // call rebuilds the states because finish() consumes them.
    let flow = |rng: &mut ChaCha20Rng| {
        let (share_p, prover_state) = Prover::<C>::start(
            &w0,
            &w1,
            &inp.context,
            &inp.id_prover,
            &inp.id_verifier,
            rng,
        )
        .unwrap();
        let (share_v, confirm_v, verifier_state) = Verifier::<C>::start(
            &share_p,
            &w0,
            &l_bytes,
            &inp.context,
            &inp.id_prover,
            &inp.id_verifier,
            rng,
        )
        .unwrap();
        (share_p, prover_state, share_v, confirm_v, verifier_state)
    };

    let (share_p, _, share_v, confirm_v, _) = flow(&mut rng);

    let with_variants = |msg: &[u8]| {
        let mut variants: Vec<Vec<u8>> = (0..msg.len()).map(|len| msg[..len].to_vec()).collect();
        for extra in [1usize, 8] {
            let mut extended = msg.to_vec();
            extended.resize(extended.len() + extra, 0);
            variants.push(extended);
        }
        variants
    };

    for bad in with_variants(&share_p) {
        assert!(
            Verifier::<C>::start(
                &bad,
                &w0,
                &l_bytes,
                &inp.context,
                &inp.id_prover,
                &inp.id_verifier,
                &mut rng,
            )
            .is_err(),
            "verifier accepted shareP of length {}",
            bad.len()
        );
    }

    for bad in with_variants(&share_v) {
        let (_, prover_state, _, confirm, _) = flow(&mut rng);
        assert!(
            prover_state.finish(&bad, &confirm).is_err(),
            "prover accepted shareV of length {}",
            bad.len()
        );
    }

    for bad in with_variants(&confirm_v) {
        let (_, prover_state, share, _, _) = flow(&mut rng);
        assert!(
            prover_state.finish(&share, &bad).is_err(),
            "prover accepted confirmV of length {}",
            bad.len()
        );
    }

    for len in 0..C::NH {
        let (_, prover_state, share, confirm, verifier_state) = flow(&mut rng);
        let prover_out = prover_state.finish(&share, &confirm).unwrap();
        assert!(
            verifier_state.finish(&prover_out.confirm_p[..len]).is_err(),
            "verifier accepted confirmP of length {len}"
        );
    }
    let (_, prover_state, share, confirm, verifier_state) = flow(&mut rng);
    let prover_out = prover_state.finish(&share, &confirm).unwrap();
    let mut extended = prover_out.confirm_p.clone();
    extended.push(0);
    assert!(verifier_state.finish(&extended).is_err());
}

macro_rules! spake2plus_props {
    ($name:ident, $suite:ty) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(32))]

                #[test]
                fn agreement(inp in inputs(), seed in any::<u64>()) {
                    super::agreement::<$suite>(&inp, seed);
                }

                #[test]
                fn mismatch(inp in inputs(), field in 0usize..4, seed in any::<u64>()) {
                    super::mismatch::<$suite>(&inp, field, seed);
                }

                #[test]
                fn tamper(
                    inp in inputs(),
                    which in 0usize..4,
                    seed in any::<u64>(),
                    idx in any::<prop::sample::Index>(),
                    flip in 1u8..,
                ) {
                    super::tamper::<$suite>(&inp, which, seed, idx, flip);
                }
            }

            #[test]
            fn truncation_sweep() {
                super::truncation::<$suite>();
            }
        }
    };
}

spake2plus_props!(ristretto255, pakery_crypto::Spake2PlusRistretto255);
#[cfg(feature = "p256")]
spake2plus_props!(p256, pakery_crypto::Spake2PlusP256);
