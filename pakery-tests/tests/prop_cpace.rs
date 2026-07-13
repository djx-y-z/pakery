//! Property-based self-play tests for CPace (draft-irtf-cfrg-cpace).
//!
//! Suites: `CpaceRistretto255` (always) and `CpaceP256` (feature `p256`).
//! All randomness is driven through a `ChaCha20Rng` seeded from a
//! proptest-generated `u64`, so every case is reproducible from the
//! proptest seed.
//!
//! Properties (see SECURITY_TESTING.md, "Property-based tests"):
//! 1. Agreement: identical password/CI/sid/AD on both sides, in both modes,
//!    yields an identical ISK and session id.
//! 2. Mismatch: any single differing transcript input (password, CI, sid,
//!    AD_initiator, AD_responder) yields differing ISKs. CPace has no
//!    confirmation phase, so a mismatch is silent by design — the property
//!    is key inequality, not an error.
//! 3. Tamper rejection: flipping any single byte of Ya or Yb either fails
//!    point decoding/validation (`Err`) or yields differing ISKs — never
//!    silently-agreeing keys.
//! 4. Truncation sweep: every strict prefix (and length extensions) of a
//!    valid share is rejected by the receiving step.

use pakery_cpace::{CpaceCiphersuite, CpaceInitiator, CpaceMode, CpaceResponder};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[derive(Debug, Clone)]
struct Inputs {
    password: Vec<u8>,
    ci: Vec<u8>,
    sid: Vec<u8>,
    ad_initiator: Vec<u8>,
    ad_responder: Vec<u8>,
}

fn bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max_len)
}

fn inputs() -> impl Strategy<Value = Inputs> {
    (bytes(32), bytes(16), bytes(16), bytes(16), bytes(16)).prop_map(
        |(password, ci, sid, ad_initiator, ad_responder)| Inputs {
            password,
            ci,
            sid,
            ad_initiator,
            ad_responder,
        },
    )
}

fn cpace_mode(symmetric: bool) -> CpaceMode {
    if symmetric {
        CpaceMode::Symmetric
    } else {
        CpaceMode::InitiatorResponder
    }
}

/// Property 1: honest self-play produces identical ISKs and session ids.
fn agreement<C: CpaceCiphersuite>(inp: &Inputs, mode: CpaceMode, seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (ya, state) = CpaceInitiator::<C>::start(
        &inp.password,
        &inp.ci,
        &inp.sid,
        &inp.ad_initiator,
        &mut rng,
    )
    .unwrap();
    let (yb, out_b) = CpaceResponder::<C>::respond(
        &ya,
        &inp.password,
        &inp.ci,
        &inp.sid,
        &inp.ad_initiator,
        &inp.ad_responder,
        mode,
        &mut rng,
    )
    .unwrap();
    let out_a = state.finish(&yb, &inp.ad_responder, mode).unwrap();

    assert_eq!(out_a.isk.as_bytes(), out_b.isk.as_bytes());
    assert_eq!(out_a.session_id, out_b.session_id);
}

/// Property 2: a single differing transcript input yields differing ISKs.
fn mismatch<C: CpaceCiphersuite>(inp: &Inputs, field: usize, mode: CpaceMode, seed: u64) {
    let mut responder = inp.clone();
    match field {
        0 => responder.password.push(0x5a),
        1 => responder.ci.push(0x5a),
        2 => responder.sid.push(0x5a),
        3 => responder.ad_initiator.push(0x5a),
        _ => responder.ad_responder.push(0x5a),
    }

    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (ya, state) = CpaceInitiator::<C>::start(
        &inp.password,
        &inp.ci,
        &inp.sid,
        &inp.ad_initiator,
        &mut rng,
    )
    .unwrap();
    let (yb, out_b) = CpaceResponder::<C>::respond(
        &ya,
        &responder.password,
        &responder.ci,
        &responder.sid,
        &responder.ad_initiator,
        &responder.ad_responder,
        mode,
        &mut rng,
    )
    .unwrap();
    let out_a = state.finish(&yb, &inp.ad_responder, mode).unwrap();

    assert_ne!(out_a.isk.as_bytes(), out_b.isk.as_bytes());
}

/// Property 3: a single flipped byte in a share is either rejected or the
/// resulting ISKs disagree.
fn tamper_share<C: CpaceCiphersuite>(
    inp: &Inputs,
    mode: CpaceMode,
    seed: u64,
    tamper_yb: bool,
    idx: prop::sample::Index,
    flip: u8,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (ya, state) = CpaceInitiator::<C>::start(
        &inp.password,
        &inp.ci,
        &inp.sid,
        &inp.ad_initiator,
        &mut rng,
    )
    .unwrap();

    if tamper_yb {
        let (yb, out_b) = CpaceResponder::<C>::respond(
            &ya,
            &inp.password,
            &inp.ci,
            &inp.sid,
            &inp.ad_initiator,
            &inp.ad_responder,
            mode,
            &mut rng,
        )
        .unwrap();
        let mut yb_bad = yb.clone();
        let i = idx.index(yb_bad.len());
        yb_bad[i] ^= flip;
        match state.finish(&yb_bad, &inp.ad_responder, mode) {
            Err(_) => {}
            Ok(out_a) => assert_ne!(out_a.isk.as_bytes(), out_b.isk.as_bytes()),
        }
    } else {
        let mut ya_bad = ya.clone();
        let i = idx.index(ya_bad.len());
        ya_bad[i] ^= flip;
        match CpaceResponder::<C>::respond(
            &ya_bad,
            &inp.password,
            &inp.ci,
            &inp.sid,
            &inp.ad_initiator,
            &inp.ad_responder,
            mode,
            &mut rng,
        ) {
            Err(_) => {}
            Ok((yb, out_b)) => {
                let out_a = state.finish(&yb, &inp.ad_responder, mode).unwrap();
                assert_ne!(out_a.isk.as_bytes(), out_b.isk.as_bytes());
            }
        }
    }
}

/// Property 4: every strict prefix (and extension) of a valid share is
/// rejected by the receiving step.
fn truncation<C: CpaceCiphersuite>() {
    let inp = Inputs {
        password: b"truncation-password".to_vec(),
        ci: b"channel-id".to_vec(),
        sid: b"session-id".to_vec(),
        ad_initiator: b"ad-a".to_vec(),
        ad_responder: b"ad-b".to_vec(),
    };
    let mode = CpaceMode::InitiatorResponder;
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    let (ya, _) = CpaceInitiator::<C>::start(
        &inp.password,
        &inp.ci,
        &inp.sid,
        &inp.ad_initiator,
        &mut rng,
    )
    .unwrap();
    let (yb, _) = CpaceResponder::<C>::respond(
        &ya,
        &inp.password,
        &inp.ci,
        &inp.sid,
        &inp.ad_initiator,
        &inp.ad_responder,
        mode,
        &mut rng,
    )
    .unwrap();

    let mut bad_shares: Vec<Vec<u8>> = Vec::new();
    for len in 0..ya.len() {
        bad_shares.push(ya[..len].to_vec());
    }
    for extra in [1usize, 8] {
        let mut extended = ya.clone();
        extended.resize(extended.len() + extra, 0);
        bad_shares.push(extended);
    }

    for bad in &bad_shares {
        assert!(
            CpaceResponder::<C>::respond(
                bad,
                &inp.password,
                &inp.ci,
                &inp.sid,
                &inp.ad_initiator,
                &inp.ad_responder,
                mode,
                &mut rng,
            )
            .is_err(),
            "responder accepted a share of length {}",
            bad.len()
        );
    }

    let mut bad_responses: Vec<Vec<u8>> = Vec::new();
    for len in 0..yb.len() {
        bad_responses.push(yb[..len].to_vec());
    }
    for extra in [1usize, 8] {
        let mut extended = yb.clone();
        extended.resize(extended.len() + extra, 0);
        bad_responses.push(extended);
    }

    for bad in &bad_responses {
        let (_, state) = CpaceInitiator::<C>::start(
            &inp.password,
            &inp.ci,
            &inp.sid,
            &inp.ad_initiator,
            &mut rng,
        )
        .unwrap();
        assert!(
            state.finish(bad, &inp.ad_responder, mode).is_err(),
            "initiator accepted a responder share of length {}",
            bad.len()
        );
    }
}

macro_rules! cpace_props {
    ($name:ident, $suite:ty) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(32))]

                #[test]
                fn agreement(inp in inputs(), symmetric in any::<bool>(), seed in any::<u64>()) {
                    super::agreement::<$suite>(&inp, cpace_mode(symmetric), seed);
                }

                #[test]
                fn mismatch(
                    inp in inputs(),
                    field in 0usize..5,
                    symmetric in any::<bool>(),
                    seed in any::<u64>(),
                ) {
                    super::mismatch::<$suite>(&inp, field, cpace_mode(symmetric), seed);
                }

                #[test]
                fn tamper_share(
                    inp in inputs(),
                    symmetric in any::<bool>(),
                    seed in any::<u64>(),
                    tamper_yb in any::<bool>(),
                    idx in any::<prop::sample::Index>(),
                    flip in 1u8..,
                ) {
                    super::tamper_share::<$suite>(
                        &inp, cpace_mode(symmetric), seed, tamper_yb, idx, flip,
                    );
                }
            }

            #[test]
            fn truncation_sweep() {
                super::truncation::<$suite>();
            }
        }
    };
}

cpace_props!(ristretto255, pakery_crypto::CpaceRistretto255);
#[cfg(feature = "p256")]
cpace_props!(p256, pakery_crypto::CpaceP256);
