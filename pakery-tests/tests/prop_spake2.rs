//! Property-based self-play tests for SPAKE2 (RFC 9382).
//!
//! Suites: `Spake2Ristretto255` (always) and `Spake2P256` (feature `p256`).
//! The password scalar `w` is derived as `scalar_from_wide_bytes(SHA-512(pw))`
//! (the protocol takes `w` directly; stretching is the caller's job). All
//! randomness is driven through a `ChaCha20Rng` seeded from a
//! proptest-generated `u64`.
//!
//! Properties (SECURITY_TESTING_ROADMAP.md, item 1):
//! 1. Agreement: identical password/identities/aad on both sides yields an
//!    identical session key and mutually valid confirmation MACs.
//! 2. Mismatch: a single differing input (password, idA, idB, aad) makes
//!    confirmation MAC verification fail on both sides; for password and
//!    identity mismatches the session keys also differ (aad feeds only the
//!    confirmation-key KDF per RFC 9382, so key inequality is not asserted
//!    for aad).
//! 3. Tamper rejection: flipping any single byte of a share either fails
//!    decoding (`Err`) or leads to differing keys and mutual confirmation
//!    failure; flipping any byte of a confirmation MAC always fails
//!    verification.
//! 4. Truncation sweep: every strict prefix (and length extensions) of a
//!    valid share or confirmation MAC is rejected.

use pakery_core::crypto::{CpaceGroup, Hash};
use pakery_crypto::Sha512Hash;
use pakery_spake2::{PartyA, PartyB, Spake2Ciphersuite};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[derive(Debug, Clone)]
struct Inputs {
    password: Vec<u8>,
    id_a: Vec<u8>,
    id_b: Vec<u8>,
    aad: Vec<u8>,
}

fn bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max_len)
}

fn inputs() -> impl Strategy<Value = Inputs> {
    (bytes(32), bytes(16), bytes(16), bytes(16)).prop_map(|(password, id_a, id_b, aad)| Inputs {
        password,
        id_a,
        id_b,
        aad,
    })
}

fn pw_scalar<G: CpaceGroup>(password: &[u8]) -> G::Scalar {
    let digest = Sha512Hash::digest(password);
    G::scalar_from_wide_bytes(&digest).expect("SHA-512 output is 64 bytes")
}

/// Property 1: honest self-play agrees on the key and both MACs verify.
fn agreement<C: Spake2Ciphersuite>(inp: &Inputs, seed: u64) {
    let w = pw_scalar::<C::Group>(&inp.password);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let (pa, state_a) = PartyA::<C>::start(&w, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();
    let (pb, state_b) = PartyB::<C>::start(&w, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();

    let out_a = state_a.finish(&pb).unwrap();
    let out_b = state_b.finish(&pa).unwrap();

    assert_eq!(out_a.session_key.as_bytes(), out_b.session_key.as_bytes());
    out_a
        .verify_peer_confirmation(&out_b.confirmation_mac)
        .unwrap();
    out_b
        .verify_peer_confirmation(&out_a.confirmation_mac)
        .unwrap();
}

/// Property 2: a single differing input breaks mutual confirmation (and,
/// except for aad, the session keys).
fn mismatch<C: Spake2Ciphersuite>(inp: &Inputs, field: usize, seed: u64) {
    let mut other = inp.clone();
    match field {
        0 => other.password.push(0x5a),
        1 => other.id_a.push(0x5a),
        2 => other.id_b.push(0x5a),
        _ => other.aad.push(0x5a),
    }

    let w_a = pw_scalar::<C::Group>(&inp.password);
    let w_b = pw_scalar::<C::Group>(&other.password);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let (pa, state_a) = PartyA::<C>::start(&w_a, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();
    let (pb, state_b) =
        PartyB::<C>::start(&w_b, &other.id_a, &other.id_b, &other.aad, &mut rng).unwrap();

    let out_a = state_a.finish(&pb).unwrap();
    let out_b = state_b.finish(&pa).unwrap();

    // aad is not part of the RFC 9382 transcript TT, only of the
    // confirmation-key derivation, so the keys legitimately match there.
    if field != 3 {
        assert_ne!(out_a.session_key.as_bytes(), out_b.session_key.as_bytes());
    }
    assert!(out_a
        .verify_peer_confirmation(&out_b.confirmation_mac)
        .is_err());
    assert!(out_b
        .verify_peer_confirmation(&out_a.confirmation_mac)
        .is_err());
}

/// Property 3a: a single flipped byte in a share never leads to silently
/// agreeing sides.
fn tamper_share<C: Spake2Ciphersuite>(
    inp: &Inputs,
    seed: u64,
    tamper_pb: bool,
    idx: prop::sample::Index,
    flip: u8,
) {
    let w = pw_scalar::<C::Group>(&inp.password);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let (pa, state_a) = PartyA::<C>::start(&w, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();
    let (pb, state_b) = PartyB::<C>::start(&w, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();

    let (honest_share, tampered, receiver_is_a) = if tamper_pb {
        let mut bad = pb.clone();
        let i = idx.index(bad.len());
        bad[i] ^= flip;
        (pa, bad, true)
    } else {
        let mut bad = pa.clone();
        let i = idx.index(bad.len());
        bad[i] ^= flip;
        (pb, bad, false)
    };

    if receiver_is_a {
        let out_b = state_b.finish(&honest_share).unwrap();
        match state_a.finish(&tampered) {
            Err(_) => {}
            Ok(out_a) => {
                assert_ne!(out_a.session_key.as_bytes(), out_b.session_key.as_bytes());
                assert!(out_a
                    .verify_peer_confirmation(&out_b.confirmation_mac)
                    .is_err());
                assert!(out_b
                    .verify_peer_confirmation(&out_a.confirmation_mac)
                    .is_err());
            }
        }
    } else {
        let out_a = state_a.finish(&honest_share).unwrap();
        match state_b.finish(&tampered) {
            Err(_) => {}
            Ok(out_b) => {
                assert_ne!(out_a.session_key.as_bytes(), out_b.session_key.as_bytes());
                assert!(out_a
                    .verify_peer_confirmation(&out_b.confirmation_mac)
                    .is_err());
                assert!(out_b
                    .verify_peer_confirmation(&out_a.confirmation_mac)
                    .is_err());
            }
        }
    }
}

/// Property 3b: a single flipped byte in a confirmation MAC always fails.
fn tamper_mac<C: Spake2Ciphersuite>(inp: &Inputs, seed: u64, idx: prop::sample::Index, flip: u8) {
    let w = pw_scalar::<C::Group>(&inp.password);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let (pa, state_a) = PartyA::<C>::start(&w, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();
    let (pb, state_b) = PartyB::<C>::start(&w, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();
    let out_a = state_a.finish(&pb).unwrap();
    let out_b = state_b.finish(&pa).unwrap();

    let mut bad_mac = out_b.confirmation_mac.clone();
    let i = idx.index(bad_mac.len());
    bad_mac[i] ^= flip;
    assert!(out_a.verify_peer_confirmation(&bad_mac).is_err());

    let mut bad_mac = out_a.confirmation_mac.clone();
    let i = idx.index(bad_mac.len());
    bad_mac[i] ^= flip;
    assert!(out_b.verify_peer_confirmation(&bad_mac).is_err());
}

/// Property 4: strict prefixes and extensions of shares and MACs are rejected.
fn truncation<C: Spake2Ciphersuite>() {
    let inp = Inputs {
        password: b"truncation-password".to_vec(),
        id_a: b"alice".to_vec(),
        id_b: b"bob".to_vec(),
        aad: b"aad".to_vec(),
    };
    let w = pw_scalar::<C::Group>(&inp.password);
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    let (pa, state_a) = PartyA::<C>::start(&w, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();
    let (pb, state_b) = PartyB::<C>::start(&w, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();

    let mut bad_shares: Vec<Vec<u8>> = Vec::new();
    for len in 0..pb.len() {
        bad_shares.push(pb[..len].to_vec());
    }
    for extra in [1usize, 8] {
        let mut extended = pb.clone();
        extended.resize(extended.len() + extra, 0);
        bad_shares.push(extended);
    }

    for bad in &bad_shares {
        let (_, state) = PartyA::<C>::start(&w, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();
        assert!(
            state.finish(bad).is_err(),
            "party A accepted a share of length {}",
            bad.len()
        );
        let (_, state) = PartyB::<C>::start(&w, &inp.id_a, &inp.id_b, &inp.aad, &mut rng).unwrap();
        assert!(
            state.finish(bad).is_err(),
            "party B accepted a share of length {}",
            bad.len()
        );
    }

    let out_a = state_a.finish(&pb).unwrap();
    let out_b = state_b.finish(&pa).unwrap();

    for len in 0..out_b.confirmation_mac.len() {
        assert!(
            out_a
                .verify_peer_confirmation(&out_b.confirmation_mac[..len])
                .is_err(),
            "party A accepted a MAC of length {len}"
        );
    }
    let mut extended = out_b.confirmation_mac.clone();
    extended.push(0);
    assert!(out_a.verify_peer_confirmation(&extended).is_err());
}

macro_rules! spake2_props {
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
                fn tamper_share(
                    inp in inputs(),
                    seed in any::<u64>(),
                    tamper_pb in any::<bool>(),
                    idx in any::<prop::sample::Index>(),
                    flip in 1u8..,
                ) {
                    super::tamper_share::<$suite>(&inp, seed, tamper_pb, idx, flip);
                }

                #[test]
                fn tamper_mac(
                    inp in inputs(),
                    seed in any::<u64>(),
                    idx in any::<prop::sample::Index>(),
                    flip in 1u8..,
                ) {
                    super::tamper_mac::<$suite>(&inp, seed, idx, flip);
                }
            }

            #[test]
            fn truncation_sweep() {
                super::truncation::<$suite>();
            }
        }
    };
}

spake2_props!(ristretto255, pakery_crypto::Spake2Ristretto255);
#[cfg(feature = "p256")]
spake2_props!(p256, pakery_crypto::Spake2P256);
