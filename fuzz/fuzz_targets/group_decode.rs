//! Fuzz the byte-level entry points of both group backends: point and
//! scalar decoding, Diffie-Hellman, and OPRF evaluate/finalize.
//!
//! Input layout: `[op][cut][payload...]`. `op % 20` selects the operation
//! (0–9 ristretto255, 10–19 P-256); `cut` splits the payload for two-argument
//! operations.
//!
//! Invariants:
//! - Every entry point returns `Ok`/`Err`, never panics or overflows.
//! - ristretto255 `from_bytes` accepts only canonical encodings, so a decoded
//!   point re-encodes byte-identically.
//! - P-256 `from_bytes` accepts compressed and uncompressed SEC1, so the
//!   check is a decode(encode(p)) == p roundtrip instead.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pakery_core::crypto::{CpaceGroup, DhGroup, Oprf, OprfClientState};
use pakery_crypto::{
    P256Dh, P256Group, P256Oprf, Ristretto255Dh, Ristretto255Group, Ristretto255Oprf,
};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

fn split(cut: u8, payload: &[u8]) -> (&[u8], &[u8]) {
    payload.split_at(cut as usize % (payload.len() + 1))
}

fn run<G: CpaceGroup, D: DhGroup, O: Oprf>(
    op: u8,
    cut: u8,
    payload: &[u8],
    strict_roundtrip: bool,
) {
    match op {
        0 => {
            if let Ok(p) = G::from_bytes(payload) {
                let enc = p.to_bytes();
                if strict_roundtrip {
                    assert_eq!(
                        enc, payload,
                        "canonical point encoding not roundtrip-stable"
                    );
                }
                let p2 = G::from_bytes(&enc).expect("re-encoded point failed to decode");
                assert!(p2 == p, "decode(encode(p)) != p");
            }
        }
        1 => {
            let _ = G::from_uniform_bytes(payload);
        }
        2 => {
            let _ = G::scalar_from_wide_bytes(payload);
        }
        3 => {
            let (sk, pk) = split(cut, payload);
            let _ = D::diffie_hellman(sk, pk);
        }
        4 => {
            // Valid secret key, fuzz public key: reaches point validation and
            // the identity-result rejection path.
            let (sk, _) = D::derive_keypair(b"pakery-fuzz-dh-seed").expect("derive_keypair");
            let _ = D::diffie_hellman(&sk, payload);
        }
        5 => {
            let _ = D::public_key_from_private(payload);
        }
        6 => {
            let _ = D::derive_keypair(payload);
        }
        7 => {
            let (key, blinded) = split(cut, payload);
            let _ = O::server_evaluate(key, blinded);
            let _ = O::derive_key(key, blinded);
        }
        8 => {
            let key = O::derive_key(b"pakery-fuzz-oprf-seed", b"fuzz").expect("derive_key");
            let _ = O::server_evaluate(&key, payload);
        }
        _ => {
            let mut rng = ChaCha8Rng::seed_from_u64(0x70616b65_72790001);
            let (state, _blinded) =
                O::client_blind(b"pakery-fuzz-password", &mut rng).expect("client_blind");
            let _ = state.finalize(b"pakery-fuzz-password", payload);
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let [sel, cut, payload @ ..] = input else {
        return;
    };
    let op = sel % 20;
    if op < 10 {
        run::<Ristretto255Group, Ristretto255Dh, Ristretto255Oprf>(op, *cut, payload, true);
    } else {
        run::<P256Group, P256Dh, P256Oprf>(op - 10, *cut, payload, false);
    }
});
