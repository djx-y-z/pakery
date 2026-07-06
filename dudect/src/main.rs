//! dudect advisory timing harness (SECURITY_TESTING_ROADMAP.md, item 7).
//!
//! Statistical constant-time testing of the secret-comparison paths, per the
//! DudeCT methodology (fixed-vs-random input classes, Welch's t-test):
//!
//! - `spake2_confirm_verify` — the confirmation-MAC verification path
//!   ([`Spake2Output::verify_peer_confirmation`], the same `ct_eq`-on-`Vec<u8>`
//!   shape used by every confirmation check in the workspace);
//! - `hmac_verify` — [`Mac::verify`] (MAC recomputation + `ct_eq`), the
//!   primitive under the SPAKE2+/OPAQUE confirmation paths whose state
//!   machines consume `self` and therefore cannot be re-measured in a loop;
//! - `shared_secret_eq` — [`SharedSecret`] equality.
//!
//! Interpretation: |t| > 5 is strong evidence of a timing leak and fails the
//! CI job; t < 5 proves nothing (other input distributions might still leak).
//! Timing statistics on shared CI runners are noisy, so the workflow running
//! this harness is weekly, advisory, and non-blocking (orion pattern) — never
//! a PR gate.

#![forbid(unsafe_code)]

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use pakery_core::crypto::{CpaceGroup, Hash, Mac};
use pakery_core::SharedSecret;
use pakery_crypto::{HmacSha512, Ristretto255Group, Sha512Hash, Spake2Ristretto255};
use pakery_spake2::{PartyA, PartyB};
use rand_core::{OsRng, UnwrapErr};

/// Measurements per benchmark run (matches upstream dudect-bencher examples).
const SAMPLES: usize = 100_000;
/// HMAC-SHA512 tag length.
const MAC_LEN: usize = 64;

fn rand_bytes(len: usize, rng: &mut BenchRng) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rng.fill(buf.as_mut_slice());
    buf
}

/// SPAKE2 confirmation-MAC verification: correct peer MAC (Left) vs random
/// MAC (Right) against one honest protocol run.
fn spake2_confirm_verify(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut proto_rng = UnwrapErr(OsRng);
    let digest = Sha512Hash::digest(b"correct horse battery staple");
    let w = <Ristretto255Group as CpaceGroup>::scalar_from_wide_bytes(&digest)
        .expect("SHA-512 output is 64 bytes");

    let (pa, state_a) =
        PartyA::<Spake2Ristretto255>::start(&w, b"client", b"server", b"", &mut proto_rng)
            .expect("SPAKE2 A start");
    let (pb, state_b) =
        PartyB::<Spake2Ristretto255>::start(&w, b"client", b"server", b"", &mut proto_rng)
            .expect("SPAKE2 B start");
    let out_a = state_a.finish(&pb).expect("SPAKE2 A finish");
    let out_b = state_b.finish(&pa).expect("SPAKE2 B finish");
    let correct_mac = out_b.confirmation_mac.clone();

    let mut inputs: Vec<(Class, Vec<u8>)> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push((Class::Left, correct_mac.clone()));
        } else {
            inputs.push((Class::Right, rand_bytes(MAC_LEN, rng)));
        }
    }
    for (class, mac) in inputs {
        runner.run_one(class, || out_a.verify_peer_confirmation(&mac));
    }
}

/// `Mac::verify` (recompute + `ct_eq`): correct tag (Left) vs random tag
/// (Right) for a fixed key and message.
fn hmac_verify(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = rand_bytes(32, rng);
    let msg = rand_bytes(64, rng);
    let correct_tag = HmacSha512::mac(&key, &msg).expect("HMAC");

    let mut inputs: Vec<(Class, Vec<u8>)> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push((Class::Left, correct_tag.clone()));
        } else {
            inputs.push((Class::Right, rand_bytes(MAC_LEN, rng)));
        }
    }
    for (class, tag) in inputs {
        runner.run_one(class, || HmacSha512::verify(&key, &msg, &tag));
    }
}

/// `SharedSecret` equality: equal secret (Left) vs random secret (Right).
fn shared_secret_eq(runner: &mut CtRunner, rng: &mut BenchRng) {
    let secret_bytes = rand_bytes(32, rng);
    let secret = SharedSecret::new(secret_bytes.clone());

    let mut inputs: Vec<(Class, SharedSecret)> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push((Class::Left, SharedSecret::new(secret_bytes.clone())));
        } else {
            inputs.push((Class::Right, SharedSecret::new(rand_bytes(32, rng))));
        }
    }
    for (class, other) in inputs {
        runner.run_one(class, || secret == other);
    }
}

ctbench_main!(spake2_confirm_verify, hmac_verify, shared_secret_eq);
