//! dudect advisory timing harness (see SECURITY_TESTING.md, "Hygiene").
//!
//! Statistical constant-time testing of the secret-comparison paths, per the
//! DudeCT methodology (two input classes, Welch's t-test over runtimes):
//!
//! - `spake2_confirm_verify` — the confirmation-MAC verification path
//!   ([`Spake2Output::verify_peer_confirmation`], the same `ct_eq`-on-`Vec<u8>`
//!   shape used by every confirmation check in the workspace);
//! - `hmac_verify` — [`Mac::verify`] (MAC recomputation + `ct_eq`), the
//!   primitive under the SPAKE2+/OPAQUE confirmation paths whose state
//!   machines consume `self` and therefore cannot be re-measured in a loop;
//! - `shared_secret_eq` — [`SharedSecret`] equality.
//!
//! # Why the verification classes are two *wrong* tags
//!
//! Both verification benches give every sample a tag that fails, and split
//! the classes on where the first mismatching byte falls: Left differs from
//! the correct tag in its first byte, Right only in its last. Each asserts
//! that both classes are rejected before it times anything.
//!
//! The obvious split — correct tag against wrong tag — is the wrong one
//! here, because it separates the classes by the accept/reject *outcome*,
//! which this workspace declares public by design:
//! `pakery_core::ct::declassify_choice` declassifies that decision, and the
//! callers then branch on it to build `Ok` or `Err`. A split along a bit the
//! code is allowed to branch on cannot tell "the comparison leaked" from
//! "the public decision cost something", whatever it reports. Two wrong tags
//! hold the outcome fixed and leave the mismatch position as the only
//! variable: that is the property `ct_eq` exists to provide, and the one an
//! early-exiting comparison would lose.
//!
//! That confound is structural, and it is not the explanation for the
//! historical spikes. Batched timing on arm64 while these classes were being
//! changed put the accept/reject difference under 1% of `Mac::verify` with
//! the sign unstable between runs — noise, at this sample size. The split is
//! unsound because of what it can measure, not because of what it did.
//!
//! `shared_secret_eq` keeps an equal/random split. The same argument applies
//! to it in weaker form: `SharedSecret::eq` returns a `bool` and has no error
//! arm to construct. The difference between the three benches is deliberate,
//! not an oversight.
//!
//! Interpretation: a single `|t| > 5` is a prompt to re-run, not a finding —
//! on byte-identical code these benches have reported -4.55, +20.17 and
//! +3.02 within minutes (README.md carries all five measurements, and what
//! the mismatch-position classes were measured to catch and to miss). Only a
//! signal that reproduces is evidence of a leak, and `|t| < 5` proves nothing
//! either way: another input distribution might still leak. Timing statistics
//! on shared CI runners are noisy, so the workflow running this harness is
//! weekly, advisory and non-blocking (orion pattern) — never a PR gate. The
//! deterministic constant-time check is `ct.yml` (Valgrind + crabgrind).

#![forbid(unsafe_code)]

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use getrandom::SysRng;
use pakery_core::crypto::{CpaceGroup, Hash, Mac};
use pakery_core::SharedSecret;
use pakery_crypto::{HmacSha512, Ristretto255Group, Sha512Hash, Spake2Ristretto255};
use pakery_spake2::{PartyA, PartyB};
use rand_core::UnwrapErr;

/// Measurements per benchmark run (matches upstream dudect-bencher examples).
const SAMPLES: usize = 100_000;

fn rand_bytes(len: usize, rng: &mut BenchRng) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rng.fill(buf.as_mut_slice());
    buf
}

/// Two tags that both fail verification, differing only in where the first
/// mismatching byte falls: the first byte (Left) against the last (Right).
///
/// Holding the accept/reject outcome fixed across the classes is what keeps
/// the bench off the public bit (see the module header); the position of the
/// mismatch is what an early-exiting comparison leaks.
fn mismatch_classes(correct: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert!(
        correct.len() >= 2,
        "a tag under 2 bytes has no distinct first and last position"
    );
    let mut first = correct.to_vec();
    first[0] ^= 0xff;
    let mut last = correct.to_vec();
    *last.last_mut().expect("checked non-empty above") ^= 0xff;
    (first, last)
}

/// SPAKE2 confirmation-MAC verification against one honest protocol run: two
/// rejected peer MACs whose first mismatching byte is the first (Left) or the
/// last (Right) of the tag.
fn spake2_confirm_verify(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut proto_rng = UnwrapErr(SysRng);
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
    let (early, late) = mismatch_classes(&correct_mac);

    // The classes only mean what the module header says they mean if the run
    // is honest and neither class crosses onto the accept path.
    assert!(
        out_a.verify_peer_confirmation(&correct_mac).is_ok(),
        "honest run: A must accept B's confirmation MAC"
    );
    assert!(
        out_a.verify_peer_confirmation(&early).is_err(),
        "Left class must be rejected"
    );
    assert!(
        out_a.verify_peer_confirmation(&late).is_err(),
        "Right class must be rejected"
    );

    let mut inputs: Vec<(Class, Vec<u8>)> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push((Class::Left, early.clone()));
        } else {
            inputs.push((Class::Right, late.clone()));
        }
    }
    for (class, mac) in inputs {
        runner.run_one(class, || out_a.verify_peer_confirmation(&mac));
    }
}

/// `Mac::verify` (recompute + `ct_eq`) for a fixed key and message: two
/// rejected tags whose first mismatching byte is the first (Left) or the last
/// (Right) of the tag.
fn hmac_verify(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = rand_bytes(32, rng);
    let msg = rand_bytes(64, rng);
    let correct_tag = HmacSha512::mac(&key, &msg).expect("HMAC");
    let (early, late) = mismatch_classes(&correct_tag);

    // As above: the setup is only sound if the correct tag verifies and both
    // classes stay on the reject path.
    assert!(
        HmacSha512::verify(&key, &msg, &correct_tag).is_ok(),
        "the recomputed tag must verify"
    );
    assert!(
        HmacSha512::verify(&key, &msg, &early).is_err(),
        "Left class must be rejected"
    );
    assert!(
        HmacSha512::verify(&key, &msg, &late).is_err(),
        "Right class must be rejected"
    );

    let mut inputs: Vec<(Class, Vec<u8>)> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push((Class::Left, early.clone()));
        } else {
            inputs.push((Class::Right, late.clone()));
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
