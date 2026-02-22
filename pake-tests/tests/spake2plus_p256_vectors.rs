//! SPAKE2+ tests for P-256 + SHA-256.
//!
//! RFC 9383 has no P-256 test vectors, so we test round-trip consistency.
#![cfg(feature = "p256")]

use pake_core::crypto::{CpaceGroup, Hash};
use pake_crypto::{
    HkdfSha256, HmacSha256, P256Group, Sha512Hash, SPAKE2_P256_M_COMPRESSED,
    SPAKE2_P256_N_COMPRESSED,
};
use pake_spake2plus::registration::compute_verifier;
use pake_spake2plus::{Prover, Spake2PlusCiphersuite, Verifier};

/// SPAKE2+ ciphersuite: P-256 + SHA-256.
struct Spake2PlusP256Sha256;

impl Spake2PlusCiphersuite for Spake2PlusP256Sha256 {
    type Group = P256Group;
    type Hash = Sha256Hash;
    type Kdf = HkdfSha256;
    type Mac = HmacSha256;

    const NH: usize = 32;
    const M_BYTES: &'static [u8] = &SPAKE2_P256_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &SPAKE2_P256_N_COMPRESSED;
}

// Need Sha256Hash for the ciphersuite
use pake_crypto::Sha256Hash;

type P = Prover<Spake2PlusP256Sha256>;
type V = Verifier<Spake2PlusP256Sha256>;

/// Derive two password scalars (w0, w1) from a password string.
fn password_to_scalars(
    password: &[u8],
) -> (
    <P256Group as CpaceGroup>::Scalar,
    <P256Group as CpaceGroup>::Scalar,
) {
    let mut h0 = <Sha512Hash as Hash>::new();
    h0.update(password);
    h0.update(b"w0");
    let w0_bytes = h0.finalize();
    let w0 = P256Group::scalar_from_wide_bytes(&w0_bytes).expect("64-byte hash");

    let mut h1 = <Sha512Hash as Hash>::new();
    h1.update(password);
    h1.update(b"w1");
    let w1_bytes = h1.finalize();
    let w1 = P256Group::scalar_from_wide_bytes(&w1_bytes).expect("64-byte hash");

    (w0, w1)
}

// --- Registration round-trip ---

#[test]
fn test_registration_round_trip() {
    let (_, w1) = password_to_scalars(b"password");

    let l_bytes = compute_verifier::<Spake2PlusP256Sha256>(&w1);
    let l = P256Group::from_bytes(&l_bytes).expect("L must be a valid point");
    assert!(!l.is_identity(), "L must not be the identity point");

    let expected_l = P256Group::basepoint_mul(&w1);
    assert_eq!(l_bytes, expected_l.to_bytes(), "L must equal w1*G");
}

// --- Full round-trip ---

#[test]
fn test_full_round_trip() {
    let (w0, w1) = password_to_scalars(b"password");
    let l_bytes = compute_verifier::<Spake2PlusP256Sha256>(&w1);

    let context = b"SPAKE2+ P-256 test context";
    let id_prover = b"client";
    let id_verifier = b"server";

    let mut rng = rand_core::OsRng;

    let (share_p_bytes, prover_state) =
        P::start(&w0, &w1, context, id_prover, id_verifier, &mut rng).unwrap();

    let (share_v_bytes, confirm_v, verifier_state) = V::start(
        &share_p_bytes,
        &w0,
        &l_bytes,
        context,
        id_prover,
        id_verifier,
        &mut rng,
    )
    .unwrap();

    let prover_output = prover_state
        .finish(&share_v_bytes, &confirm_v)
        .expect("Prover should accept Verifier's confirmation");

    let verifier_output = verifier_state
        .finish(&prover_output.confirm_p)
        .expect("Verifier should accept Prover's confirmation");

    assert_eq!(
        prover_output.session_key.as_bytes(),
        verifier_output.session_key.as_bytes(),
        "Session keys must match for same password"
    );
}

// --- Wrong password ---

#[test]
fn test_wrong_password_confirmation_fails() {
    let (w0_correct, w1_correct) = password_to_scalars(b"correct_password");
    let l_bytes = compute_verifier::<Spake2PlusP256Sha256>(&w1_correct);

    let (w0_wrong, w1_wrong) = password_to_scalars(b"wrong_password");

    let context = b"test";
    let id_prover = b"client";
    let id_verifier = b"server";
    let mut rng = rand_core::OsRng;

    let (share_p_bytes, prover_state) = P::start(
        &w0_wrong,
        &w1_wrong,
        context,
        id_prover,
        id_verifier,
        &mut rng,
    )
    .unwrap();

    let (share_v_bytes, confirm_v, _verifier_state) = V::start(
        &share_p_bytes,
        &w0_correct,
        &l_bytes,
        context,
        id_prover,
        id_verifier,
        &mut rng,
    )
    .unwrap();

    let result = prover_state.finish(&share_v_bytes, &confirm_v);
    assert!(
        result.is_err(),
        "Prover should reject Verifier's confirmation when using wrong password"
    );
}

// --- Deterministic replay ---

#[test]
fn test_deterministic_replay() {
    let (w0, w1) = password_to_scalars(b"password");
    let l_bytes = compute_verifier::<Spake2PlusP256Sha256>(&w1);

    let context = b"deterministic test";
    let id_prover = b"alice";
    let id_verifier = b"bob";

    let (x, _) = password_to_scalars(b"fixed scalar x for prover");
    let (y, _) = password_to_scalars(b"fixed scalar y for verifier");

    // First run
    let (sp1, ps1) = P::start_with_scalar(&w0, &w1, &x, context, id_prover, id_verifier).unwrap();
    let (sv1, cv1, vs1) =
        V::start_with_scalar(&sp1, &w0, &l_bytes, &y, context, id_prover, id_verifier).unwrap();
    let po1 = ps1.finish(&sv1, &cv1).unwrap();
    let vo1 = vs1.finish(&po1.confirm_p).unwrap();

    // Second run (same scalars)
    let (sp2, ps2) = P::start_with_scalar(&w0, &w1, &x, context, id_prover, id_verifier).unwrap();
    let (sv2, cv2, vs2) =
        V::start_with_scalar(&sp2, &w0, &l_bytes, &y, context, id_prover, id_verifier).unwrap();
    let po2 = ps2.finish(&sv2, &cv2).unwrap();
    let vo2 = vs2.finish(&po2.confirm_p).unwrap();

    assert_eq!(sp1, sp2, "shareP must be deterministic");
    assert_eq!(sv1, sv2, "shareV must be deterministic");
    assert_eq!(cv1, cv2, "confirmV must be deterministic");
    assert_eq!(
        po1.confirm_p, po2.confirm_p,
        "confirmP must be deterministic"
    );
    assert_eq!(
        po1.session_key.as_bytes(),
        po2.session_key.as_bytes(),
        "Prover session keys must be deterministic"
    );
    assert_eq!(
        vo1.session_key.as_bytes(),
        vo2.session_key.as_bytes(),
        "Verifier session keys must be deterministic"
    );
}
