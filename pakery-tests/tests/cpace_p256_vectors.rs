//! CPace tests for P-256 + SHA-512.
//!
//! CPace P-256 uses SHA-512 because hash output must be >= 2*field_size (64 bytes).
//! No RFC test vectors for CPace P-256, so we test round-trip consistency.
#![cfg(feature = "p256")]

use pakery_core::crypto::CpaceGroup;
use pakery_cpace::transcript::CpaceMode;
use pakery_cpace::{CpaceInitiator, CpaceResponder};
use pakery_crypto::{P256Group, Sha512Hash};

/// CPace ciphersuite: P-256 + SHA-512.
struct CpaceP256Sha512;

impl pakery_cpace::CpaceCiphersuite for CpaceP256Sha512 {
    type Group = P256Group;
    type Hash = Sha512Hash;

    const DSI: &'static [u8] = b"CPaceP256";
    const HASH_BLOCK_SIZE: usize = 128; // SHA-512
    const FIELD_SIZE_BYTES: usize = 32;
}

// --- Full round-trip (InitiatorResponder mode) ---

#[test]
fn test_full_round_trip_ir() {
    let prs = b"password";
    let ci = b"channel_info";
    let sid = b"session-id-12345";
    let ad_a = b"initiator_ad";
    let ad_b = b"responder_ad";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    let (ya_bytes, state) =
        CpaceInitiator::<CpaceP256Sha512>::start(prs, ci, sid, ad_a, &mut rng).unwrap();

    let (yb_bytes, resp_output) = CpaceResponder::<CpaceP256Sha512>::respond(
        &ya_bytes,
        prs,
        ci,
        sid,
        ad_a,
        ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng,
    )
    .unwrap();

    let init_output = state
        .finish(&yb_bytes, ad_b, CpaceMode::InitiatorResponder)
        .unwrap();

    assert_eq!(
        init_output.isk.as_bytes(),
        resp_output.isk.as_bytes(),
        "ISK must match between initiator and responder"
    );

    assert_eq!(
        init_output.session_id, resp_output.session_id,
        "Session IDs must match"
    );
}

// --- Full round-trip (Symmetric mode) ---

#[test]
fn test_full_round_trip_symmetric() {
    let prs = b"password";
    let ci = b"channel_info";
    let sid = b"session-id-12345";
    let ad_a = b"ad_alpha";
    let ad_b = b"ad_beta";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    let (ya_bytes, state) =
        CpaceInitiator::<CpaceP256Sha512>::start(prs, ci, sid, ad_a, &mut rng).unwrap();

    let (yb_bytes, resp_output) = CpaceResponder::<CpaceP256Sha512>::respond(
        &ya_bytes,
        prs,
        ci,
        sid,
        ad_a,
        ad_b,
        CpaceMode::Symmetric,
        &mut rng,
    )
    .unwrap();

    let init_output = state.finish(&yb_bytes, ad_b, CpaceMode::Symmetric).unwrap();

    assert_eq!(
        init_output.isk.as_bytes(),
        resp_output.isk.as_bytes(),
        "ISK must match in symmetric mode"
    );

    assert_eq!(
        init_output.session_id, resp_output.session_id,
        "Session IDs must match in symmetric mode"
    );
}

// --- Wrong password ---

#[test]
fn test_wrong_password_fails() {
    let prs_correct = b"correct_password";
    let prs_wrong = b"wrong_password";
    let ci = b"channel_info";
    let sid = b"session-id";
    let ad_a = b"ad_a";
    let ad_b = b"ad_b";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    let (ya_bytes, state) =
        CpaceInitiator::<CpaceP256Sha512>::start(prs_correct, ci, sid, ad_a, &mut rng).unwrap();

    let (yb_bytes, resp_output) = CpaceResponder::<CpaceP256Sha512>::respond(
        &ya_bytes,
        prs_wrong,
        ci,
        sid,
        ad_a,
        ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng,
    )
    .unwrap();

    let init_output = state
        .finish(&yb_bytes, ad_b, CpaceMode::InitiatorResponder)
        .unwrap();

    assert_ne!(
        init_output.isk.as_bytes(),
        resp_output.isk.as_bytes(),
        "Different passwords must produce different ISKs"
    );
}

// --- Invalid point rejection ---

#[test]
fn test_invalid_point_rejection() {
    // Identity point (SEC1 encoding: 0x00)
    let result = P256Group::from_bytes(&[0x00]);
    assert!(
        result.is_err() || result.unwrap().is_identity(),
        "Identity encoding should be rejected or recognized as identity"
    );

    // Garbage uncompressed point
    let mut garbage = [0xffu8; 65];
    garbage[0] = 0x04;
    assert!(
        P256Group::from_bytes(&garbage).is_err(),
        "Garbage uncompressed point must be rejected"
    );

    // Garbage compressed point
    let mut garbage_compressed = [0xffu8; 33];
    garbage_compressed[0] = 0x02;
    assert!(
        P256Group::from_bytes(&garbage_compressed).is_err(),
        "Garbage compressed point must be rejected"
    );
}

// --- Empty password round-trip ---

#[test]
fn test_empty_password_round_trip() {
    let prs = b"";
    let ci = b"channel_info";
    let sid = b"session-id-12345";
    let ad_a = b"ad_a";
    let ad_b = b"ad_b";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    let (ya_bytes, state) =
        CpaceInitiator::<CpaceP256Sha512>::start(prs, ci, sid, ad_a, &mut rng).unwrap();

    let (yb_bytes, resp_output) = CpaceResponder::<CpaceP256Sha512>::respond(
        &ya_bytes,
        prs,
        ci,
        sid,
        ad_a,
        ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng,
    )
    .unwrap();

    let init_output = state
        .finish(&yb_bytes, ad_b, CpaceMode::InitiatorResponder)
        .unwrap();

    assert_eq!(
        init_output.isk.as_bytes(),
        resp_output.isk.as_bytes(),
        "Empty password must produce matching ISKs"
    );
    assert_eq!(
        init_output.session_id, resp_output.session_id,
        "Session IDs must match with empty password"
    );
}

// --- Empty context and identities ---

#[test]
fn test_empty_context_and_identities() {
    let prs = b"password";
    let ci = b"";
    let sid = b"";
    let ad_a = b"";
    let ad_b = b"";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    let (ya_bytes, state) =
        CpaceInitiator::<CpaceP256Sha512>::start(prs, ci, sid, ad_a, &mut rng).unwrap();

    let (yb_bytes, resp_output) = CpaceResponder::<CpaceP256Sha512>::respond(
        &ya_bytes,
        prs,
        ci,
        sid,
        ad_a,
        ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng,
    )
    .unwrap();

    let init_output = state
        .finish(&yb_bytes, ad_b, CpaceMode::InitiatorResponder)
        .unwrap();

    assert_eq!(
        init_output.isk.as_bytes(),
        resp_output.isk.as_bytes(),
        "Empty context/identities must produce matching ISKs"
    );
}
