//! CPace tests for P-256 + SHA-512.
//!
//! CPace P-256 uses SHA-512 because hash output must be >= 2*field_size (64 bytes).
//! Our suite differs from the draft's CPACE-P256_XMD:SHA-256_SSWU_NU_ suite
//! (different DSI and hash), so the draft's positive vectors do not apply and
//! we test round-trip consistency instead.
//!
//! The draft's *point-validation* vectors DO apply: they exercise SEC1
//! decoding and the identity check, which are suite-independent. The
//! `official negative vectors` section below consumes G_NistP256_points from
//! draft-irtf-cfrg-cpace-21 appendix B.5.10/B.5.11 (testvectors.json at
//! https://github.com/cfrg/draft-irtf-cfrg-cpace, commit
//! 8fb4056e1b9201927d9f651b9970d9d5660c7892). Re-check on every draft bump.
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

// --- Official negative vectors (draft-irtf-cfrg-cpace-21 B.5.10 / B.5.11) ---

/// B.5.10 "Valid" entry of G_NistP256_points: G.scalar_mult(s, X).
const P256_VALID_MULT_SCALAR_HEX: &str =
    "F012501C091FF9B99A123FFFE571D8BC01E8077EE581362E1BD213990835643B";
const P256_VALID_MULT_POINT_HEX: &str =
    "0424648EB986C2BE0AF636455CEF0550671D6BCD8AA26E0D72FFA1B1FD12BA4E0F\
     78DA2B6D2184F31AF39E566AEF127014B6936C9A37346D10A4AB2514FAEF5831";
const P256_VALID_MULT_RESULT_HEX: &str =
    "04F5A191F078C87C36633B78C701751159D56C59F3FE9105B5720673470F303AB9\
     25B6A7FD1CDD8F649A21CF36B68D9E9C4A11919A951892519786104B27033757";

/// B.5.11 Y_i1: uncompressed SEC1 encoding of a point NOT on the P-256 curve
/// (the "Valid" X with its last byte changed).
const P256_INVALID_Y1_HEX: &str =
    "0424648EB986C2BE0AF636455CEF0550671D6BCD8AA26E0D72FFA1B1FD12BA4E0F\
     78DA2B6D2184F31AF39E566AEF127014B6936C9A37346D10A4AB2514FAEF5857";
/// B.5.11 Y_i2: the SEC1 encoding of the point at infinity (single 0x00 byte).
const P256_INVALID_Y2_HEX: &str = "00";

fn h(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("valid hex")
}

#[test]
fn test_scalar_mult_valid_vector() {
    use p256::elliptic_curve::ff::PrimeField;

    let s_bytes: [u8; 32] = h(P256_VALID_MULT_SCALAR_HEX).try_into().expect("32 bytes");
    let s = p256::Scalar::from_repr(s_bytes.into()).expect("canonical scalar");
    let x = P256Group::from_bytes(&h(P256_VALID_MULT_POINT_HEX)).expect("valid point");
    let result = x.scalar_mul(&s);

    assert_eq!(
        &result.to_bytes()[..],
        &h(P256_VALID_MULT_RESULT_HEX)[..],
        "G.scalar_mult(s, X) must match draft-21 B.5.10 vector"
    );
}

#[test]
fn test_invalid_y1_rejected_by_decoder() {
    // Y_i1 is not on the curve — from_bytes must fail.
    assert!(
        P256Group::from_bytes(&h(P256_INVALID_Y1_HEX)).is_err(),
        "off-curve point Y_i1 must be rejected by SEC1 decoding"
    );
}

#[test]
fn test_invalid_y2_rejected_or_identity() {
    // Y_i2 is the SEC1 point-at-infinity encoding: either the decoder rejects
    // it outright, or it decodes to the identity (which the protocol rejects).
    match P256Group::from_bytes(&h(P256_INVALID_Y2_HEX)) {
        Err(_) => {}
        Ok(p) => assert!(p.is_identity(), "Y_i2 must decode to the identity"),
    }
}

/// draft-21 B.5.11: "When including Y_i1 or Y_i2 in messages of A or B the
/// protocol MUST abort."
#[test]
fn test_invalid_points_abort_protocol() {
    let prs = b"password";
    let ci = b"channel_info";
    let sid = b"session-id";
    let ad_a = b"ad_a";
    let ad_b = b"ad_b";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    for (name, hex) in [("Y_i1", P256_INVALID_Y1_HEX), ("Y_i2", P256_INVALID_Y2_HEX)] {
        let invalid = h(hex);

        // Initiator receives the invalid point as the responder's share.
        let (_, state) =
            CpaceInitiator::<CpaceP256Sha512>::start(prs, ci, sid, ad_a, &mut rng).unwrap();
        assert!(
            state
                .finish(&invalid, ad_b, CpaceMode::InitiatorResponder)
                .is_err(),
            "initiator must abort on {name}"
        );

        // Responder receives the invalid point as the initiator's share.
        assert!(
            CpaceResponder::<CpaceP256Sha512>::respond(
                &invalid,
                prs,
                ci,
                sid,
                ad_a,
                ad_b,
                CpaceMode::InitiatorResponder,
                &mut rng,
            )
            .is_err(),
            "responder must abort on {name}"
        );
    }
}
