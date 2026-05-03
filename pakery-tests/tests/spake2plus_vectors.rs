//! SPAKE2+ tests for Ristretto255 + SHA-512.
//!
//! RFC 9383 has no Ristretto255 test vectors (only P256-SHA256),
//! so we test round-trip consistency and protocol correctness.

use pakery_core::crypto::{CpaceGroup, Hash};
use pakery_crypto::{
    HkdfSha512, HmacSha512, Ristretto255Group, Sha512Hash, SPAKE2_M_COMPRESSED, SPAKE2_N_COMPRESSED,
};
use pakery_spake2plus::registration::compute_verifier;
use pakery_spake2plus::{Prover, Spake2PlusCiphersuite, Verifier};

/// SPAKE2+ ciphersuite: Ristretto255 + SHA-512.
struct Spake2PlusRistretto255Sha512;

impl Spake2PlusCiphersuite for Spake2PlusRistretto255Sha512 {
    type Group = Ristretto255Group;
    type Hash = Sha512Hash;
    type Kdf = HkdfSha512;
    type Mac = HmacSha512;

    const NH: usize = 64;
    const M_BYTES: &'static [u8] = &SPAKE2_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &SPAKE2_N_COMPRESSED;
}

type P = Prover<Spake2PlusRistretto255Sha512>;
type V = Verifier<Spake2PlusRistretto255Sha512>;

/// Derive two password scalars (w0, w1) from a password string.
fn password_to_scalars(
    password: &[u8],
) -> (
    <Ristretto255Group as CpaceGroup>::Scalar,
    <Ristretto255Group as CpaceGroup>::Scalar,
) {
    // Derive w0 from Hash(password || "w0")
    let mut h0 = <Sha512Hash as Hash>::new();
    h0.update(password);
    h0.update(b"w0");
    let w0_bytes = h0.finalize();
    let w0 = Ristretto255Group::scalar_from_wide_bytes(&w0_bytes).expect("64-byte hash");

    // Derive w1 from Hash(password || "w1")
    let mut h1 = <Sha512Hash as Hash>::new();
    h1.update(password);
    h1.update(b"w1");
    let w1_bytes = h1.finalize();
    let w1 = Ristretto255Group::scalar_from_wide_bytes(&w1_bytes).expect("64-byte hash");

    (w0, w1)
}

// --- Registration round-trip ---

#[test]
fn test_registration_round_trip() {
    let (_, w1) = password_to_scalars(b"password");

    // Compute L = w1*G
    let l_bytes = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1);

    // L should be a valid point
    let l = Ristretto255Group::from_bytes(&l_bytes).expect("L must be a valid point");
    assert!(!l.is_identity(), "L must not be the identity point");

    // L should equal w1*G computed directly
    let expected_l = Ristretto255Group::basepoint_mul(&w1);
    assert_eq!(l_bytes, expected_l.to_bytes(), "L must equal w1*G");
}

// --- Full round-trip ---

#[test]
fn test_full_round_trip() {
    let (w0, w1) = password_to_scalars(b"password");
    let l_bytes = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1);

    let context = b"SPAKE2+ test context";
    let id_prover = b"client";
    let id_verifier = b"server";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    // Prover starts → sends shareP
    let (share_p_bytes, prover_state) =
        P::start(&w0, &w1, context, id_prover, id_verifier, &mut rng).unwrap();

    // Verifier starts → sends (shareV, confirmV)
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

    // Prover finishes: verifies confirmV, produces confirmP
    let prover_output = prover_state
        .finish(&share_v_bytes, &confirm_v)
        .expect("Prover should accept Verifier's confirmation");

    // Verifier finishes: verifies confirmP
    let verifier_output = verifier_state
        .finish(&prover_output.confirm_p)
        .expect("Verifier should accept Prover's confirmation");

    // Session keys must match
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
    let l_bytes = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1_correct);

    let (w0_wrong, w1_wrong) = password_to_scalars(b"wrong_password");

    let context = b"test";
    let id_prover = b"client";
    let id_verifier = b"server";
    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    // Prover uses wrong password
    let (share_p_bytes, prover_state) = P::start(
        &w0_wrong,
        &w1_wrong,
        context,
        id_prover,
        id_verifier,
        &mut rng,
    )
    .unwrap();

    // Verifier uses correct verifier (w0, L)
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

    // Prover should fail to verify confirmV (wrong password → different TT)
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
    let l_bytes = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1);

    let context = b"deterministic test";
    let id_prover = b"alice";
    let id_verifier = b"bob";

    // Use fixed scalars for determinism
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

    // Same public shares
    assert_eq!(sp1, sp2, "shareP must be deterministic");
    assert_eq!(sv1, sv2, "shareV must be deterministic");

    // Same confirmation MACs
    assert_eq!(cv1, cv2, "confirmV must be deterministic");
    assert_eq!(
        po1.confirm_p, po2.confirm_p,
        "confirmP must be deterministic"
    );

    // Same session keys
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

// --- Invalid point rejection ---

#[test]
fn test_invalid_point_rejection_prover() {
    let (w0, w1) = password_to_scalars(b"password");
    let context = b"test";
    let id_prover = b"client";
    let id_verifier = b"server";

    let (x, _) = password_to_scalars(b"fixed scalar x");
    let (_, prover_state) =
        P::start_with_scalar(&w0, &w1, &x, context, id_prover, id_verifier).unwrap();

    // Garbage bytes should be rejected as shareV
    let garbage = [0xffu8; 32];
    let dummy_mac = [0u8; 64];
    assert!(
        prover_state.finish(&garbage, &dummy_mac).is_err(),
        "Garbage bytes must be rejected as shareV"
    );
}

#[test]
fn test_invalid_point_rejection_verifier() {
    let (w0, _w1) = password_to_scalars(b"password");
    let l_bytes = [0u8; 32]; // identity point for L (will be decoded but cause issues)

    let context = b"test";
    let id_prover = b"client";
    let id_verifier = b"server";
    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    // Garbage shareP should be rejected
    let garbage = [0xffu8; 32];
    let result = V::start(
        &garbage,
        &w0,
        &l_bytes,
        context,
        id_prover,
        id_verifier,
        &mut rng,
    );
    assert!(result.is_err(), "Garbage bytes must be rejected as shareP");
}

// --- Identity Z/V rejection ---

#[test]
fn test_identity_z_rejection() {
    // If a malicious Verifier sends shareV = w0*N, then tmp = shareV - w0*N = identity,
    // so Z = x * identity = identity. The protocol should reject this.
    let (w0, w1) = password_to_scalars(b"password");
    let context = b"test";
    let id_prover = b"client";
    let id_verifier = b"server";

    let (x, _) = password_to_scalars(b"fixed scalar x");
    let (_, prover_state) =
        P::start_with_scalar(&w0, &w1, &x, context, id_prover, id_verifier).unwrap();

    // Construct shareV = w0*N (makes tmp = identity, Z = identity)
    let n = Ristretto255Group::from_bytes(&SPAKE2_N_COMPRESSED).unwrap();
    let crafted_share_v = n.scalar_mul(&w0);
    let crafted_sv_bytes = crafted_share_v.to_bytes();
    let dummy_mac = [0u8; 64];

    let result = prover_state.finish(&crafted_sv_bytes, &dummy_mac);
    assert!(result.is_err(), "Identity Z must be rejected");
}

// --- Encoding test ---

#[test]
fn test_10_field_le64_transcript_structure() {
    use pakery_spake2plus::encoding::build_transcript;

    let tt = build_transcript(
        b"context",  // 7 bytes
        b"prover",   // 6 bytes
        b"verifier", // 8 bytes
        b"M",        // 1 byte
        b"N",        // 1 byte
        b"shareP",   // 6 bytes
        b"shareV",   // 6 bytes
        b"Z",        // 1 byte
        b"V",        // 1 byte
        b"w0",       // 2 bytes
    );

    // 10 fields with 8-byte LE length prefix each
    let data_len = 7 + 6 + 8 + 1 + 1 + 6 + 6 + 1 + 1 + 2;
    let expected_len = 10 * 8 + data_len;
    assert_eq!(tt.len(), expected_len, "transcript length must match");

    // Verify first field: context = "context" (len=7)
    assert_eq!(&tt[0..8], &[7, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&tt[8..15], b"context");

    // Verify second field: idProver = "prover" (len=6)
    assert_eq!(&tt[15..23], &[6, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&tt[23..29], b"prover");
}

// --- Empty context/identities ---

#[test]
fn test_empty_context_and_identities() {
    let (w0, w1) = password_to_scalars(b"password");
    let l_bytes = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1);

    let context = b"";
    let id_prover = b"";
    let id_verifier = b"";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    // Both identities and context empty (valid per RFC 9383)
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
        .expect("should succeed with empty context/identities");

    let verifier_output = verifier_state
        .finish(&prover_output.confirm_p)
        .expect("should succeed with empty context/identities");

    assert_eq!(
        prover_output.session_key.as_bytes(),
        verifier_output.session_key.as_bytes(),
        "Empty identities should still produce matching keys"
    );
}

// --- Empty password round-trip ---

#[test]
fn test_empty_password_round_trip() {
    let (w0, w1) = password_to_scalars(b"");
    let l_bytes = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1);

    let context = b"SPAKE2+ empty password test";
    let id_prover = b"client";
    let id_verifier = b"server";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

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
        .expect("Prover should accept Verifier's confirmation with empty password");

    let verifier_output = verifier_state
        .finish(&prover_output.confirm_p)
        .expect("Verifier should accept Prover's confirmation with empty password");

    assert_eq!(
        prover_output.session_key.as_bytes(),
        verifier_output.session_key.as_bytes(),
        "Empty password must produce matching session keys"
    );
}

// --- Verifier-first confirmation order ---

#[test]
fn test_verifier_first_confirmation_order() {
    // Verify that the protocol flow is:
    // 1. Prover sends shareP
    // 2. Verifier sends (shareV, confirmV)
    // 3. Prover verifies confirmV, then sends confirmP
    // 4. Verifier verifies confirmP
    //
    // This test ensures that confirmV is verified before confirmP is computed.
    let (w0, w1) = password_to_scalars(b"password");
    let l_bytes = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1);

    let context = b"order test";
    let id_prover = b"client";
    let id_verifier = b"server";
    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

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

    // If we tamper with confirmV, prover should reject before producing confirmP
    let mut bad_confirm_v = confirm_v.clone();
    bad_confirm_v[0] ^= 0xff;

    let result = prover_state.finish(&share_v_bytes, &bad_confirm_v);
    assert!(result.is_err(), "Prover must reject tampered confirmV");

    // The verifier state is still waiting — it never gets confirmP from a failed prover
    // This proves the ordering: confirmV is verified before confirmP is produced
    drop(verifier_state);
}

// --- Multiple passwords produce different keys ---

#[test]
fn test_different_passwords_different_keys() {
    let (w0_a, w1_a) = password_to_scalars(b"password_a");
    let l_bytes_a = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1_a);

    let (w0_b, w1_b) = password_to_scalars(b"password_b");
    let l_bytes_b = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1_b);

    let context = b"test";
    let id_prover = b"client";
    let id_verifier = b"server";
    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    // Run A
    let (sp_a, ps_a) = P::start(&w0_a, &w1_a, context, id_prover, id_verifier, &mut rng).unwrap();
    let (sv_a, cv_a, vs_a) = V::start(
        &sp_a,
        &w0_a,
        &l_bytes_a,
        context,
        id_prover,
        id_verifier,
        &mut rng,
    )
    .unwrap();
    let po_a = ps_a.finish(&sv_a, &cv_a).unwrap();
    let vo_a = vs_a.finish(&po_a.confirm_p).unwrap();

    // Run B
    let (sp_b, ps_b) = P::start(&w0_b, &w1_b, context, id_prover, id_verifier, &mut rng).unwrap();
    let (sv_b, cv_b, vs_b) = V::start(
        &sp_b,
        &w0_b,
        &l_bytes_b,
        context,
        id_prover,
        id_verifier,
        &mut rng,
    )
    .unwrap();
    let po_b = ps_b.finish(&sv_b, &cv_b).unwrap();
    let vo_b = vs_b.finish(&po_b.confirm_p).unwrap();

    assert_ne!(
        po_a.session_key.as_bytes(),
        po_b.session_key.as_bytes(),
        "Different passwords must produce different session keys"
    );
    assert_ne!(
        vo_a.session_key.as_bytes(),
        vo_b.session_key.as_bytes(),
        "Different passwords must produce different session keys"
    );
}

// --- Consumer methods on output types (v0.2.0 ergonomic API) ---

#[test]
fn prover_output_into_session_key_matches_field_access() {
    let (w0, w1) = password_to_scalars(b"into_session_key");
    let l_bytes = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1);
    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    let (sp, ps) = P::start(&w0, &w1, b"ctx", b"p", b"v", &mut rng).unwrap();
    let (sv, cv, _vs) = V::start(&sp, &w0, &l_bytes, b"ctx", b"p", b"v", &mut rng).unwrap();
    let po = ps.finish(&sv, &cv).unwrap();

    let expected = po.session_key.as_bytes().to_vec();
    let extracted = po.into_session_key();
    assert_eq!(extracted.as_bytes(), expected.as_slice());
}

#[test]
fn prover_output_into_confirm_p_matches_field_access() {
    let (w0, w1) = password_to_scalars(b"into_confirm_p");
    let l_bytes = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1);
    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    let (sp, ps) = P::start(&w0, &w1, b"ctx", b"p", b"v", &mut rng).unwrap();
    let (sv, cv, _vs) = V::start(&sp, &w0, &l_bytes, b"ctx", b"p", b"v", &mut rng).unwrap();
    let po = ps.finish(&sv, &cv).unwrap();

    let expected = po.confirm_p.clone();
    let extracted = po.into_confirm_p();
    assert_eq!(extracted, expected);
}

#[test]
fn spake2plus_output_into_session_key_matches_field_access() {
    let (w0, w1) = password_to_scalars(b"verifier_consumer");
    let l_bytes = compute_verifier::<Spake2PlusRistretto255Sha512>(&w1);
    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

    let (sp, ps) = P::start(&w0, &w1, b"ctx", b"p", b"v", &mut rng).unwrap();
    let (sv, cv, vs) = V::start(&sp, &w0, &l_bytes, b"ctx", b"p", b"v", &mut rng).unwrap();
    let po = ps.finish(&sv, &cv).unwrap();
    let vo = vs.finish(&po.confirm_p).unwrap();

    let expected = vo.session_key.as_bytes().to_vec();
    let extracted = vo.into_session_key();
    assert_eq!(extracted.as_bytes(), expected.as_slice());
}
