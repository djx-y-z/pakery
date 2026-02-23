//! SPAKE2+ tests for P-256 + SHA-256.
//!
//! Includes RFC 9383 Appendix C.1 test vectors (SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256).
#![cfg(feature = "p256")]

use pake_core::crypto::{CpaceGroup, Hash};
use pake_crypto::{
    HkdfSha256, HmacSha256, P256Group, Sha256Hash, Sha512Hash, SPAKE2_P256_M_COMPRESSED,
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

type P = Prover<Spake2PlusP256Sha256>;
type V = Verifier<Spake2PlusP256Sha256>;

fn h(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("valid hex")
}

/// Construct a P-256 scalar from a 32-byte big-endian hex string.
fn scalar_from_hex(hex_str: &str) -> <P256Group as CpaceGroup>::Scalar {
    use p256::elliptic_curve::ff::PrimeField;
    let bytes = h(hex_str);
    let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
    p256::Scalar::from_repr(arr.into()).unwrap()
}

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

// ============================================================================
// RFC 9383 Appendix C.1 — SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256
// ============================================================================

const RFC_CONTEXT: &[u8] = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors";
const RFC_ID_PROVER: &[u8] = b"client";
const RFC_ID_VERIFIER: &[u8] = b"server";

const RFC_W0: &str = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3";
const RFC_W1: &str = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba";
const RFC_L: &str = "04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc00f00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd";
const RFC_X: &str = "d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539";
const RFC_Y: &str = "717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3";

const RFC_SHARE_P: &str = "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727";
const RFC_SHARE_V: &str = "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048";
const RFC_Z: &str = "04bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d50091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c41839";
const RFC_V: &str = "0458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b68";

const RFC_K_MAIN: &str = "4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29";
const RFC_K_CONFIRM_P: &str = "871ae3f7b78445e34438fb284504240239031c39d80ac23eb5ab9be5ad6db58a";
const RFC_K_CONFIRM_V: &str = "ccd53c7c1fa37b64a462b40db8be101cedcf838950162902054e644b400f1680";
const RFC_CONFIRM_V: &str = "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68";
const RFC_CONFIRM_P: &str = "926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527";
const RFC_K_SHARED: &str = "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7";

#[test]
fn test_rfc9383_vector_share_p() {
    // shareP = x*G + w0*M
    let x = scalar_from_hex(RFC_X);
    let w0 = scalar_from_hex(RFC_W0);
    let m = P256Group::from_bytes(&SPAKE2_P256_M_COMPRESSED).unwrap();

    let x_g = P256Group::basepoint_mul(&x);
    let w0_m = m.scalar_mul(&w0);
    let share_p = x_g.add(&w0_m);

    assert_eq!(
        hex::encode(share_p.to_bytes()),
        RFC_SHARE_P,
        "shareP must match RFC 9383 vector"
    );
}

#[test]
fn test_rfc9383_vector_share_v() {
    // shareV = y*G + w0*N
    let y = scalar_from_hex(RFC_Y);
    let w0 = scalar_from_hex(RFC_W0);
    let n = P256Group::from_bytes(&SPAKE2_P256_N_COMPRESSED).unwrap();

    let y_g = P256Group::basepoint_mul(&y);
    let w0_n = n.scalar_mul(&w0);
    let share_v = y_g.add(&w0_n);

    assert_eq!(
        hex::encode(share_v.to_bytes()),
        RFC_SHARE_V,
        "shareV must match RFC 9383 vector"
    );
}

#[test]
fn test_rfc9383_vector_transcript() {
    use pake_spake2plus::encoding::build_transcript;

    // M and N use canonical group encoding (uncompressed for P-256),
    // matching the protocol's transcript construction.
    let m = P256Group::from_bytes(&SPAKE2_P256_M_COMPRESSED).unwrap();
    let n = P256Group::from_bytes(&SPAKE2_P256_N_COMPRESSED).unwrap();

    let tt = build_transcript(
        RFC_CONTEXT,
        RFC_ID_PROVER,
        RFC_ID_VERIFIER,
        &m.to_bytes(),
        &n.to_bytes(),
        &h(RFC_SHARE_P),
        &h(RFC_SHARE_V),
        &h(RFC_Z),
        &h(RFC_V),
        &h(RFC_W0),
    );

    let k_main = Sha256Hash::digest(&tt);
    assert_eq!(
        hex::encode(&k_main),
        RFC_K_MAIN,
        "K_main = SHA-256(TT) must match RFC 9383 vector"
    );
}

#[test]
fn test_rfc9383_vector_key_schedule() {
    use pake_core::crypto::{Kdf, Mac};

    let k_main = h(RFC_K_MAIN);

    // PRK = HKDF-Extract(salt=[], ikm=K_main)
    let prk = HkdfSha256::extract(&[], &k_main);

    // K_confirmP || K_confirmV = HKDF-Expand(PRK, "ConfirmationKeys", 64)
    let kc = HkdfSha256::expand(&prk, b"ConfirmationKeys", 64).unwrap();
    let k_confirm_p = &kc[..32];
    let k_confirm_v = &kc[32..64];

    assert_eq!(
        hex::encode(k_confirm_p),
        RFC_K_CONFIRM_P,
        "K_confirmP must match RFC 9383 vector"
    );
    assert_eq!(
        hex::encode(k_confirm_v),
        RFC_K_CONFIRM_V,
        "K_confirmV must match RFC 9383 vector"
    );

    // K_shared = HKDF-Expand(PRK, "SharedKey", 32)
    let k_shared = HkdfSha256::expand(&prk, b"SharedKey", 32).unwrap();
    assert_eq!(
        hex::encode(&k_shared),
        RFC_K_SHARED,
        "K_shared must match RFC 9383 vector"
    );

    // confirmV = HMAC(K_confirmV, shareP)
    let confirm_v = HmacSha256::mac(k_confirm_v, &h(RFC_SHARE_P)).unwrap();
    assert_eq!(
        hex::encode(&confirm_v),
        RFC_CONFIRM_V,
        "confirmV must match RFC 9383 vector"
    );

    // confirmP = HMAC(K_confirmP, shareV)
    let confirm_p = HmacSha256::mac(k_confirm_p, &h(RFC_SHARE_V)).unwrap();
    assert_eq!(
        hex::encode(&confirm_p),
        RFC_CONFIRM_P,
        "confirmP must match RFC 9383 vector"
    );
}

#[test]
fn test_rfc9383_vector_full_protocol() {
    let w0 = scalar_from_hex(RFC_W0);
    let w1 = scalar_from_hex(RFC_W1);
    let x = scalar_from_hex(RFC_X);
    let y = scalar_from_hex(RFC_Y);
    let l_bytes = h(RFC_L);

    let (share_p_bytes, prover_state) =
        P::start_with_scalar(&w0, &w1, &x, RFC_CONTEXT, RFC_ID_PROVER, RFC_ID_VERIFIER).unwrap();

    assert_eq!(
        hex::encode(&share_p_bytes),
        RFC_SHARE_P,
        "shareP must match RFC 9383 vector"
    );

    let (share_v_bytes, confirm_v, verifier_state) = V::start_with_scalar(
        &share_p_bytes,
        &w0,
        &l_bytes,
        &y,
        RFC_CONTEXT,
        RFC_ID_PROVER,
        RFC_ID_VERIFIER,
    )
    .unwrap();

    assert_eq!(
        hex::encode(&share_v_bytes),
        RFC_SHARE_V,
        "shareV must match RFC 9383 vector"
    );
    assert_eq!(
        hex::encode(&confirm_v),
        RFC_CONFIRM_V,
        "confirmV must match RFC 9383 vector"
    );

    let prover_output = prover_state
        .finish(&share_v_bytes, &confirm_v)
        .expect("Prover should accept Verifier's confirmation");

    assert_eq!(
        hex::encode(&prover_output.confirm_p),
        RFC_CONFIRM_P,
        "confirmP must match RFC 9383 vector"
    );
    assert_eq!(
        hex::encode(prover_output.session_key.as_bytes()),
        RFC_K_SHARED,
        "Prover K_shared must match RFC 9383 vector"
    );

    let verifier_output = verifier_state
        .finish(&prover_output.confirm_p)
        .expect("Verifier should accept Prover's confirmation");

    assert_eq!(
        hex::encode(verifier_output.session_key.as_bytes()),
        RFC_K_SHARED,
        "Verifier K_shared must match RFC 9383 vector"
    );
}

// ============================================================================
// Non-vector tests
// ============================================================================

#[test]
fn test_registration_round_trip() {
    let (_, w1) = password_to_scalars(b"password");

    let l_bytes = compute_verifier::<Spake2PlusP256Sha256>(&w1);
    let l = P256Group::from_bytes(&l_bytes).expect("L must be a valid point");
    assert!(!l.is_identity(), "L must not be the identity point");

    let expected_l = P256Group::basepoint_mul(&w1);
    assert_eq!(l_bytes, expected_l.to_bytes(), "L must equal w1*G");
}

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

// --- Invalid point rejection (Prover receives garbage shareV) ---

#[test]
fn test_invalid_point_rejection_prover() {
    let (w0, w1) = password_to_scalars(b"password");
    let context = b"test";
    let id_prover = b"client";
    let id_verifier = b"server";

    let (x, _) = password_to_scalars(b"fixed scalar x");
    let (_, prover_state) =
        P::start_with_scalar(&w0, &w1, &x, context, id_prover, id_verifier).unwrap();

    // Garbage bytes (invalid SEC1 point)
    let mut garbage = [0xffu8; 33];
    garbage[0] = 0x02;
    let dummy_mac = [0u8; 32];
    assert!(
        prover_state.finish(&garbage, &dummy_mac).is_err(),
        "Garbage bytes must be rejected as shareV"
    );
}

// --- Invalid point rejection (Verifier receives garbage shareP) ---

#[test]
fn test_invalid_point_rejection_verifier() {
    let (w0, w1) = password_to_scalars(b"password");
    let l_bytes = compute_verifier::<Spake2PlusP256Sha256>(&w1);

    let context = b"test";
    let id_prover = b"client";
    let id_verifier = b"server";
    let mut rng = rand_core::OsRng;

    // Garbage shareP
    let mut garbage = [0xffu8; 33];
    garbage[0] = 0x02;
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

// --- Identity Z rejection ---

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
    let n = P256Group::from_bytes(&SPAKE2_P256_N_COMPRESSED).unwrap();
    let crafted_share_v = n.scalar_mul(&w0);
    let crafted_sv_bytes = crafted_share_v.to_bytes();
    let dummy_mac = [0u8; 32];

    let result = prover_state.finish(&crafted_sv_bytes, &dummy_mac);
    assert!(result.is_err(), "Identity Z must be rejected");
}

// --- Verifier-first confirmation order ---

#[test]
fn test_verifier_first_confirmation_order() {
    let (w0, w1) = password_to_scalars(b"password");
    let l_bytes = compute_verifier::<Spake2PlusP256Sha256>(&w1);

    let context = b"order test";
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

    // Tamper with confirmV — prover should reject before producing confirmP
    let mut bad_confirm_v = confirm_v.clone();
    bad_confirm_v[0] ^= 0xff;

    let result = prover_state.finish(&share_v_bytes, &bad_confirm_v);
    assert!(result.is_err(), "Prover must reject tampered confirmV");

    // Verifier never gets confirmP — ordering enforced
    drop(verifier_state);
}

// --- Empty password round-trip ---

#[test]
fn test_empty_password_round_trip() {
    let (w0, w1) = password_to_scalars(b"");
    let l_bytes = compute_verifier::<Spake2PlusP256Sha256>(&w1);

    let context = b"SPAKE2+ empty password test";
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
        .expect("Should succeed with empty password");

    let verifier_output = verifier_state
        .finish(&prover_output.confirm_p)
        .expect("Should succeed with empty password");

    assert_eq!(
        prover_output.session_key.as_bytes(),
        verifier_output.session_key.as_bytes(),
        "Empty password must produce matching session keys"
    );
}

// --- Empty context and identities ---

#[test]
fn test_empty_context_and_identities() {
    let (w0, w1) = password_to_scalars(b"password");
    let l_bytes = compute_verifier::<Spake2PlusP256Sha256>(&w1);

    let context = b"";
    let id_prover = b"";
    let id_verifier = b"";

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
        .expect("Should succeed with empty identities");

    let verifier_output = verifier_state
        .finish(&prover_output.confirm_p)
        .expect("Should succeed with empty identities");

    assert_eq!(
        prover_output.session_key.as_bytes(),
        verifier_output.session_key.as_bytes(),
        "Empty identities should still produce matching keys"
    );
}
