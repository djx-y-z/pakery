//! SPAKE2 tests for P-256 + SHA-256.
//!
//! Includes RFC 9382 Appendix B test vectors (SPAKE2-P256-SHA256-HKDF-SHA256-HMAC-SHA256).
#![cfg(feature = "p256")]

use pake_core::crypto::{CpaceGroup, Hash};
use pake_crypto::{
    HkdfSha256, HmacSha256, P256Group, Sha256Hash, Sha512Hash, SPAKE2_P256_M_COMPRESSED,
    SPAKE2_P256_N_COMPRESSED,
};
use pake_spake2::{PartyA, PartyB, Spake2Ciphersuite};

/// SPAKE2 ciphersuite: P-256 + SHA-256.
struct Spake2P256Sha256;

impl Spake2Ciphersuite for Spake2P256Sha256 {
    type Group = P256Group;
    type Hash = Sha256Hash;
    type Kdf = HkdfSha256;
    type Mac = HmacSha256;

    const NH: usize = 32;
    const M_BYTES: &'static [u8] = &SPAKE2_P256_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &SPAKE2_P256_N_COMPRESSED;
}

type A = PartyA<Spake2P256Sha256>;
type B = PartyB<Spake2P256Sha256>;

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

/// Derive a password scalar from a password string (for round-trip tests).
fn password_to_scalar(password: &[u8]) -> <P256Group as CpaceGroup>::Scalar {
    let hash = Sha512Hash::digest(password);
    P256Group::scalar_from_wide_bytes(&hash).expect("64-byte hash")
}

// --- RFC 9382 Appendix B test vector ---
// SPAKE2-P256-SHA256-HKDF-SHA256-HMAC-SHA256, A='server', B='client'

const W_HEX: &str = "2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f";
const X_HEX: &str = "43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729";
const Y_HEX: &str = "dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be";

const PA_HEX: &str = "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c";
const PB_HEX: &str = "0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7";
const K_HEX: &str = "0412af7e89717850671913e6b469ace67bd90a4df8ce45c2af19010175e37eed69f75897996d539356e2fa6a406d528501f907e04d97515fbe83db277b715d3325";

// Ke || Ka = Hash(TT) per RFC 9382 §4
// Ke = first half, Ka = second half
const KE_HEX: &str = "0e0672dc86f8e45565d338b0540abe69";
const KCA_HEX: &str = "00c12546835755c86d8c0db7851ae86f";
const KCB_HEX: &str = "a9fa3406c3b781b93d804485430ca27a";
const MAC_A_HEX: &str = "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0";
const MAC_B_HEX: &str = "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b";

#[test]
fn test_rfc9382_vector_pa_pb() {
    let w = scalar_from_hex(W_HEX);
    let x = scalar_from_hex(X_HEX);
    let y = scalar_from_hex(Y_HEX);

    let identity_a = b"server";
    let identity_b = b"client";
    let aad = b"";

    // Verify pA
    let (pa_bytes, _state_a) = A::start_with_scalar(&w, &x, identity_a, identity_b, aad).unwrap();
    assert_eq!(
        hex::encode(&pa_bytes),
        PA_HEX,
        "pA must match RFC 9382 vector"
    );

    // Verify pB
    let (pb_bytes, _state_b) = B::start_with_scalar(&w, &y, identity_a, identity_b, aad).unwrap();
    assert_eq!(
        hex::encode(&pb_bytes),
        PB_HEX,
        "pB must match RFC 9382 vector"
    );
}

#[test]
fn test_rfc9382_vector_shared_secret() {
    // Manually compute K = x * (pB - w*N) using the RFC values
    let w = scalar_from_hex(W_HEX);
    let x = scalar_from_hex(X_HEX);

    let pb = P256Group::from_bytes(&h(PB_HEX)).unwrap();
    let n = P256Group::from_bytes(&SPAKE2_P256_N_COMPRESSED).unwrap();

    // K = x * (pB - w*N)
    let w_n = n.scalar_mul(&w);
    let pb_minus_wn = pb.add(&w_n.negate());
    let k = pb_minus_wn.scalar_mul(&x);
    assert_eq!(
        hex::encode(k.to_bytes()),
        K_HEX,
        "K must match RFC 9382 vector"
    );
}

#[test]
fn test_rfc9382_vector_full_protocol() {
    let w = scalar_from_hex(W_HEX);
    let x = scalar_from_hex(X_HEX);
    let y = scalar_from_hex(Y_HEX);

    let identity_a = b"server";
    let identity_b = b"client";
    let aad = b"";

    let (pa_bytes, state_a) = A::start_with_scalar(&w, &x, identity_a, identity_b, aad).unwrap();
    let (pb_bytes, state_b) = B::start_with_scalar(&w, &y, identity_a, identity_b, aad).unwrap();

    let output_a = state_a.finish(&pb_bytes).unwrap();
    let output_b = state_b.finish(&pa_bytes).unwrap();

    // Session keys must match each other
    assert_eq!(
        output_a.session_key.as_bytes(),
        output_b.session_key.as_bytes(),
        "Session keys must match"
    );

    // Verify session key matches RFC vector
    assert_eq!(
        hex::encode(output_a.session_key.as_bytes()),
        KE_HEX,
        "Session key Ke must match RFC 9382 vector"
    );

    // Verify confirmation MACs match RFC vector
    assert_eq!(
        hex::encode(&output_a.confirmation_mac),
        MAC_A_HEX,
        "A's confirmation MAC must match RFC 9382 vector"
    );
    assert_eq!(
        hex::encode(&output_b.confirmation_mac),
        MAC_B_HEX,
        "B's confirmation MAC must match RFC 9382 vector"
    );

    // Cross-verification
    output_a
        .verify_peer_confirmation(&output_b.confirmation_mac)
        .expect("A should accept B's confirmation");
    output_b
        .verify_peer_confirmation(&output_a.confirmation_mac)
        .expect("B should accept A's confirmation");
}

#[test]
fn test_rfc9382_vector_key_schedule() {
    use pake_core::crypto::Kdf;

    // Hash(TT) from the RFC
    let hash_tt = h("0e0672dc86f8e45565d338b0540abe6915bdf72e2b35b5c9e5663168e960a91b");

    // Ke = first 16, Ka = last 16 (per RFC 9382: "Ke || Ka = Hash(TT)")
    let ke = &hash_tt[..16];
    let ka = &hash_tt[16..32];
    assert_eq!(hex::encode(ke), KE_HEX, "Ke = first half of Hash(TT)");

    // PRK = HKDF-SHA256-Extract(salt=[], ikm=Ka)
    let prk = HkdfSha256::extract(&[], ka);

    // KcA || KcB = HKDF-SHA256-Expand(PRK, "ConfirmationKeys", 32)
    let kc = HkdfSha256::expand(&prk, b"ConfirmationKeys", 32).unwrap();
    let kc_a = &kc[..16];
    let kc_b = &kc[16..];

    assert_eq!(hex::encode(kc_a), KCA_HEX, "KcA must match RFC vector");
    assert_eq!(hex::encode(kc_b), KCB_HEX, "KcB must match RFC vector");
}

// --- Full round-trip (random) ---

#[test]
fn test_full_round_trip() {
    let w = password_to_scalar(b"password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"additional data";

    let mut rng = rand_core::OsRng;

    let (pa_bytes, state_a) = A::start(&w, identity_a, identity_b, aad, &mut rng).unwrap();
    let (pb_bytes, state_b) = B::start(&w, identity_a, identity_b, aad, &mut rng).unwrap();

    let output_a = state_a.finish(&pb_bytes).unwrap();
    let output_b = state_b.finish(&pa_bytes).unwrap();

    assert_eq!(
        output_a.session_key.as_bytes(),
        output_b.session_key.as_bytes(),
        "Session keys must match for same password"
    );

    output_a
        .verify_peer_confirmation(&output_b.confirmation_mac)
        .expect("A should accept B's confirmation");
    output_b
        .verify_peer_confirmation(&output_a.confirmation_mac)
        .expect("B should accept A's confirmation");
}

// --- Wrong password ---

#[test]
fn test_wrong_password_different_keys() {
    let w_correct = password_to_scalar(b"password");
    let w_wrong = password_to_scalar(b"wrong_password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"";

    let mut rng = rand_core::OsRng;

    let (pa_bytes, state_a) = A::start(&w_correct, identity_a, identity_b, aad, &mut rng).unwrap();
    let (pb_bytes, state_b) = B::start(&w_wrong, identity_a, identity_b, aad, &mut rng).unwrap();

    let output_a = state_a.finish(&pb_bytes).unwrap();
    let output_b = state_b.finish(&pa_bytes).unwrap();

    assert_ne!(
        output_a.session_key.as_bytes(),
        output_b.session_key.as_bytes(),
        "Different passwords must produce different session keys"
    );

    assert!(
        output_a
            .verify_peer_confirmation(&output_b.confirmation_mac)
            .is_err(),
        "A should reject B's confirmation (wrong password)"
    );
}

// --- Deterministic replay ---

#[test]
fn test_deterministic_replay() {
    let w = password_to_scalar(b"password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"test";

    let x = password_to_scalar(b"fixed scalar x for party a");
    let y = password_to_scalar(b"fixed scalar y for party b");

    let (pa1, state_a1) = A::start_with_scalar(&w, &x, identity_a, identity_b, aad).unwrap();
    let (pb1, state_b1) = B::start_with_scalar(&w, &y, identity_a, identity_b, aad).unwrap();
    let output_a1 = state_a1.finish(&pb1).unwrap();
    let output_b1 = state_b1.finish(&pa1).unwrap();

    let (pa2, state_a2) = A::start_with_scalar(&w, &x, identity_a, identity_b, aad).unwrap();
    let (pb2, state_b2) = B::start_with_scalar(&w, &y, identity_a, identity_b, aad).unwrap();
    let output_a2 = state_a2.finish(&pb2).unwrap();
    let output_b2 = state_b2.finish(&pa2).unwrap();

    assert_eq!(pa1, pa2, "pA must be deterministic");
    assert_eq!(pb1, pb2, "pB must be deterministic");

    assert_eq!(
        output_a1.session_key.as_bytes(),
        output_a2.session_key.as_bytes(),
        "Session keys must be deterministic"
    );
    assert_eq!(
        output_a1.confirmation_mac, output_a2.confirmation_mac,
        "Confirmation MACs must be deterministic"
    );
    assert_eq!(
        output_b1.confirmation_mac, output_b2.confirmation_mac,
        "Confirmation MACs must be deterministic"
    );
}

// --- Invalid point rejection ---

#[test]
fn test_invalid_point_rejection() {
    let w = password_to_scalar(b"password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"";

    let x = password_to_scalar(b"fixed scalar x");
    let (_, state_a) = A::start_with_scalar(&w, &x, identity_a, identity_b, aad).unwrap();

    // Garbage bytes (65 bytes with 0x04 prefix but invalid coords)
    let mut garbage = [0xffu8; 65];
    garbage[0] = 0x04;
    assert!(
        state_a.finish(&garbage).is_err(),
        "Garbage bytes must be rejected"
    );
}

// --- Identity point rejection ---

#[test]
fn test_identity_point_rejection() {
    let w = password_to_scalar(b"password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"";

    let x = password_to_scalar(b"fixed scalar x");
    let (_, state_a) = A::start_with_scalar(&w, &x, identity_a, identity_b, aad).unwrap();

    // Construct pB = w*N (makes K = x * (pB - w*N) = x * identity = identity)
    let n = P256Group::from_bytes(&SPAKE2_P256_N_COMPRESSED).unwrap();
    let crafted_pb = n.scalar_mul(&w);
    let crafted_pb_bytes = crafted_pb.to_bytes();

    let result = state_a.finish(&crafted_pb_bytes);
    assert!(result.is_err(), "Identity point K must be rejected");
}

// --- Empty identities ---

#[test]
fn test_empty_identities() {
    let w = password_to_scalar(b"password");
    let aad = b"";

    let mut rng = rand_core::OsRng;

    let (pa_bytes, state_a) = A::start(&w, b"", b"", aad, &mut rng).unwrap();
    let (pb_bytes, state_b) = B::start(&w, b"", b"", aad, &mut rng).unwrap();

    let output_a = state_a.finish(&pb_bytes).unwrap();
    let output_b = state_b.finish(&pa_bytes).unwrap();

    assert_eq!(
        output_a.session_key.as_bytes(),
        output_b.session_key.as_bytes(),
        "Empty identities should still produce matching keys"
    );

    output_a
        .verify_peer_confirmation(&output_b.confirmation_mac)
        .expect("confirmation should succeed with empty identities");
    output_b
        .verify_peer_confirmation(&output_a.confirmation_mac)
        .expect("confirmation should succeed with empty identities");
}
