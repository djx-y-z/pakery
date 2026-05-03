//! SPAKE2 tests for P-256 + SHA-256.
//!
//! Includes all 4 RFC 9382 Appendix B test vectors (SPAKE2-P256-SHA256-HKDF-SHA256-HMAC-SHA256).
#![cfg(feature = "p256")]

use pakery_core::crypto::{CpaceGroup, Hash};
use pakery_crypto::{
    HkdfSha256, HmacSha256, P256Group, Sha256Hash, Sha512Hash, SPAKE2_P256_M_COMPRESSED,
    SPAKE2_P256_N_COMPRESSED,
};
use pakery_spake2::{PartyA, PartyB, Spake2Ciphersuite};

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

/// Run a full SPAKE2 protocol with deterministic scalars and verify all RFC outputs.
#[allow(clippy::too_many_arguments)]
fn run_vector_test(
    identity_a: &[u8],
    identity_b: &[u8],
    w_hex: &str,
    x_hex: &str,
    y_hex: &str,
    pa_hex: &str,
    pb_hex: &str,
    ke_hex: &str,
    mac_a_hex: &str,
    mac_b_hex: &str,
) {
    let w = scalar_from_hex(w_hex);
    let x = scalar_from_hex(x_hex);
    let y = scalar_from_hex(y_hex);
    let aad = b"";

    let (pa_bytes, state_a) = A::start_with_scalar(&w, &x, identity_a, identity_b, aad).unwrap();
    let (pb_bytes, state_b) = B::start_with_scalar(&w, &y, identity_a, identity_b, aad).unwrap();

    assert_eq!(hex::encode(&pa_bytes), pa_hex, "pA mismatch");
    assert_eq!(hex::encode(&pb_bytes), pb_hex, "pB mismatch");

    let output_a = state_a.finish(&pb_bytes).unwrap();
    let output_b = state_b.finish(&pa_bytes).unwrap();

    assert_eq!(
        output_a.session_key.as_bytes(),
        output_b.session_key.as_bytes(),
        "Session keys must match"
    );
    assert_eq!(
        hex::encode(output_a.session_key.as_bytes()),
        ke_hex,
        "Ke mismatch"
    );
    assert_eq!(
        hex::encode(&output_a.confirmation_mac),
        mac_a_hex,
        "MAC_A mismatch"
    );
    assert_eq!(
        hex::encode(&output_b.confirmation_mac),
        mac_b_hex,
        "MAC_B mismatch"
    );

    output_a
        .verify_peer_confirmation(&output_b.confirmation_mac)
        .expect("A should accept B's confirmation");
    output_b
        .verify_peer_confirmation(&output_a.confirmation_mac)
        .expect("B should accept A's confirmation");
}

/// Build the transcript and verify Hash(TT) matches the RFC value.
fn verify_transcript(
    identity_a: &[u8],
    identity_b: &[u8],
    pa_hex: &str,
    pb_hex: &str,
    k_hex: &str,
    w_hex: &str,
    hash_tt_hex: &str,
) {
    use pakery_spake2::encoding::build_transcript;

    let tt = build_transcript(
        identity_a,
        identity_b,
        &h(pa_hex),
        &h(pb_hex),
        &h(k_hex),
        &h(w_hex),
    );

    let hash_tt = Sha256Hash::digest(&tt);
    assert_eq!(hex::encode(&hash_tt), hash_tt_hex, "Hash(TT) mismatch");
}

// ============================================================================
// RFC 9382 Appendix B — Vector 1: A="server", B="client"
// ============================================================================

const V1_W: &str = "2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f";
const V1_X: &str = "43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729";
const V1_Y: &str = "dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be";
const V1_PA: &str = "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c";
const V1_PB: &str = "0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7";
const V1_K: &str = "0412af7e89717850671913e6b469ace67bd90a4df8ce45c2af19010175e37eed69f75897996d539356e2fa6a406d528501f907e04d97515fbe83db277b715d3325";
const V1_HASH_TT: &str = "0e0672dc86f8e45565d338b0540abe6915bdf72e2b35b5c9e5663168e960a91b";
const V1_KE: &str = "0e0672dc86f8e45565d338b0540abe69";
const V1_KCA: &str = "00c12546835755c86d8c0db7851ae86f";
const V1_KCB: &str = "a9fa3406c3b781b93d804485430ca27a";
const V1_MAC_A: &str = "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0";
const V1_MAC_B: &str = "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b";

#[test]
fn test_rfc9382_v1_pa_pb() {
    let w = scalar_from_hex(V1_W);
    let x = scalar_from_hex(V1_X);
    let y = scalar_from_hex(V1_Y);

    let (pa_bytes, _) = A::start_with_scalar(&w, &x, b"server", b"client", b"").unwrap();
    assert_eq!(
        hex::encode(&pa_bytes),
        V1_PA,
        "pA must match RFC 9382 vector 1"
    );

    let (pb_bytes, _) = B::start_with_scalar(&w, &y, b"server", b"client", b"").unwrap();
    assert_eq!(
        hex::encode(&pb_bytes),
        V1_PB,
        "pB must match RFC 9382 vector 1"
    );
}

#[test]
fn test_rfc9382_v1_shared_secret() {
    let w = scalar_from_hex(V1_W);
    let x = scalar_from_hex(V1_X);

    let pb = P256Group::from_bytes(&h(V1_PB)).unwrap();
    let n = P256Group::from_bytes(&SPAKE2_P256_N_COMPRESSED).unwrap();

    // K = x * (pB - w*N)
    let w_n = n.scalar_mul(&w);
    let pb_minus_wn = pb.add(&w_n.negate());
    let k = pb_minus_wn.scalar_mul(&x);
    assert_eq!(
        hex::encode(k.to_bytes()),
        V1_K,
        "K must match RFC 9382 vector 1"
    );
}

#[test]
fn test_rfc9382_v1_full_protocol() {
    run_vector_test(
        b"server", b"client", V1_W, V1_X, V1_Y, V1_PA, V1_PB, V1_KE, V1_MAC_A, V1_MAC_B,
    );
}

#[test]
fn test_rfc9382_v1_transcript() {
    verify_transcript(b"server", b"client", V1_PA, V1_PB, V1_K, V1_W, V1_HASH_TT);
}

#[test]
fn test_rfc9382_v1_key_schedule() {
    use pakery_core::crypto::Kdf;

    let hash_tt = h(V1_HASH_TT);

    let ke = &hash_tt[..16];
    let ka = &hash_tt[16..32];
    assert_eq!(hex::encode(ke), V1_KE, "Ke = first half of Hash(TT)");

    let prk = HkdfSha256::extract(&[], ka);
    let kc = HkdfSha256::expand(&prk, b"ConfirmationKeys", 32).unwrap();
    let kc_a = &kc[..16];
    let kc_b = &kc[16..];

    assert_eq!(hex::encode(kc_a), V1_KCA, "KcA must match RFC vector");
    assert_eq!(hex::encode(kc_b), V1_KCB, "KcB must match RFC vector");
}

// ============================================================================
// RFC 9382 Appendix B — Vector 2: A="", B="client"
// ============================================================================

const V2_W: &str = "0548d8729f730589e579b0475a582c1608138ddf7054b73b5381c7e883e2efae";
const V2_X: &str = "403abbe3b1b4b9ba17e3032849759d723939a27a27b9d921c500edde18ed654b";
const V2_Y: &str = "903023b6598908936ea7c929bd761af6039577a9c3f9581064187c3049d87065";
const V2_PA: &str = "04a897b769e681c62ac1c2357319a3d363f610839c4477720d24cbe32f5fd85f44fb92ba966578c1b712be6962498834078262caa5b441ecfa9d4a9485720e918a";
const V2_PB: &str = "04e0f816fd1c35e22065d5556215c097e799390d16661c386e0ecc84593974a61b881a8c82327687d0501862970c64565560cb5671f696048050ca66ca5f8cc7fc";
const V2_K: &str = "048f83ec9f6e4f87cc6f9dc740bdc2769725f923364f01c84148c049a39a735ebda82eac03e00112fd6a5710682767cff5361f7e819e53d8d3c3a2922e0d837aa6";
const V2_HASH_TT: &str = "642f05c473c2cd79909f9a841e2f30a70bf89b18180af97353ba198789c2b963";
const V2_KE: &str = "642f05c473c2cd79909f9a841e2f30a7";
const V2_MAC_A: &str = "47d29e6666af1b7dd450d571233085d7a9866e4d49d2645e2df975489521232b";
const V2_MAC_B: &str = "3313c5cefc361d27fb16847a91c2a73b766ffa90a4839122a9b70a2f6bd1d6df";

#[test]
fn test_rfc9382_v2_full_protocol() {
    run_vector_test(
        b"", b"client", V2_W, V2_X, V2_Y, V2_PA, V2_PB, V2_KE, V2_MAC_A, V2_MAC_B,
    );
}

#[test]
fn test_rfc9382_v2_transcript() {
    verify_transcript(b"", b"client", V2_PA, V2_PB, V2_K, V2_W, V2_HASH_TT);
}

// ============================================================================
// RFC 9382 Appendix B — Vector 3: A="server", B=""
// ============================================================================

const V3_W: &str = "626e0cdc7b14c9db3e52a0b1b3a768c98e37852d5db30febe0497b14eae8c254";
const V3_X: &str = "07adb3db6bc623d3399726bfdbfd3d15a58ea776ab8a308b00392621291f9633";
const V3_Y: &str = "b6a4fc8dbb629d4ba51d6f91ed1532cf87adec98f25dd153a75accafafedec16";
const V3_PA: &str = "04f88fb71c99bfffaea370966b7eb99cd4be0ff1a7d335caac4211c4afd855e2e15a873b298503ad8ba1d9cbb9a392d2ba309b48bfd7879aefd0f2cea6009763b0";
const V3_PB: &str = "040c269d6be017dccb15182ac6bfcd9e2a14de019dd587eaf4bdfd353f031101e7cca177f8eb362a6e83e7d5e729c0732e1b528879c086f39ba0f31a9661bd34db";
const V3_K: &str = "0445ee233b8ecb51ebd6e7da3f307e88a1616bae2166121221fdc0dadb986afaf3ec8a988dc9c626fa3b99f58a7ca7c9b844bb3e8dd9554aafc5b53813504c1cbe";
const V3_HASH_TT: &str = "005184ff460da2ce59062c87733c299c3521297d736598fc0a1127600efa1afb";
const V3_KE: &str = "005184ff460da2ce59062c87733c299c";
const V3_MAC_A: &str = "bc9f9bbe99f26d0b2260e6456e05a86196a3307ec6663a18bf6ac825736533b2";
const V3_MAC_B: &str = "c2370e1bf813b086dff0d834e74425a06e6390f48f5411900276dcccc5a297ec";

#[test]
fn test_rfc9382_v3_full_protocol() {
    run_vector_test(
        b"server", b"", V3_W, V3_X, V3_Y, V3_PA, V3_PB, V3_KE, V3_MAC_A, V3_MAC_B,
    );
}

#[test]
fn test_rfc9382_v3_transcript() {
    verify_transcript(b"server", b"", V3_PA, V3_PB, V3_K, V3_W, V3_HASH_TT);
}

// ============================================================================
// RFC 9382 Appendix B — Vector 4: A="", B=""
// ============================================================================

const V4_W: &str = "7bf46c454b4c1b25799527d896508afd5fc62ef4ec59db1efb49113063d70cca";
const V4_X: &str = "8cef65df64bb2d0f83540c53632de911b5b24b3eab6cc74a97609fd659e95473";
const V4_Y: &str = "d7a66f64074a84652d8d623a92e20c9675c61cb5b4f6a0063e4648a2fdc02d53";
const V4_PA: &str = "04a65b367a3f613cf9f0654b1b28a1e3a8a40387956c8ba6063e8658563890f46ca1ef6a676598889fc28de2950ab8120b79a5ef1ea4c9f44bc98f585634b46d66";
const V4_PB: &str = "04589f13218822710d98d8b2123a079041052d9941b9cf88c6617ddb2fcc0494662eea8ba6b64692dc318250030c6af045cb738bc81ba35b043c3dcb46adf6f58d";
const V4_K: &str = "041a3c03d51b452537ca2a1fea6110353c6d5ed483c4f0f86f4492ca3f378d40a994b4477f93c64d928edbbcd3e85a7c709b7ea73ee97986ce3d1438e135543772";
const V4_HASH_TT: &str = "fc6374762ba5cf11f4b2caa08b2cd1b9907ae0e26e8d6234318d91583cd74c86";
const V4_KE: &str = "fc6374762ba5cf11f4b2caa08b2cd1b9";
const V4_MAC_A: &str = "dfb4db8d48ae5a675963ea5e6c19d98d4ea028d8e898dad96ea19a80ade95dca";
const V4_MAC_B: &str = "d0f0609d1613138d354f7e95f19fb556bf52d751947241e8c7118df5ef0ae175";

#[test]
fn test_rfc9382_v4_full_protocol() {
    run_vector_test(
        b"", b"", V4_W, V4_X, V4_Y, V4_PA, V4_PB, V4_KE, V4_MAC_A, V4_MAC_B,
    );
}

#[test]
fn test_rfc9382_v4_transcript() {
    verify_transcript(b"", b"", V4_PA, V4_PB, V4_K, V4_W, V4_HASH_TT);
}

// ============================================================================
// Non-vector tests
// ============================================================================

#[test]
fn test_full_round_trip() {
    let w = password_to_scalar(b"password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"additional data";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

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

#[test]
fn test_wrong_password_different_keys() {
    let w_correct = password_to_scalar(b"password");
    let w_wrong = password_to_scalar(b"wrong_password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

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

#[test]
fn test_empty_identities() {
    let w = password_to_scalar(b"password");
    let aad = b"";

    let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

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
