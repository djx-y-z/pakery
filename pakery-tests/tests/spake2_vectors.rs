//! SPAKE2 tests for Ristretto255 + SHA-512.
//!
//! RFC 9382 has no Ristretto255 test vectors (only P256-SHA256),
//! so we test round-trip consistency and constant verification.

use pakery_core::crypto::{CpaceGroup, Hash};
use pakery_crypto::{
    HkdfSha512, HmacSha512, Ristretto255Group, Sha512Hash, SPAKE2_M_COMPRESSED, SPAKE2_N_COMPRESSED,
};
use pakery_spake2::{PartyA, PartyB, Spake2Ciphersuite};

/// SPAKE2 ciphersuite: Ristretto255 + SHA-512.
struct Spake2Ristretto255Sha512;

impl Spake2Ciphersuite for Spake2Ristretto255Sha512 {
    type Group = Ristretto255Group;
    type Hash = Sha512Hash;
    type Kdf = HkdfSha512;
    type Mac = HmacSha512;

    const NH: usize = 64;
    const M_BYTES: &'static [u8] = &SPAKE2_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &SPAKE2_N_COMPRESSED;
}

type A = PartyA<Spake2Ristretto255Sha512>;
type B = PartyB<Spake2Ristretto255Sha512>;

/// Derive a password scalar from a password string.
fn password_to_scalar(password: &[u8]) -> <Ristretto255Group as CpaceGroup>::Scalar {
    let hash = Sha512Hash::digest(password);
    Ristretto255Group::scalar_from_wide_bytes(&hash).expect("64-byte hash")
}

// --- M/N constant verification ---

#[test]
fn test_m_constant_derivation() {
    let hash = Sha512Hash::digest(b"M SPAKE2 ristretto255");
    let point = Ristretto255Group::from_uniform_bytes(&hash).unwrap();
    let compressed = point.to_bytes();
    assert_eq!(
        compressed, SPAKE2_M_COMPRESSED,
        "M constant must match derivation from hash-to-curve"
    );
}

#[test]
fn test_n_constant_derivation() {
    let hash = Sha512Hash::digest(b"N SPAKE2 ristretto255");
    let point = Ristretto255Group::from_uniform_bytes(&hash).unwrap();
    let compressed = point.to_bytes();
    assert_eq!(
        compressed, SPAKE2_N_COMPRESSED,
        "N constant must match derivation from hash-to-curve"
    );
}

// --- Full round-trip ---

#[test]
fn test_full_round_trip() {
    let w = password_to_scalar(b"password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"additional data";

    let mut rng = rand_core::OsRng;

    // Party A starts
    let (pa_bytes, state_a) = A::start(&w, identity_a, identity_b, aad, &mut rng).unwrap();

    // Party B starts
    let (pb_bytes, state_b) = B::start(&w, identity_a, identity_b, aad, &mut rng).unwrap();

    // Party A finishes
    let output_a = state_a.finish(&pb_bytes).unwrap();

    // Party B finishes
    let output_b = state_b.finish(&pa_bytes).unwrap();

    // Session keys must match
    assert_eq!(
        output_a.session_key.as_bytes(),
        output_b.session_key.as_bytes(),
        "Session keys must match for same password"
    );

    // Confirmation: A verifies B's MAC
    output_a
        .verify_peer_confirmation(&output_b.confirmation_mac)
        .expect("A should accept B's confirmation");

    // Confirmation: B verifies A's MAC
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

    // Party A with correct password
    let (pa_bytes, state_a) = A::start(&w_correct, identity_a, identity_b, aad, &mut rng).unwrap();

    // Party B with wrong password
    let (pb_bytes, state_b) = B::start(&w_wrong, identity_a, identity_b, aad, &mut rng).unwrap();

    let output_a = state_a.finish(&pb_bytes).unwrap();
    let output_b = state_b.finish(&pa_bytes).unwrap();

    // Session keys must differ
    assert_ne!(
        output_a.session_key.as_bytes(),
        output_b.session_key.as_bytes(),
        "Different passwords must produce different session keys"
    );

    // Confirmation must fail
    assert!(
        output_a
            .verify_peer_confirmation(&output_b.confirmation_mac)
            .is_err(),
        "A should reject B's confirmation (wrong password)"
    );
    assert!(
        output_b
            .verify_peer_confirmation(&output_a.confirmation_mac)
            .is_err(),
        "B should reject A's confirmation (wrong password)"
    );
}

// --- Deterministic replay ---

#[test]
fn test_deterministic_replay() {
    let w = password_to_scalar(b"password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"test";

    // Use fixed scalars for determinism
    let x = password_to_scalar(b"fixed scalar x for party a");
    let y = password_to_scalar(b"fixed scalar y for party b");

    // First run
    let (pa1, state_a1) = A::start_with_scalar(&w, &x, identity_a, identity_b, aad).unwrap();
    let (pb1, state_b1) = B::start_with_scalar(&w, &y, identity_a, identity_b, aad).unwrap();
    let output_a1 = state_a1.finish(&pb1).unwrap();
    let output_b1 = state_b1.finish(&pa1).unwrap();

    // Second run (same scalars)
    let (pa2, state_a2) = A::start_with_scalar(&w, &x, identity_a, identity_b, aad).unwrap();
    let (pb2, state_b2) = B::start_with_scalar(&w, &y, identity_a, identity_b, aad).unwrap();
    let output_a2 = state_a2.finish(&pb2).unwrap();
    let output_b2 = state_b2.finish(&pa2).unwrap();

    // Same public shares
    assert_eq!(pa1, pa2, "pA must be deterministic");
    assert_eq!(pb1, pb2, "pB must be deterministic");

    // Same session keys
    assert_eq!(
        output_a1.session_key.as_bytes(),
        output_a2.session_key.as_bytes(),
        "Session keys must be deterministic"
    );

    // Same MACs
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

    // Garbage bytes should be rejected
    let garbage = [0xffu8; 32];
    assert!(
        state_a.finish(&garbage).is_err(),
        "Garbage bytes must be rejected"
    );
}

// --- Identity point rejection ---

#[test]
fn test_identity_point_rejection() {
    // If a malicious peer sends a crafted point that leads to K = identity,
    // the protocol should reject it. We test by constructing a scenario where
    // the shared secret K would be identity.
    //
    // Party A computes K = x * (pB - w*N). If pB = w*N, then K = x * identity = identity.
    let w = password_to_scalar(b"password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"";

    let x = password_to_scalar(b"fixed scalar x");
    let (_, state_a) = A::start_with_scalar(&w, &x, identity_a, identity_b, aad).unwrap();

    // Construct pB = w*N (this would make K = identity)
    let n = Ristretto255Group::from_bytes(&SPAKE2_N_COMPRESSED).unwrap();
    let crafted_pb = n.scalar_mul(&w);
    let crafted_pb_bytes = crafted_pb.to_bytes();

    let result = state_a.finish(&crafted_pb_bytes);
    assert!(result.is_err(), "Identity point K must be rejected");
}

// --- Encoding tests ---

#[test]
fn test_le64_encoding_in_transcript() {
    use pakery_spake2::encoding::build_transcript;

    let tt = build_transcript(b"A", b"B", b"pA", b"pB", b"K", b"w");

    // Each field: 8-byte LE length + data
    // "A" → [1,0,0,0,0,0,0,0, 0x41]
    // "B" → [1,0,0,0,0,0,0,0, 0x42]
    // "pA" → [2,0,0,0,0,0,0,0, ...]
    // "pB" → [2,0,0,0,0,0,0,0, ...]
    // "K" → [1,0,0,0,0,0,0,0, ...]
    // "w" → [1,0,0,0,0,0,0,0, ...]
    let expected_len = 6 * 8 + 1 + 1 + 2 + 2 + 1 + 1;
    assert_eq!(tt.len(), expected_len, "transcript length");

    // Check first field encoding: len=1 as LE u64, then 'A'
    assert_eq!(&tt[0..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(tt[8], b'A');
}

// --- Empty password ---

#[test]
fn test_empty_password_round_trip() {
    let w = password_to_scalar(b"");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"";

    let mut rng = rand_core::OsRng;

    let (pa_bytes, state_a) = A::start(&w, identity_a, identity_b, aad, &mut rng).unwrap();
    let (pb_bytes, state_b) = B::start(&w, identity_a, identity_b, aad, &mut rng).unwrap();

    let output_a = state_a.finish(&pb_bytes).unwrap();
    let output_b = state_b.finish(&pa_bytes).unwrap();

    assert_eq!(
        output_a.session_key.as_bytes(),
        output_b.session_key.as_bytes(),
        "Empty password must produce matching session keys"
    );

    output_a
        .verify_peer_confirmation(&output_b.confirmation_mac)
        .expect("A should accept B's confirmation with empty password");
    output_b
        .verify_peer_confirmation(&output_a.confirmation_mac)
        .expect("B should accept A's confirmation with empty password");
}

// --- Identity point encoding as received share ---

#[test]
fn test_identity_encoding_as_received_share() {
    let w = password_to_scalar(b"password");
    let identity_a = b"alice";
    let identity_b = b"bob";
    let aad = b"";

    let mut rng = rand_core::OsRng;

    // Send all-zeros (Ristretto identity encoding) as pB to Party A.
    // Defense-in-depth: identity is rejected before computation.
    let (_, state_a) = A::start(&w, identity_a, identity_b, aad, &mut rng).unwrap();
    let identity_bytes = [0u8; 32];
    let result_a = state_a.finish(&identity_bytes);
    assert!(result_a.is_err(), "identity as pB must be rejected");

    // Send all-zeros as pA to Party B — same reasoning.
    let (_, state_b) = B::start(&w, identity_a, identity_b, aad, &mut rng).unwrap();
    let result_b = state_b.finish(&identity_bytes);
    assert!(result_b.is_err(), "identity as pA must be rejected");
}

// --- Empty identities ---

#[test]
fn test_empty_identities() {
    let w = password_to_scalar(b"password");
    let aad = b"";

    let mut rng = rand_core::OsRng;

    // Both identities empty (valid per RFC 9382)
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

// --- MAC confirmation tampering ---

#[test]
fn test_tampered_confirmation_mac_rejected() {
    let w = password_to_scalar(b"password");
    let mut rng = rand_core::OsRng;

    let (pa_bytes, state_a) = A::start(&w, b"alice", b"bob", b"", &mut rng).unwrap();
    let (pb_bytes, state_b) = B::start(&w, b"alice", b"bob", b"", &mut rng).unwrap();

    let output_a = state_a.finish(&pb_bytes).unwrap();
    let output_b = state_b.finish(&pa_bytes).unwrap();

    // Tamper with each byte position of the MAC
    for i in 0..output_b.confirmation_mac.len() {
        let mut tampered = output_b.confirmation_mac.clone();
        tampered[i] ^= 0x01;
        assert!(
            output_a.verify_peer_confirmation(&tampered).is_err(),
            "tampered MAC byte {i} must be rejected"
        );
    }

    // Truncated MAC
    assert!(
        output_a
            .verify_peer_confirmation(
                &output_b.confirmation_mac[..output_b.confirmation_mac.len() - 1]
            )
            .is_err(),
        "truncated MAC must be rejected"
    );

    // Empty MAC
    assert!(
        output_a.verify_peer_confirmation(&[]).is_err(),
        "empty MAC must be rejected"
    );
}

#[test]
fn test_swapped_confirmation_macs_rejected() {
    let w = password_to_scalar(b"password");
    let mut rng = rand_core::OsRng;

    let (pa_bytes, state_a) = A::start(&w, b"alice", b"bob", b"", &mut rng).unwrap();
    let (pb_bytes, state_b) = B::start(&w, b"alice", b"bob", b"", &mut rng).unwrap();

    let output_a = state_a.finish(&pb_bytes).unwrap();
    let output_b = state_b.finish(&pa_bytes).unwrap();

    // Party A's own MAC sent back to Party A (instead of Party B's MAC)
    assert!(
        output_a
            .verify_peer_confirmation(&output_a.confirmation_mac)
            .is_err(),
        "own MAC must not verify as peer MAC (asymmetric keys)"
    );

    // Party B's own MAC sent back to Party B
    assert!(
        output_b
            .verify_peer_confirmation(&output_b.confirmation_mac)
            .is_err(),
        "own MAC must not verify as peer MAC (asymmetric keys)"
    );
}
