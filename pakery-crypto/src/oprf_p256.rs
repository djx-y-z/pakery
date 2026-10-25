//! P-256 OPRF implementation (RFC 9497, base mode).

use alloc::vec::Vec;

use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::FromSec1Point;
use p256::hash2curve::GroupDigest;
use p256::{AffinePoint, FieldBytes, NistP256, ProjectivePoint, Scalar, Sec1Point};
use pakery_core::crypto::oprf::{Oprf, OprfClientState};
use pakery_core::PakeError;
use rand_core::CryptoRng;
use sha2::Sha256;
use subtle::ConditionallySelectable;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::oprf_common::{expand_message_xmd, finalize_hash, i2osp_2};

// RFC 9497 Section 4.3 — P256-SHA256, base mode (0x00).
const HASH_TO_GROUP_DST: &[u8] = b"HashToGroup-OPRFV1-\x00-P256-SHA256";
const DERIVE_KEYPAIR_DST: &[u8] = b"DeriveKeyPairOPRFV1-\x00-P256-SHA256";

/// 2^256 mod n (P-256 group order) — used for wide scalar reduction.
pub(crate) fn r_constant() -> Scalar {
    Scalar::from_repr(p256::FieldBytes::from([
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x43, 0x19, 0x05, 0x52, 0x58, 0xE8, 0x61, 0x7B, 0x0C, 0x46, 0x35, 0x3D, 0x03, 0x9C,
        0xDA, 0xAF,
    ]))
    .expect("R constant is a valid P-256 scalar")
}

/// Client state for the P-256 OPRF.
///
/// The inner OPRF blinding scalar is zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct P256OprfClientState {
    blind: [u8; 32],
}

/// Serialize a `ProjectivePoint` as compressed SEC1: 33 bytes, or the one-byte
/// SEC1 identity encoding `0x00` for the identity — the bytes sec1's own
/// `to_sec1_point(true)` produces, without its branches.
///
/// Constant time for a secret point. sec1's `Tag::compress_y` branches on the
/// parity of `y` and `as_bytes` dispatches on the tag byte, so a secret point
/// (an unblinded OPRF value, a Diffie-Hellman result) must not go through it;
/// this goes through [`encode_point_ct`]. Only whether the point is the
/// identity is declassified, and every caller treats that as public: it either
/// rules the identity out first or sends the encoding.
pub(crate) fn point_to_bytes(point: &ProjectivePoint) -> Vec<u8> {
    use subtle::ConstantTimeEq;
    if pakery_core::ct::declassify_choice(point.ct_eq(&ProjectivePoint::IDENTITY)) {
        return alloc::vec![0x00];
    }
    encode_point_ct(point).to_vec()
}

/// Serialize a non-identity point as compressed SEC1 (33 bytes) in constant
/// time: `0x02 | y_is_odd || x`, which is exactly the SEC1 compressed encoding.
///
/// The affine conversion inverts `z` with a constant-time inversion, and the
/// parity and the `x` bytes are read without a branch. The identity has no
/// 33-byte encoding; for it this returns a meaningless `0x02 || 0^32`, so the
/// caller must have ruled it out.
pub(crate) fn encode_point_ct(point: &ProjectivePoint) -> [u8; 33] {
    let affine = point.to_affine();
    let mut out = [0u8; 33];
    // A select rather than `0x02 | parity`: the same bytes, and no operator
    // for a mutant to flip into an equivalent one (`|` and `^` agree here).
    out[0] = u8::conditional_select(&0x02, &0x03, affine.y_is_odd());
    out[1..].copy_from_slice(&affine.x());
    out
}

/// Deserialize a compressed SEC1 point.
///
/// Only the compressed form (tag `0x02`/`0x03`, 33 bytes) is accepted —
/// identity (`0x00`), uncompressed (`0x04`), and compact (`0x05`) SEC1
/// encodings are rejected so every group element has exactly one valid
/// byte representation (encoding non-malleability).
pub(crate) fn point_from_bytes(bytes: &[u8]) -> Result<ProjectivePoint, PakeError> {
    let encoded = Sec1Point::from_bytes(bytes)
        .map_err(|_| PakeError::InvalidInput("invalid point encoding"))?;
    if !encoded.is_compressed() {
        return Err(PakeError::InvalidInput("invalid point encoding"));
    }
    let affine = AffinePoint::from_sec1_point(&encoded);
    if affine.is_none().into() {
        return Err(PakeError::InvalidInput("invalid P-256 point"));
    }
    Ok(affine.expect("validated above").into())
}

/// Deserialize a 32-byte big-endian scalar.
///
/// Constant time for a secret scalar (a key, a blind): `from_repr` decides
/// canonicity without a branch, and only the accept/reject decision is
/// declassified — a public outcome — so the scalar itself stays secret for
/// the ctgrind harness rather than being parsed from a laundered copy.
pub(crate) fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar, PakeError> {
    // A reference, not a copy: the bytes go into `repr`, which is wiped below,
    // and by value into `from_repr`'s argument, which cannot be.
    let arr: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| PakeError::InvalidInput("invalid scalar length"))?;
    let mut repr = p256::FieldBytes::default();
    repr.copy_from_slice(arr);
    let scalar = Scalar::from_repr(repr);
    repr.zeroize();
    if !pakery_core::ct::declassify_choice(scalar.is_some()) {
        return Err(PakeError::InvalidInput("invalid P-256 scalar"));
    }
    Ok(scalar.unwrap_or(Scalar::ZERO))
}

/// Hash an arbitrary input to a P-256 point (RFC 9380 hash-to-curve).
fn hash_to_group(input: &[u8]) -> Result<ProjectivePoint, PakeError> {
    NistP256::hash_from_bytes(&[input], &[HASH_TO_GROUP_DST])
        .map_err(|_| PakeError::ProtocolError("hash-to-group failed"))
}

/// Hash concatenated inputs to a P-256 scalar using the given DST.
///
/// Uses expand_message_xmd with L=48 bytes, then reduces mod n.
fn hash_to_scalar_with_dst(input: &[&[u8]], dst: &[u8]) -> Result<Scalar, PakeError> {
    // L = ceil((ceil(log2(r)) + k) / 8) = ceil((256 + 128) / 8) = 48
    // Both buffers hold the uniform bytes, which `derive_key` turns into a
    // secret key, so both are wiped on drop.
    let uniform = expand_message_xmd::<Sha256>(input, dst, 48)?;
    let mut wide = Zeroizing::new([0u8; 48]);
    wide.copy_from_slice(&uniform);
    Ok(reduce_48_to_scalar(&wide))
}

/// Reduce 48 big-endian bytes to a P-256 scalar.
///
/// Interprets as `high * 2^256 + low` where high is 16 bytes and low is 32 bytes,
/// then reduces modulo the group order n. The bytes can be secret (a derived
/// key, a proof nonce), so this function wipes its own copies of both halves;
/// the input buffer is the caller's to wipe.
pub(crate) fn reduce_48_to_scalar(bytes: &[u8; 48]) -> Scalar {
    let mut high_fb = FieldBytes::default();
    high_fb[16..].copy_from_slice(&bytes[..16]);
    let high = <Scalar as Reduce<FieldBytes>>::reduce(&high_fb);
    high_fb.zeroize();

    let mut low_fb = FieldBytes::default();
    low_fb.copy_from_slice(&bytes[16..]);
    let low = <Scalar as Reduce<FieldBytes>>::reduce(&low_fb);
    low_fb.zeroize();

    high * r_constant() + low
}

impl OprfClientState for P256OprfClientState {
    fn finalize(
        &self,
        password: &[u8],
        evaluated_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        let z = point_from_bytes(evaluated_bytes)?;

        // Reject identity element as defense-in-depth: an identity evaluation
        // element would make the OPRF output independent of the password.
        {
            use subtle::ConstantTimeEq;
            if bool::from(z.ct_eq(&ProjectivePoint::IDENTITY)) {
                return Err(PakeError::InvalidInput("evaluation element is identity"));
            }
        }

        // ctgrind: the blind stays secret through the parse and the inversion;
        // only the two refusal decisions are declassified.
        let blind_scalar = scalar_from_bytes(&self.blind)?;
        let r_inv = blind_scalar.invert();
        if pakery_core::ct::declassify_choice(r_inv.is_none()) {
            return Err(PakeError::ProtocolError("blind scalar has no inverse"));
        }
        let r_inv = r_inv.unwrap_or(Scalar::ZERO);

        // `n` is the PRF value before hashing, so it is secret and goes through
        // the constant-time encoder. It is not the identity: `z` was rejected
        // above if it was, and `r_inv` inverts a nonzero scalar.
        let n = z * r_inv;
        let n_bytes = Zeroizing::new(encode_point_ct(&n));
        finalize_hash::<Sha256>(password, &*n_bytes)
    }
}

/// P-256 OPRF (RFC 9497, base mode).
pub struct P256Oprf;

impl Oprf for P256Oprf {
    type ClientState = P256OprfClientState;

    // P256-SHA256: 32-byte scalar, 33-byte compressed SEC1 element.
    const KEY_LEN: usize = 32;
    const ELEMENT_LEN: usize = 33;
    // `finalize_hash::<Sha256>` below.
    const OUTPUT_LEN: usize = 32;

    fn client_blind(
        password: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::ClientState, Vec<u8>), PakeError> {
        // Generate a non-zero random scalar by 32-byte rejection sampling:
        // draw 32 bytes, accept iff they are a canonical scalar. That
        // byte-consumption pattern is what the RFC 9497 / RFC 9807 vector tests
        // depend on — they replay a deterministic 32-byte scalar through a test
        // RNG — so it is a fixed contract of this function, not an imitation of
        // whatever `Scalar::random` does internally. Until 0.4.0 it was also
        // out of reach — `ff` 0.14's `Field::random` takes a rand_core 0.10
        // RNG, and the bound here was rand_core 0.9 — but that is no longer
        // what stops us: the byte contract above is.
        //
        // ctgrind: candidates are not marked — accepting or rejecting one is a
        // public retry decision taken before the value means anything. The
        // accepted blind is the secret: it is marked, and the scalar re-derived
        // from the marked bytes, so the blinding multiplication and the
        // encoding of the blind below run tainted, as in the RFC 9497 suites.
        let mut r = loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            rng.fill_bytes(&mut *bytes);
            // Copied in place rather than through a by-value array, so the only
            // copy left unwiped is `from_repr`'s own argument.
            let mut fb = p256::FieldBytes::default();
            fb.copy_from_slice(&*bytes);
            let result = Option::<Scalar>::from(Scalar::from_repr(fb));
            fb.zeroize();
            if let Some(s) = result {
                if !bool::from(s.is_zero()) {
                    pakery_core::ct::mark_secret(&*bytes);
                    let mut fb = p256::FieldBytes::default();
                    fb.copy_from_slice(&*bytes);
                    let r = Scalar::from_repr(fb).unwrap_or(Scalar::ZERO);
                    fb.zeroize();
                    break r;
                }
            }
        };

        let t = hash_to_group(password)?;
        let blinded = t * r;
        let blind: [u8; 32] = r.to_repr().into();
        r.zeroize();

        // ctgrind: the blind is secret key material — already tainted through
        // `r`; marked again to keep the policy explicit.
        pakery_core::ct::mark_secret(&blind);
        let blinded_bytes = point_to_bytes(&blinded);
        // ctgrind: the blinded element is the OPRF wire message — public by
        // protocol design (blinding hides the password).
        pakery_core::ct::declassify(&blinded_bytes);
        Ok((P256OprfClientState { blind }, blinded_bytes))
    }

    fn server_evaluate(oprf_key: &[u8], blinded_bytes: &[u8]) -> Result<Vec<u8>, PakeError> {
        // ctgrind: the key stays secret through the parse; only the refusal
        // decisions are declassified.
        let sk = scalar_from_bytes(oprf_key)?;
        if pakery_core::ct::declassify_choice(sk.is_zero()) {
            return Err(PakeError::InvalidInput("OPRF key is zero"));
        }
        let blinded = point_from_bytes(blinded_bytes)?;

        // Reject identity element as defense-in-depth.
        {
            use subtle::ConstantTimeEq;
            if bool::from(blinded.ct_eq(&ProjectivePoint::IDENTITY)) {
                return Err(PakeError::InvalidInput("blinded element is identity"));
            }
        }

        let evaluated = blinded * sk;
        let evaluated_bytes = point_to_bytes(&evaluated);
        // ctgrind: the evaluated element is a wire message.
        pakery_core::ct::declassify(&evaluated_bytes);
        Ok(evaluated_bytes)
    }

    fn derive_key(seed: &[u8], info: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        let info_len = i2osp_2(info.len())?;

        for counter in 0u8..=255 {
            let mut sk =
                hash_to_scalar_with_dst(&[seed, &info_len, info, &[counter]], DERIVE_KEYPAIR_DST)?;
            // ctgrind: whether a candidate reduces to zero is public (it only
            // increments the retry counter).
            if !pakery_core::ct::declassify_choice(sk.is_zero()) {
                // The scalar and its encoding are wiped once the returned
                // buffer holds the key.
                let mut repr = sk.to_repr();
                let key = Zeroizing::new(repr.to_vec());
                repr.zeroize();
                sk.zeroize();
                return Ok(key);
            }
        }

        Err(PakeError::ProtocolError(
            "DeriveKeyPair: all counters yielded zero",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p256::elliptic_curve::sec1::ToSec1Point;

    /// Both constant-time encoders agree with sec1's own compressed encoding,
    /// which they replace: on the generator and its negation, on `k * G` for
    /// `k = 1..=64`, on hash outputs (both y parities), and — for
    /// `point_to_bytes` — on the identity, which sec1 encodes as `0x00`.
    #[test]
    fn constant_time_encoders_match_sec1() {
        let sec1 = |p: &ProjectivePoint| p.to_affine().to_sec1_point(true).as_bytes().to_vec();
        let mut parities = [false; 2];
        let mut points = alloc::vec![ProjectivePoint::GENERATOR, -ProjectivePoint::GENERATOR];
        let mut k = ProjectivePoint::IDENTITY;
        for i in 0u8..64 {
            k += ProjectivePoint::GENERATOR;
            points.push(k);
            points.push(hash_to_group(&[i]).unwrap());
        }
        for point in &points {
            let ct = encode_point_ct(point);
            assert_eq!(ct.as_slice(), sec1(point).as_slice());
            assert_eq!(point_to_bytes(point), sec1(point));
            parities[usize::from(ct[0] & 1)] = true;
        }
        assert_eq!(parities, [true, true], "both y parities covered");
        assert_eq!(
            point_to_bytes(&ProjectivePoint::IDENTITY),
            sec1(&ProjectivePoint::IDENTITY)
        );
        assert_eq!(point_to_bytes(&ProjectivePoint::IDENTITY), [0x00]);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 9497 Appendix A.3.1 — P256-SHA256 OPRF mode.
    const SEED: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
    const KEY_INFO: &str = "74657374206b6579";
    const SK_SM: &str = "159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf";

    /// `point_from_bytes` must accept only the canonical compressed SEC1
    /// form. The SEC1 compact tag (`0x05`) is a second encoding of the same
    /// x-coordinate that p256 would silently decompact, making point
    /// encodings malleable (found by the `opaque_flow` fuzzer, issue #13:
    /// flipping a stored `RegistrationRecord` public-key tag 0x02 -> 0x05
    /// decoded to the same point and login still completed).
    #[test]
    fn point_from_bytes_rejects_non_compressed_sec1() {
        let compressed = point_to_bytes(&ProjectivePoint::GENERATOR);
        assert_eq!(compressed.len(), 33);
        assert!(point_from_bytes(&compressed).is_ok());

        // Compact tag 0x05 (same length, same x) must be rejected.
        let mut compact = compressed.clone();
        compact[0] = 0x05;
        assert!(point_from_bytes(&compact).is_err());

        // Uncompressed tag 0x04 (65 bytes) must be rejected.
        let uncompressed = ProjectivePoint::GENERATOR
            .to_affine()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(uncompressed.len(), 65);
        assert!(point_from_bytes(&uncompressed).is_err());

        // SEC1 identity encoding (single 0x00 byte) must be rejected.
        assert!(point_from_bytes(&[0x00]).is_err());
    }

    #[test]
    fn derive_key_pair() {
        let sk = P256Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();
        assert_eq!(*sk, hex(SK_SM));
    }

    /// Calling `.zeroize()` on a live value must clear every secret field
    /// (roadmap item 7: catches a future field added without zeroization).
    #[test]
    fn zeroize_clears_all_secret_fields() {
        let mut state = P256OprfClientState { blind: [0xAA; 32] };
        state.zeroize();
        assert_eq!(state.blind, [0u8; 32]);
    }

    #[test]
    fn test_vector_1() {
        let input = hex("00");
        let blind_bytes = hex("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364");
        let expected_blinded =
            hex("03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d");
        let expected_eval =
            hex("030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832");
        let expected_output =
            hex("a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd");

        // Blind
        let blind = scalar_from_bytes(&blind_bytes).unwrap();
        let t = hash_to_group(&input).unwrap();
        let blinded = t * blind;
        assert_eq!(point_to_bytes(&blinded), expected_blinded);

        // Server evaluate
        let sk = hex(SK_SM);
        let eval = P256Oprf::server_evaluate(&sk, &expected_blinded).unwrap();
        assert_eq!(eval, expected_eval);

        // Finalize
        let state = P256OprfClientState {
            blind: blind_bytes.as_slice().try_into().unwrap(),
        };
        let output = state.finalize(&input, &expected_eval).unwrap();
        assert_eq!(*output, expected_output);
    }

    #[test]
    fn test_vector_2() {
        let input = hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        let blind_bytes = hex("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364");
        let expected_blinded =
            hex("03cc1df781f1c2240a64d1c297b3f3d16262ef5d4cf102734882675c26231b0838");
        let expected_eval =
            hex("03a0395fe3828f2476ffcd1f4fe540e5a8489322d398be3c4e5a869db7fcb7c52c");
        let expected_output =
            hex("c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce");

        // Blind
        let blind = scalar_from_bytes(&blind_bytes).unwrap();
        let t = hash_to_group(&input).unwrap();
        let blinded = t * blind;
        assert_eq!(point_to_bytes(&blinded), expected_blinded);

        // Server evaluate
        let sk = hex(SK_SM);
        let eval = P256Oprf::server_evaluate(&sk, &expected_blinded).unwrap();
        assert_eq!(eval, expected_eval);

        // Finalize
        let state = P256OprfClientState {
            blind: blind_bytes.as_slice().try_into().unwrap(),
        };
        let output = state.finalize(&input, &expected_eval).unwrap();
        assert_eq!(*output, expected_output);
    }

    #[test]
    fn roundtrip() {
        use getrandom::SysRng;
        use rand_core::UnwrapErr;
        let sk = P256Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();
        let password = b"hunter2";
        let (state, blinded) = P256Oprf::client_blind(password, &mut UnwrapErr(SysRng)).unwrap();
        let eval = P256Oprf::server_evaluate(&sk, &blinded).unwrap();
        let output = state.finalize(password, &eval).unwrap();
        assert_eq!(output.len(), 32); // SHA-256 output

        // Same password + key should produce the same output.
        let (state2, blinded2) = P256Oprf::client_blind(password, &mut UnwrapErr(SysRng)).unwrap();
        let eval2 = P256Oprf::server_evaluate(&sk, &blinded2).unwrap();
        let output2 = state2.finalize(password, &eval2).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn server_evaluate_rejects_identity() {
        let sk = hex(SK_SM);
        // SEC1 identity encoding = single 0x00 byte.
        assert!(P256Oprf::server_evaluate(&sk, &[0x00]).is_err());
    }

    #[test]
    fn invalid_key_length() {
        assert!(P256Oprf::server_evaluate(
            &[0u8; 16],
            &hex("03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d")
        )
        .is_err());
    }

    #[test]
    fn invalid_blinded_element() {
        let sk = hex(SK_SM);
        assert!(P256Oprf::server_evaluate(&sk, &[0u8; 16]).is_err());
    }

    #[test]
    fn finalize_rejects_zero_blind() {
        let state = P256OprfClientState { blind: [0u8; 32] };
        let eval = hex("030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832");
        assert!(state.finalize(&[0x00], &eval).is_err());
    }

    #[test]
    fn finalize_rejects_identity_evaluation() {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let (state, _) = P256Oprf::client_blind(b"password", &mut rng).unwrap();
        // SEC1 identity encoding = single 0x00 byte.
        assert!(state.finalize(b"password", &[0x00]).is_err());
    }

    #[test]
    fn server_evaluate_rejects_zero_key() {
        let blinded = hex("03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d");
        assert!(P256Oprf::server_evaluate(&[0u8; 32], &blinded).is_err());
    }

    #[test]
    fn server_evaluate_rejects_non_canonical_key() {
        // P-256 group order n:
        // FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        // A scalar >= n must be rejected by from_repr.
        let n_bytes = hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        let blinded = hex("03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d");
        assert!(P256Oprf::server_evaluate(&n_bytes, &blinded).is_err());
    }

    #[test]
    fn different_passwords_different_outputs() {
        use getrandom::SysRng;
        use rand_core::UnwrapErr;
        let sk = P256Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();

        let (state_a, blinded_a) =
            P256Oprf::client_blind(b"password-A", &mut UnwrapErr(SysRng)).unwrap();
        let eval_a = P256Oprf::server_evaluate(&sk, &blinded_a).unwrap();
        let output_a = state_a.finalize(b"password-A", &eval_a).unwrap();

        let (state_b, blinded_b) =
            P256Oprf::client_blind(b"password-B", &mut UnwrapErr(SysRng)).unwrap();
        let eval_b = P256Oprf::server_evaluate(&sk, &blinded_b).unwrap();
        let output_b = state_b.finalize(b"password-B", &eval_b).unwrap();

        assert_ne!(output_a, output_b);
    }

    #[test]
    fn empty_password_roundtrip() {
        use getrandom::SysRng;
        use rand_core::UnwrapErr;
        let sk = P256Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();
        let (state, blinded) = P256Oprf::client_blind(b"", &mut UnwrapErr(SysRng)).unwrap();
        let eval = P256Oprf::server_evaluate(&sk, &blinded).unwrap();
        let output = state.finalize(b"", &eval).unwrap();
        assert_eq!(output.len(), 32);

        // Must be deterministic.
        let (state2, blinded2) = P256Oprf::client_blind(b"", &mut UnwrapErr(SysRng)).unwrap();
        let eval2 = P256Oprf::server_evaluate(&sk, &blinded2).unwrap();
        let output2 = state2.finalize(b"", &eval2).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn different_keys_different_outputs() {
        use getrandom::SysRng;
        use rand_core::UnwrapErr;
        let sk1 = P256Oprf::derive_key(&hex(SEED), b"key1").unwrap();
        let sk2 = P256Oprf::derive_key(&hex(SEED), b"key2").unwrap();

        let (state1, blinded1) =
            P256Oprf::client_blind(b"password", &mut UnwrapErr(SysRng)).unwrap();
        let eval1 = P256Oprf::server_evaluate(&sk1, &blinded1).unwrap();
        let output1 = state1.finalize(b"password", &eval1).unwrap();

        let (state2, blinded2) =
            P256Oprf::client_blind(b"password", &mut UnwrapErr(SysRng)).unwrap();
        let eval2 = P256Oprf::server_evaluate(&sk2, &blinded2).unwrap();
        let output2 = state2.finalize(b"password", &eval2).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn invalid_evaluation_element_length() {
        let state = P256OprfClientState {
            blind: hex("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364")
                .try_into()
                .unwrap(),
        };
        // Too short
        assert!(state.finalize(b"test", &[0x03; 16]).is_err());
        // Too long
        assert!(state.finalize(b"test", &[0x03; 64]).is_err());
    }

    #[test]
    fn invalid_evaluation_element_not_on_curve() {
        let state = P256OprfClientState {
            blind: hex("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364")
                .try_into()
                .unwrap(),
        };
        // Valid length compressed point but not on curve (all 0xFF for x-coordinate).
        let mut bad_point = vec![0x03];
        bad_point.extend_from_slice(&[0xFF; 32]);
        assert!(state.finalize(b"test", &bad_point).is_err());
    }
}
