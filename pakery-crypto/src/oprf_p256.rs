//! P-256 OPRF implementation (RFC 9497, base mode).

use alloc::vec::Vec;

use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, NistP256, ProjectivePoint, Scalar, U256};
use pakery_core::crypto::oprf::{Oprf, OprfClientState};
use pakery_core::PakeError;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::oprf_common::{expand_message_xmd, finalize_hash, i2osp_2};

// RFC 9497 Section 4.3 — P256-SHA256, base mode (0x00).
const HASH_TO_GROUP_DST: &[u8] = b"HashToGroup-OPRFV1-\x00-P256-SHA256";
const DERIVE_KEYPAIR_DST: &[u8] = b"DeriveKeyPairOPRFV1-\x00-P256-SHA256";

/// 2^256 mod n (P-256 group order) — used for wide scalar reduction.
fn r_constant() -> Scalar {
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

/// Serialize a `ProjectivePoint` as compressed SEC1 (33 bytes).
pub(crate) fn point_to_bytes(point: &ProjectivePoint) -> Vec<u8> {
    point.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

/// Deserialize a compressed SEC1 point.
pub(crate) fn point_from_bytes(bytes: &[u8]) -> Result<ProjectivePoint, PakeError> {
    let encoded = EncodedPoint::from_bytes(bytes)
        .map_err(|_| PakeError::InvalidInput("invalid point encoding"))?;
    let affine = AffinePoint::from_encoded_point(&encoded);
    if affine.is_none().into() {
        return Err(PakeError::InvalidInput("invalid P-256 point"));
    }
    Ok(affine.expect("validated above").into())
}

/// Deserialize a 32-byte big-endian scalar.
pub(crate) fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar, PakeError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PakeError::InvalidInput("invalid scalar length"))?;
    let fb = p256::FieldBytes::from(arr);
    Option::from(Scalar::from_repr(fb)).ok_or(PakeError::InvalidInput("invalid P-256 scalar"))
}

/// Hash an arbitrary input to a P-256 point (RFC 9380 hash-to-curve).
fn hash_to_group(input: &[u8]) -> Result<ProjectivePoint, PakeError> {
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[input], &[HASH_TO_GROUP_DST])
        .map_err(|_| PakeError::ProtocolError("hash-to-group failed"))
}

/// Hash concatenated inputs to a P-256 scalar using the given DST.
///
/// Uses expand_message_xmd with L=48 bytes, then reduces mod n.
fn hash_to_scalar_with_dst(input: &[&[u8]], dst: &[u8]) -> Result<Scalar, PakeError> {
    // L = ceil((ceil(log2(r)) + k) / 8) = ceil((256 + 128) / 8) = 48
    let uniform = expand_message_xmd::<Sha256>(input, dst, 48)?;
    let arr: [u8; 48] = uniform
        .try_into()
        .expect("expand_message_xmd returned 48 bytes");
    Ok(reduce_48_to_scalar(&arr))
}

/// Reduce 48 big-endian bytes to a P-256 scalar.
///
/// Interprets as `high * 2^256 + low` where high is 16 bytes and low is 32 bytes,
/// then reduces modulo the group order n.
fn reduce_48_to_scalar(bytes: &[u8; 48]) -> Scalar {
    let mut high_fb = p256::FieldBytes::default();
    high_fb[16..].copy_from_slice(&bytes[..16]);
    let high = <Scalar as Reduce<U256>>::reduce_bytes(&high_fb);

    let low_arr: [u8; 32] = bytes[16..]
        .try_into()
        .expect("bytes[16..] is exactly 32 bytes");
    let low_fb = p256::FieldBytes::from(low_arr);
    let low = <Scalar as Reduce<U256>>::reduce_bytes(&low_fb);

    high * r_constant() + low
}

impl OprfClientState for P256OprfClientState {
    fn finalize(
        &self,
        password: &[u8],
        evaluated_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        let z = point_from_bytes(evaluated_bytes)?;

        let blind_scalar = scalar_from_bytes(&self.blind)?;
        let r_inv = blind_scalar.invert();
        if bool::from(r_inv.is_none()) {
            return Err(PakeError::ProtocolError("blind scalar has no inverse"));
        }
        let r_inv = r_inv.expect("checked above");

        let n = z * r_inv;
        Ok(Zeroizing::new(finalize_hash::<Sha256>(
            password,
            &point_to_bytes(&n),
        )?))
    }
}

/// P-256 OPRF (RFC 9497, base mode).
pub struct P256Oprf;

impl Oprf for P256Oprf {
    type ClientState = P256OprfClientState;

    fn client_blind(
        password: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ClientState, Vec<u8>), PakeError> {
        // Generate non-zero random scalar.
        let mut r = loop {
            let s = Scalar::random(&mut *rng);
            if !bool::from(s.is_zero()) {
                break s;
            }
        };

        let t = hash_to_group(password)?;
        let blinded = t * r;
        let blind = r.to_repr().into();
        r.zeroize();

        Ok((P256OprfClientState { blind }, point_to_bytes(&blinded)))
    }

    fn server_evaluate(oprf_key: &[u8], blinded_bytes: &[u8]) -> Result<Vec<u8>, PakeError> {
        let sk = scalar_from_bytes(oprf_key)?;
        if bool::from(sk.is_zero()) {
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
        Ok(point_to_bytes(&evaluated))
    }

    fn derive_key(seed: &[u8], info: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        let info_len = i2osp_2(info.len())?;

        for counter in 0u8..=255 {
            let sk =
                hash_to_scalar_with_dst(&[seed, &info_len, info, &[counter]], DERIVE_KEYPAIR_DST)?;
            if !bool::from(sk.is_zero()) {
                return Ok(Zeroizing::new(sk.to_repr().to_vec()));
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

    #[test]
    fn derive_key_pair() {
        let sk = P256Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();
        assert_eq!(*sk, hex(SK_SM));
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
        use rand_core::OsRng;
        let sk = P256Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();
        let password = b"hunter2";
        let (state, blinded) = P256Oprf::client_blind(password, &mut OsRng).unwrap();
        let eval = P256Oprf::server_evaluate(&sk, &blinded).unwrap();
        let output = state.finalize(password, &eval).unwrap();
        assert_eq!(output.len(), 32); // SHA-256 output

        // Same password + key should produce the same output.
        let (state2, blinded2) = P256Oprf::client_blind(password, &mut OsRng).unwrap();
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
        use rand_core::OsRng;
        let sk = P256Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();

        let (state_a, blinded_a) = P256Oprf::client_blind(b"password-A", &mut OsRng).unwrap();
        let eval_a = P256Oprf::server_evaluate(&sk, &blinded_a).unwrap();
        let output_a = state_a.finalize(b"password-A", &eval_a).unwrap();

        let (state_b, blinded_b) = P256Oprf::client_blind(b"password-B", &mut OsRng).unwrap();
        let eval_b = P256Oprf::server_evaluate(&sk, &blinded_b).unwrap();
        let output_b = state_b.finalize(b"password-B", &eval_b).unwrap();

        assert_ne!(output_a, output_b);
    }

    #[test]
    fn empty_password_roundtrip() {
        use rand_core::OsRng;
        let sk = P256Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();
        let (state, blinded) = P256Oprf::client_blind(b"", &mut OsRng).unwrap();
        let eval = P256Oprf::server_evaluate(&sk, &blinded).unwrap();
        let output = state.finalize(b"", &eval).unwrap();
        assert_eq!(output.len(), 32);

        // Must be deterministic.
        let (state2, blinded2) = P256Oprf::client_blind(b"", &mut OsRng).unwrap();
        let eval2 = P256Oprf::server_evaluate(&sk, &blinded2).unwrap();
        let output2 = state2.finalize(b"", &eval2).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn different_keys_different_outputs() {
        use rand_core::OsRng;
        let sk1 = P256Oprf::derive_key(&hex(SEED), b"key1").unwrap();
        let sk2 = P256Oprf::derive_key(&hex(SEED), b"key2").unwrap();

        let (state1, blinded1) = P256Oprf::client_blind(b"password", &mut OsRng).unwrap();
        let eval1 = P256Oprf::server_evaluate(&sk1, &blinded1).unwrap();
        let output1 = state1.finalize(b"password", &eval1).unwrap();

        let (state2, blinded2) = P256Oprf::client_blind(b"password", &mut OsRng).unwrap();
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
