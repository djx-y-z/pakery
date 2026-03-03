//! Ristretto255 OPRF implementation (RFC 9497, base mode).

use alloc::vec::Vec;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::Scalar;
use pakery_core::crypto::oprf::{Oprf, OprfClientState};
use pakery_core::PakeError;
use rand_core::CryptoRngCore;
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::oprf_common::{expand_message_xmd, finalize_hash, i2osp_2};

// RFC 9497 Section 4.1 — ristretto255-SHA512, base mode (0x00).
const HASH_TO_GROUP_DST: &[u8] = b"HashToGroup-OPRFV1-\x00-ristretto255-SHA512";
#[cfg(test)]
const HASH_TO_SCALAR_DST: &[u8] = b"HashToScalar-OPRFV1-\x00-ristretto255-SHA512";
const DERIVE_KEYPAIR_DST: &[u8] = b"DeriveKeyPairOPRFV1-\x00-ristretto255-SHA512";

/// Client state for the Ristretto255 OPRF.
///
/// The inner OPRF blinding scalar is zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ristretto255OprfClientState {
    blind: [u8; 32],
}

impl OprfClientState for Ristretto255OprfClientState {
    fn finalize(&self, password: &[u8], evaluated_bytes: &[u8]) -> Result<Vec<u8>, PakeError> {
        let z_bytes: [u8; 32] = evaluated_bytes
            .try_into()
            .map_err(|_| PakeError::InvalidInput("invalid evaluation element length"))?;
        let z = CompressedRistretto(z_bytes)
            .decompress()
            .ok_or(PakeError::InvalidInput("invalid evaluation element"))?;

        let blind_scalar = Scalar::from_canonical_bytes(self.blind)
            .into_option()
            .ok_or(PakeError::ProtocolError("invalid blind scalar"))?;
        if bool::from(blind_scalar.ct_eq(&Scalar::ZERO)) {
            return Err(PakeError::ProtocolError("blind scalar is zero"));
        }
        let r_inv = blind_scalar.invert();

        let n = r_inv * z;
        finalize_hash::<Sha512>(password, &n.compress().to_bytes())
    }
}

/// Ristretto255 OPRF (RFC 9497, base mode).
pub struct Ristretto255Oprf;

/// Hash an arbitrary input to a `RistrettoPoint`.
fn hash_to_group(input: &[u8]) -> Result<RistrettoPoint, PakeError> {
    let uniform = expand_message_xmd::<Sha512>(&[input], HASH_TO_GROUP_DST, 64)?;
    let arr: [u8; 64] = uniform
        .try_into()
        .expect("expand_message_xmd returned 64 bytes");
    Ok(RistrettoPoint::from_uniform_bytes(&arr))
}

/// Hash concatenated inputs to a `Scalar` using the HashToScalar DST.
#[cfg(test)]
fn hash_to_scalar(input: &[&[u8]]) -> Result<Scalar, PakeError> {
    hash_to_scalar_with_dst(input, HASH_TO_SCALAR_DST)
}

/// Hash concatenated inputs to a `Scalar` using the given DST.
fn hash_to_scalar_with_dst(input: &[&[u8]], dst: &[u8]) -> Result<Scalar, PakeError> {
    let uniform = expand_message_xmd::<Sha512>(input, dst, 64)?;
    let arr: [u8; 64] = uniform
        .try_into()
        .expect("expand_message_xmd returned 64 bytes");
    Ok(Scalar::from_bytes_mod_order_wide(&arr))
}

impl Oprf for Ristretto255Oprf {
    type ClientState = Ristretto255OprfClientState;

    fn client_blind(
        password: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ClientState, Vec<u8>), PakeError> {
        // Generate non-zero random scalar.
        let mut r = loop {
            let s = Scalar::random(rng);
            if !bool::from(s.ct_eq(&Scalar::ZERO)) {
                break s;
            }
        };

        let t = hash_to_group(password)?;
        let blinded = r * t;
        let blind = r.to_bytes();
        r.zeroize();

        Ok((
            Ristretto255OprfClientState { blind },
            blinded.compress().to_bytes().to_vec(),
        ))
    }

    fn server_evaluate(oprf_key: &[u8], blinded_bytes: &[u8]) -> Result<Vec<u8>, PakeError> {
        let sk_bytes: [u8; 32] = oprf_key
            .try_into()
            .map_err(|_| PakeError::InvalidInput("invalid OPRF key length"))?;
        let sk = Scalar::from_canonical_bytes(sk_bytes)
            .into_option()
            .ok_or(PakeError::InvalidInput("invalid OPRF key"))?;
        if bool::from(sk.ct_eq(&Scalar::ZERO)) {
            return Err(PakeError::InvalidInput("OPRF key is zero"));
        }

        let blinded_arr: [u8; 32] = blinded_bytes
            .try_into()
            .map_err(|_| PakeError::InvalidInput("invalid blinded element length"))?;
        let blinded = CompressedRistretto(blinded_arr)
            .decompress()
            .ok_or(PakeError::InvalidInput("invalid blinded element"))?;

        // Reject identity element as defense-in-depth.
        {
            use curve25519_dalek::traits::Identity;
            use subtle::ConstantTimeEq;
            if bool::from(blinded.ct_eq(&RistrettoPoint::identity())) {
                return Err(PakeError::InvalidInput("blinded element is identity"));
            }
        }

        let evaluated = sk * blinded;
        Ok(evaluated.compress().to_bytes().to_vec())
    }

    fn derive_key(seed: &[u8], info: &[u8]) -> Result<Vec<u8>, PakeError> {
        let info_len = i2osp_2(info.len())?;

        for counter in 0u8..=255 {
            let sk =
                hash_to_scalar_with_dst(&[seed, &info_len, info, &[counter]], DERIVE_KEYPAIR_DST)?;
            if !bool::from(sk.ct_eq(&Scalar::ZERO)) {
                return Ok(sk.to_bytes().to_vec());
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

    // RFC 9497 Appendix A.1.1 — ristretto255-SHA512 OPRF mode.
    const SEED: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
    const KEY_INFO: &str = "74657374206b6579";
    const SK_SM: &str = "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e";

    #[test]
    fn derive_key_pair() {
        let sk = Ristretto255Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();
        assert_eq!(sk, hex(SK_SM));
    }

    #[test]
    fn test_vector_1() {
        let input = hex("00");
        let blind_bytes = hex("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");
        let expected_blinded =
            hex("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c");
        let expected_eval = hex("7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e");
        let expected_output = hex("527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6");

        // Blind
        let blind = Scalar::from_canonical_bytes(blind_bytes.as_slice().try_into().unwrap())
            .into_option()
            .unwrap();
        let t = hash_to_group(&input).unwrap();
        let blinded = blind * t;
        assert_eq!(blinded.compress().to_bytes().to_vec(), expected_blinded);

        // Server evaluate
        let sk = hex(SK_SM);
        let eval = Ristretto255Oprf::server_evaluate(&sk, &expected_blinded).unwrap();
        assert_eq!(eval, expected_eval);

        // Finalize
        let state = Ristretto255OprfClientState {
            blind: blind_bytes.as_slice().try_into().unwrap(),
        };
        let output = state.finalize(&input, &expected_eval).unwrap();
        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_vector_2() {
        let input = hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        let blind_bytes = hex("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");
        let expected_blinded =
            hex("da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418");
        let expected_eval = hex("b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25");
        let expected_output = hex("f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73");

        // Blind
        let blind = Scalar::from_canonical_bytes(blind_bytes.as_slice().try_into().unwrap())
            .into_option()
            .unwrap();
        let t = hash_to_group(&input).unwrap();
        let blinded = blind * t;
        assert_eq!(blinded.compress().to_bytes().to_vec(), expected_blinded);

        // Server evaluate
        let sk = hex(SK_SM);
        let eval = Ristretto255Oprf::server_evaluate(&sk, &expected_blinded).unwrap();
        assert_eq!(eval, expected_eval);

        // Finalize
        let state = Ristretto255OprfClientState {
            blind: blind_bytes.as_slice().try_into().unwrap(),
        };
        let output = state.finalize(&input, &expected_eval).unwrap();
        assert_eq!(output, expected_output);
    }

    #[test]
    fn roundtrip() {
        use rand_core::OsRng;
        let sk = Ristretto255Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();
        let password = b"hunter2";
        let (state, blinded) = Ristretto255Oprf::client_blind(password, &mut OsRng).unwrap();
        let eval = Ristretto255Oprf::server_evaluate(&sk, &blinded).unwrap();
        let output = state.finalize(password, &eval).unwrap();
        assert_eq!(output.len(), 64); // SHA-512 output

        // Same password + key should produce the same output.
        let (state2, blinded2) = Ristretto255Oprf::client_blind(password, &mut OsRng).unwrap();
        let eval2 = Ristretto255Oprf::server_evaluate(&sk, &blinded2).unwrap();
        let output2 = state2.finalize(password, &eval2).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn invalid_key_length() {
        assert!(Ristretto255Oprf::server_evaluate(&[0u8; 16], &[0u8; 32]).is_err());
    }

    #[test]
    fn invalid_blinded_element() {
        let sk = hex(SK_SM);
        assert!(Ristretto255Oprf::server_evaluate(&sk, &[0u8; 16]).is_err());
    }

    #[test]
    fn server_evaluate_rejects_identity() {
        let sk = hex(SK_SM);
        // Ristretto identity = 32 zero bytes.
        let identity = [0u8; 32];
        assert!(Ristretto255Oprf::server_evaluate(&sk, &identity).is_err());
    }

    #[test]
    fn finalize_rejects_zero_blind() {
        let state = Ristretto255OprfClientState { blind: [0u8; 32] };
        let eval = hex("7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e");
        assert!(state.finalize(&[0x00], &eval).is_err());
    }

    #[test]
    fn hash_to_scalar_not_zero() {
        let s = hash_to_scalar(&[b"test input"]).unwrap();
        assert_ne!(s, Scalar::ZERO);
    }

    #[test]
    fn server_evaluate_rejects_zero_key() {
        let blinded = hex("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c");
        assert!(Ristretto255Oprf::server_evaluate(&[0u8; 32], &blinded).is_err());
    }

    #[test]
    fn different_passwords_different_outputs() {
        use rand_core::OsRng;
        let sk = Ristretto255Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();

        let (state_a, blinded_a) =
            Ristretto255Oprf::client_blind(b"password-A", &mut OsRng).unwrap();
        let eval_a = Ristretto255Oprf::server_evaluate(&sk, &blinded_a).unwrap();
        let output_a = state_a.finalize(b"password-A", &eval_a).unwrap();

        let (state_b, blinded_b) =
            Ristretto255Oprf::client_blind(b"password-B", &mut OsRng).unwrap();
        let eval_b = Ristretto255Oprf::server_evaluate(&sk, &blinded_b).unwrap();
        let output_b = state_b.finalize(b"password-B", &eval_b).unwrap();

        assert_ne!(output_a, output_b);
    }

    #[test]
    fn empty_password_roundtrip() {
        use rand_core::OsRng;
        let sk = Ristretto255Oprf::derive_key(&hex(SEED), &hex(KEY_INFO)).unwrap();
        let (state, blinded) = Ristretto255Oprf::client_blind(b"", &mut OsRng).unwrap();
        let eval = Ristretto255Oprf::server_evaluate(&sk, &blinded).unwrap();
        let output = state.finalize(b"", &eval).unwrap();
        assert_eq!(output.len(), 64); // SHA-512 output

        // Must be deterministic.
        let (state2, blinded2) = Ristretto255Oprf::client_blind(b"", &mut OsRng).unwrap();
        let eval2 = Ristretto255Oprf::server_evaluate(&sk, &blinded2).unwrap();
        let output2 = state2.finalize(b"", &eval2).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn different_keys_different_outputs() {
        use rand_core::OsRng;
        let sk1 = Ristretto255Oprf::derive_key(&hex(SEED), b"key1").unwrap();
        let sk2 = Ristretto255Oprf::derive_key(&hex(SEED), b"key2").unwrap();

        let (state1, blinded1) = Ristretto255Oprf::client_blind(b"password", &mut OsRng).unwrap();
        let eval1 = Ristretto255Oprf::server_evaluate(&sk1, &blinded1).unwrap();
        let output1 = state1.finalize(b"password", &eval1).unwrap();

        let (state2, blinded2) = Ristretto255Oprf::client_blind(b"password", &mut OsRng).unwrap();
        let eval2 = Ristretto255Oprf::server_evaluate(&sk2, &blinded2).unwrap();
        let output2 = state2.finalize(b"password", &eval2).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn invalid_evaluation_element_length() {
        let state = Ristretto255OprfClientState {
            blind: hex("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706")
                .try_into()
                .unwrap(),
        };
        // Too short
        assert!(state.finalize(b"test", &[0u8; 16]).is_err());
        // Too long
        assert!(state.finalize(b"test", &[0u8; 64]).is_err());
    }

    #[test]
    fn invalid_evaluation_element_not_on_curve() {
        let state = Ristretto255OprfClientState {
            blind: hex("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706")
                .try_into()
                .unwrap(),
        };
        // 32 bytes that don't decompress to a valid Ristretto point.
        assert!(state.finalize(b"test", &[0xFF; 32]).is_err());
    }
}
