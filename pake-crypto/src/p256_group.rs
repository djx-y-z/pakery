//! P-256 (NIST P-256 / secp256r1) implementation of the CpaceGroup trait.

use alloc::vec::Vec;
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{ff::Field, ff::PrimeField};
use p256::{AffinePoint, EncodedPoint, NistP256, ProjectivePoint, Scalar};
use pake_core::crypto::group::CpaceGroup;
use pake_core::PakeError;
use rand_core::CryptoRngCore;

/// DST for hash-to-curve in `from_uniform_bytes`.
const HASH_TO_CURVE_DST: &[u8] = b"PAKE-P256-HashToCurve-v1";

/// P-256 group element for CPace and SPAKE2 protocols.
#[derive(Clone, PartialEq)]
pub struct P256Group {
    point: ProjectivePoint,
}

impl CpaceGroup for P256Group {
    type Scalar = Scalar;

    fn scalar_mul(&self, scalar: &Scalar) -> Self {
        Self {
            point: self.point * scalar,
        }
    }

    fn is_identity(&self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.point.ct_eq(&ProjectivePoint::IDENTITY))
    }

    fn to_bytes(&self) -> Vec<u8> {
        // SEC1 uncompressed encoding (65 bytes, 0x04 prefix)
        self.point
            .to_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PakeError> {
        // Accept both compressed (33 bytes) and uncompressed (65 bytes) SEC1
        let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| PakeError::InvalidPoint)?;
        let affine = AffinePoint::from_encoded_point(&encoded);
        if affine.is_none().into() {
            return Err(PakeError::InvalidPoint);
        }
        Ok(Self {
            point: affine.expect("validated by is_none check above").into(),
        })
    }

    fn from_uniform_bytes(bytes: &[u8]) -> Result<Self, PakeError> {
        if bytes.len() != 64 {
            return Err(PakeError::InvalidInput(
                "from_uniform_bytes requires 64 bytes",
            ));
        }
        let point =
            NistP256::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(&[bytes], &[HASH_TO_CURVE_DST])
                .map_err(|_| PakeError::ProtocolError("hash-to-curve failed"))?;
        Ok(Self { point })
    }

    fn random_scalar(rng: &mut impl CryptoRngCore) -> Scalar {
        Scalar::random(rng)
    }

    fn add(&self, other: &Self) -> Self {
        Self {
            point: self.point + other.point,
        }
    }

    fn negate(&self) -> Self {
        Self { point: -self.point }
    }

    fn basepoint_mul(scalar: &Scalar) -> Self {
        Self {
            point: ProjectivePoint::GENERATOR * scalar,
        }
    }

    fn scalar_from_wide_bytes(bytes: &[u8]) -> Result<Scalar, PakeError> {
        if bytes.len() != 64 {
            return Err(PakeError::InvalidInput(
                "scalar_from_wide_bytes requires 64 bytes",
            ));
        }

        // Interpret 64 bytes as big-endian 512-bit integer, reduce mod group order n.
        // Split into high (first 32 bytes) and low (last 32 bytes).
        // result = reduce(high) * R + reduce(low), where R = 2^256 mod n.
        let high_fb = p256::FieldBytes::clone_from_slice(&bytes[..32]);
        let low_fb = p256::FieldBytes::clone_from_slice(&bytes[32..]);

        let high = <Scalar as Reduce<p256::U256>>::reduce_bytes(&high_fb);
        let low = <Scalar as Reduce<p256::U256>>::reduce_bytes(&low_fb);

        Ok(high * r_constant() + low)
    }

    fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
        scalar.to_repr().to_vec()
    }
}

/// Pre-computed constant R = 2^256 mod n for P-256.
///
/// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
/// R = 0x00000000FFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF
fn r_constant() -> Scalar {
    Scalar::from_repr(p256::FieldBytes::from([
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x43, 0x19, 0x05, 0x52, 0x58, 0xE8, 0x61, 0x7B, 0x0C, 0x46, 0x35, 0x3D, 0x03, 0x9C,
        0xDA, 0xAF,
    ]))
    .expect("R constant is a valid P-256 scalar")
}
