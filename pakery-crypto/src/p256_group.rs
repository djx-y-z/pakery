//! P-256 (NIST P-256 / secp256r1) implementation of the CpaceGroup trait.

use alloc::vec::Vec;
use p256::elliptic_curve::ff::PrimeField;
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, NistP256, ProjectivePoint, Scalar};
use pakery_core::crypto::group::CpaceGroup;
use pakery_core::PakeError;
use rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

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
        // ctgrind: the identity-rejection outcome is a public protocol abort.
        pakery_core::ct::declassify_choice(self.point.ct_eq(&ProjectivePoint::IDENTITY))
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

    fn random_scalar(rng: &mut impl CryptoRng) -> Scalar {
        // Generate a uniformly-random non-zero scalar via 32-byte rejection
        // sampling. Matches p256 0.13's `Scalar::random` byte-consumption
        // pattern, preserving RFC test-vector compatibility for downstream
        // protocols that pass deterministic 32-byte scalars via test RNGs. We
        // can't call `Scalar::random` directly because it is tied to rand_core
        // 0.6 and incompatible with our 0.9 RNG bound.
        //
        // ctgrind: candidate bytes are deliberately NOT marked secret here —
        // rejection sampling branches on each candidate's validity (a public
        // retry decision), which memcheck would flag inside p256's CtOption.
        // Taint enters downstream at byte boundaries instead (the protocol
        // crates mark K/w/Z/V byte encodings secret).
        loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            rng.fill_bytes(&mut *bytes);
            let mut fb = p256::FieldBytes::from(*bytes);
            let result = Option::<Scalar>::from(Scalar::from_repr(fb));
            fb.zeroize();
            if let Some(s) = result {
                return s;
            }
        }
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
        let high_arr: [u8; 32] = bytes[..32].try_into().expect("first 32 bytes");
        let high_fb = p256::FieldBytes::from(high_arr);
        let low_arr: [u8; 32] = bytes[32..].try_into().expect("last 32 bytes");
        let low_fb = p256::FieldBytes::from(low_arr);

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

#[cfg(test)]
mod tests {
    use super::*;
    use pakery_core::crypto::CpaceGroup;

    /// `scalar_to_bytes` must produce the canonical 32-byte big-endian SEC1
    /// encoding (roadmap item 8: CPace itself never serializes scalars, so
    /// only a direct contract test constrains this trait method).
    #[test]
    fn scalar_to_bytes_roundtrips_canonical_encoding() {
        let mut wide = [0u8; 64];
        wide[63] = 5; // 5 < group order: reduction is the identity
        let scalar = <P256Group as CpaceGroup>::scalar_from_wide_bytes(&wide).unwrap();
        let bytes = <P256Group as CpaceGroup>::scalar_to_bytes(&scalar);
        let mut expected = [0u8; 32];
        expected[31] = 5;
        assert_eq!(bytes, expected);
    }

    /// Known-answer test for the wide reduction with a non-zero high half
    /// (roadmap item 8: with high = 0, `high * R + low` is insensitive to
    /// the operators and to R — mutants on both survived). Expected value is
    /// (0xABAB...AB, 512 bits) mod n, computed independently.
    #[test]
    fn scalar_from_wide_bytes_reduces_high_half() {
        let wide = [0xABu8; 64];
        let scalar = <P256Group as CpaceGroup>::scalar_from_wide_bytes(&wide).unwrap();
        let bytes = <P256Group as CpaceGroup>::scalar_to_bytes(&scalar);
        let expected = [
            0x48, 0x00, 0x69, 0xDC, 0x58, 0x3A, 0x66, 0xEE, 0x6C, 0x52, 0xE0, 0xED, 0x1D, 0x1E,
            0x35, 0x14, 0xB6, 0x15, 0x4E, 0x79, 0xE8, 0x1E, 0xEF, 0x5F, 0x27, 0x9C, 0x08, 0x90,
            0xE0, 0x10, 0xAC, 0x82,
        ];
        assert_eq!(bytes, expected);
    }
}
