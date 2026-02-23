//! Ristretto255 implementations of CpaceGroup and DhGroup traits.

use alloc::vec::Vec;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use pake_core::crypto::dh::DhGroup;
use pake_core::crypto::group::CpaceGroup;
use pake_core::PakeError;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

/// Ristretto255 group element for CPace.
#[derive(Clone, PartialEq)]
pub struct Ristretto255Group {
    point: RistrettoPoint,
}

impl CpaceGroup for Ristretto255Group {
    type Scalar = Scalar;

    fn scalar_mul(&self, scalar: &Scalar) -> Self {
        Self {
            point: self.point * scalar,
        }
    }

    fn is_identity(&self) -> bool {
        use curve25519_dalek::traits::Identity;
        use subtle::ConstantTimeEq;
        self.point.ct_eq(&RistrettoPoint::identity()).into()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.point.compress().to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PakeError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| PakeError::InvalidPoint)?;
        let point = CompressedRistretto(arr)
            .decompress()
            .ok_or(PakeError::InvalidPoint)?;
        Ok(Self { point })
    }

    fn from_uniform_bytes(bytes: &[u8]) -> Result<Self, PakeError> {
        let arr: &[u8; 64] = bytes
            .try_into()
            .map_err(|_| PakeError::InvalidInput("from_uniform_bytes requires 64 bytes"))?;
        Ok(Self {
            point: RistrettoPoint::from_uniform_bytes(arr),
        })
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
            point: scalar * RISTRETTO_BASEPOINT_POINT,
        }
    }

    fn scalar_from_wide_bytes(bytes: &[u8]) -> Result<Scalar, PakeError> {
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| PakeError::InvalidInput("scalar_from_wide_bytes requires 64 bytes"))?;
        Ok(Scalar::from_bytes_mod_order_wide(&arr))
    }

    fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
        scalar.to_bytes().to_vec()
    }
}

/// Ristretto255 Diffie-Hellman group (byte-level operations).
pub struct Ristretto255Dh;

impl DhGroup for Ristretto255Dh {
    fn diffie_hellman(sk: &[u8], pk: &[u8]) -> Result<Vec<u8>, PakeError> {
        use curve25519_dalek::traits::Identity;
        use subtle::ConstantTimeEq;
        let sk_bytes: [u8; 32] = sk
            .try_into()
            .map_err(|_| PakeError::InvalidInput("invalid secret key length"))?;
        let scalar = Scalar::from_canonical_bytes(sk_bytes)
            .into_option()
            .ok_or(PakeError::InvalidInput("invalid scalar"))?;

        let pk_bytes: [u8; 32] = pk
            .try_into()
            .map_err(|_| PakeError::InvalidInput("invalid public key length"))?;
        let pk_point = CompressedRistretto(pk_bytes)
            .decompress()
            .ok_or(PakeError::InvalidInput("invalid public key point"))?;

        let result = scalar * pk_point;
        if bool::from(result.ct_eq(&RistrettoPoint::identity())) {
            return Err(PakeError::IdentityPoint);
        }
        Ok(result.compress().to_bytes().to_vec())
    }

    fn derive_keypair(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PakeError> {
        let server = voprf::OprfServer::<voprf::Ristretto255>::new_from_seed(
            seed,
            b"OPAQUE-DeriveDiffieHellmanKeyPair",
        )
        .map_err(|_| PakeError::ProtocolError("DeriveKeyPair failed"))?;

        let sk_bytes = server.serialize().to_vec();
        let sk_arr: [u8; 32] = sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PakeError::ProtocolError("invalid key size"))?;
        let scalar =
            Scalar::from_canonical_bytes(sk_arr)
                .into_option()
                .ok_or(PakeError::ProtocolError(
                    "invalid scalar from DeriveKeyPair",
                ))?;

        let pk = (scalar * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes()
            .to_vec();
        Ok((sk_bytes, pk))
    }

    fn generate_keypair(rng: &mut impl CryptoRngCore) -> Result<(Vec<u8>, Vec<u8>), PakeError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let result = Self::derive_keypair(&seed);
        seed.zeroize();
        result
    }

    fn public_key_from_private(sk: &[u8]) -> Result<Vec<u8>, PakeError> {
        let sk_bytes: [u8; 32] = sk
            .try_into()
            .map_err(|_| PakeError::InvalidInput("invalid secret key length"))?;
        let scalar = Scalar::from_canonical_bytes(sk_bytes)
            .into_option()
            .ok_or(PakeError::InvalidInput("invalid scalar"))?;
        let pk = (scalar * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes()
            .to_vec();
        Ok(pk)
    }
}
