//! CPace ciphersuite trait and implementations.

use digest::Digest;
use group::{Group, GroupEncoding};
use rand_core::CryptoRngCore;

/// Defines a CPace ciphersuite: a prime-order group, hash function, and associated parameters.
pub trait CpaceCiphersuite {
    /// The prime-order group used for the protocol.
    type Group: Group + GroupEncoding;
    /// The hash function used for transcript hashing.
    type Hash: Digest + Clone;

    /// Domain Separation Identifier, e.g. `b"CPaceRistretto255"`.
    const DSI: &'static [u8];
    /// Hash input block size in bytes (128 for SHA-512).
    const HASH_BLOCK_SIZE: usize;
    /// Field element size in bytes (32 for Ristretto255).
    const FIELD_SIZE_BYTES: usize;

    /// Map `2 * FIELD_SIZE_BYTES` uniform random bytes to a group element.
    fn element_derivation(uniform_bytes: &[u8]) -> Self::Group;

    /// Sample a random scalar from a cryptographic RNG.
    fn sample_scalar(rng: &mut impl CryptoRngCore) -> <Self::Group as Group>::Scalar;
}

/// CPace ciphersuite using Ristretto255 with SHA-512.
#[cfg(feature = "ristretto255")]
pub struct Ristretto255Sha512;

#[cfg(feature = "ristretto255")]
impl CpaceCiphersuite for Ristretto255Sha512 {
    type Group = curve25519_dalek::RistrettoPoint;
    type Hash = sha2::Sha512;

    const DSI: &'static [u8] = b"CPaceRistretto255";
    const HASH_BLOCK_SIZE: usize = 128;
    const FIELD_SIZE_BYTES: usize = 32;

    fn element_derivation(bytes: &[u8]) -> curve25519_dalek::RistrettoPoint {
        let arr: &[u8; 64] = bytes
            .try_into()
            .expect("element_derivation requires 64 bytes");
        curve25519_dalek::RistrettoPoint::from_uniform_bytes(arr)
    }

    fn sample_scalar(rng: &mut impl CryptoRngCore) -> curve25519_dalek::Scalar {
        curve25519_dalek::Scalar::random(rng)
    }
}
