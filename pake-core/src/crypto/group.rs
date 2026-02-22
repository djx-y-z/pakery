//! CPace group trait for typed group operations.

use crate::error::PakeError;
use alloc::vec::Vec;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

/// A prime-order group suitable for CPace.
///
/// Operations are typed (not byte-level) for performance and type safety.
pub trait CpaceGroup: Clone + PartialEq {
    /// The scalar type for this group.
    type Scalar: Clone + Zeroize;

    /// Scalar multiplication: `self * scalar`.
    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self;

    /// Check whether this element is the identity.
    fn is_identity(&self) -> bool;

    /// Serialize to bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, PakeError>;

    /// Map uniform random bytes (of length `2 * field_size`) to a group element.
    fn from_uniform_bytes(bytes: &[u8]) -> Result<Self, PakeError>;

    /// Sample a random scalar.
    fn random_scalar(rng: &mut impl CryptoRngCore) -> Self::Scalar;

    /// Point addition: `self + other`.
    fn add(&self, other: &Self) -> Self;

    /// Point negation: `-self`.
    fn negate(&self) -> Self;

    /// Basepoint (generator) multiplication: `scalar * G`.
    fn basepoint_mul(scalar: &Self::Scalar) -> Self;

    /// Deserialize a scalar from 64 wide bytes (reduced mod group order).
    fn scalar_from_wide_bytes(bytes: &[u8]) -> Result<Self::Scalar, PakeError>;

    /// Serialize a scalar to bytes.
    fn scalar_to_bytes(scalar: &Self::Scalar) -> Vec<u8>;
}
