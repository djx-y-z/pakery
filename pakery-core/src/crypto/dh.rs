//! Diffie-Hellman group trait for byte-level DH operations.

use crate::error::PakeError;
use alloc::vec::Vec;
use rand_core::CryptoRng;
use zeroize::Zeroizing;

/// A Diffie-Hellman group operating on byte-serialized keys.
pub trait DhGroup {
    /// Perform a Diffie-Hellman key exchange: `sk * pk`.
    fn diffie_hellman(sk: &[u8], pk: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError>;

    /// Derive a keypair deterministically from a seed.
    ///
    /// Returns `(secret_key, public_key)`.
    fn derive_keypair(seed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), PakeError>;

    /// Generate a random keypair.
    ///
    /// Returns `(secret_key, public_key)`.
    fn generate_keypair(
        rng: &mut impl CryptoRng,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), PakeError>;

    /// Compute the public key from a private key.
    fn public_key_from_private(sk: &[u8]) -> Result<Vec<u8>, PakeError>;
}
