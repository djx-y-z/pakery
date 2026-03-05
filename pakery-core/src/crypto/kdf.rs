//! Key derivation function trait.

use crate::error::PakeError;
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// A key derivation function (extract-then-expand).
pub trait Kdf {
    /// Extract a pseudorandom key from input keying material.
    fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>>;

    /// Expand a pseudorandom key to the desired length.
    fn expand(prk: &[u8], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, PakeError>;
}
