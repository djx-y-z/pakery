//! Key derivation function trait.

use crate::error::PakeError;
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// A key derivation function (extract-then-expand).
pub trait Kdf {
    /// The length in bytes of the pseudorandom key returned by
    /// [`extract`](Self::extract).
    ///
    /// RFC 9807 defines OPAQUE's `Nx` as the output size of Extract, so an
    /// `OpaqueCiphersuite` whose `NX` disagrees with this value is rejected
    /// at compile time.
    const EXTRACT_SIZE: usize;

    /// Extract a pseudorandom key from input keying material.
    fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>>;

    /// Expand a pseudorandom key to the desired length.
    fn expand(prk: &[u8], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, PakeError>;
}
