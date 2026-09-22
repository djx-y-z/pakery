//! HKDF-SHA512 implementation of the Kdf trait.

use alloc::vec;
use alloc::vec::Vec;
use hkdf::Hkdf;
use pakery_core::crypto::Kdf;
use pakery_core::PakeError;
use zeroize::Zeroizing;

/// HKDF with SHA-512.
pub struct HkdfSha512;

impl Kdf for HkdfSha512 {
    const EXTRACT_SIZE: usize = 64;

    fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
        let (prk, _) = Hkdf::<sha2::Sha512>::extract(Some(salt), ikm);
        Zeroizing::new(prk.to_vec())
    }

    fn expand(prk: &[u8], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        let hkdf = Hkdf::<sha2::Sha512>::from_prk(prk)
            .map_err(|_| PakeError::InvalidInput("invalid PRK length"))?;
        // Zeroizing before the fallible call: on the `?` below the buffer is
        // dropped, and a plain `Vec` would drop unwiped.
        let mut output = Zeroizing::new(vec![0u8; len]);
        hkdf.expand(info, output.as_mut_slice())
            .map_err(|_| PakeError::ProtocolError("HKDF expand failed"))?;
        Ok(output)
    }
}
