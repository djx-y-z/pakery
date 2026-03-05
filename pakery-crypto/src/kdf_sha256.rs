//! HKDF-SHA256 implementation of the Kdf trait.

use alloc::vec;
use alloc::vec::Vec;
use hkdf::Hkdf;
use pakery_core::crypto::Kdf;
use pakery_core::PakeError;
use zeroize::Zeroizing;

/// HKDF with SHA-256.
pub struct HkdfSha256;

impl Kdf for HkdfSha256 {
    fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
        let (prk, _) = Hkdf::<sha2::Sha256>::extract(Some(salt), ikm);
        Zeroizing::new(prk.to_vec())
    }

    fn expand(prk: &[u8], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        let hkdf = Hkdf::<sha2::Sha256>::from_prk(prk)
            .map_err(|_| PakeError::InvalidInput("invalid PRK length"))?;
        let mut output = vec![0u8; len];
        hkdf.expand(info, &mut output)
            .map_err(|_| PakeError::ProtocolError("HKDF expand failed"))?;
        Ok(Zeroizing::new(output))
    }
}
