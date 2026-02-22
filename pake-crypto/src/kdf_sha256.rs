//! HKDF-SHA256 implementation of the Kdf trait.

use hkdf::Hkdf;
use pake_core::crypto::Kdf;
use pake_core::PakeError;

/// HKDF with SHA-256.
pub struct HkdfSha256;

impl Kdf for HkdfSha256 {
    fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _) = Hkdf::<sha2::Sha256>::extract(Some(salt), ikm);
        prk.to_vec()
    }

    fn expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, PakeError> {
        let hkdf = Hkdf::<sha2::Sha256>::from_prk(prk)
            .map_err(|_| PakeError::InvalidInput("invalid PRK length"))?;
        let mut output = vec![0u8; len];
        hkdf.expand(info, &mut output)
            .map_err(|_| PakeError::ProtocolError("HKDF expand failed"))?;
        Ok(output)
    }
}
