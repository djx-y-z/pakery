//! Argon2id implementation of the Ksf trait.

use alloc::vec;
use alloc::vec::Vec;
use pakery_core::crypto::Ksf;
use pakery_core::PakeError;
use zeroize::Zeroizing;

/// Argon2id key stretching function for production use.
pub struct Argon2idKsf;

impl Ksf for Argon2idKsf {
    fn stretch(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let params = Params::new(65536, 3, 4, Some(64))
            .map_err(|_| PakeError::ProtocolError("argon2 params"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = vec![0u8; 64];
        argon2
            .hash_password_into(input, b"OPAQUE-Argon2id", &mut output)
            .map_err(|_| PakeError::ProtocolError("argon2 hash"))?;
        Ok(Zeroizing::new(output))
    }
}
