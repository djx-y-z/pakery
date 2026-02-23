//! HMAC-SHA256 implementation of the Mac trait.

use alloc::vec::Vec;
use hmac::Hmac;
use pake_core::crypto::Mac;
use pake_core::PakeError;

/// HMAC with SHA-256.
pub struct HmacSha256;

impl Mac for HmacSha256 {
    fn mac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, PakeError> {
        use hmac::Mac as _;
        let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(key)
            .map_err(|_| PakeError::InvalidInput("HMAC key rejected"))?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}
