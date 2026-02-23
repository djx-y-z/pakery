//! HMAC-SHA512 implementation of the Mac trait.

use alloc::vec::Vec;
use hmac::Hmac;
use pake_core::crypto::Mac;
use pake_core::PakeError;

/// HMAC with SHA-512.
pub struct HmacSha512;

impl Mac for HmacSha512 {
    fn mac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, PakeError> {
        use hmac::Mac as _;
        let mut mac = <Hmac<sha2::Sha512>>::new_from_slice(key)
            .map_err(|_| PakeError::InvalidInput("HMAC key rejected"))?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}
