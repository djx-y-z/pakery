//! Message authentication code trait.

use crate::error::PakeError;
use alloc::vec::Vec;
use subtle::ConstantTimeEq;

/// A message authentication code.
pub trait Mac {
    /// Compute a MAC tag.
    fn mac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, PakeError>;

    /// Verify a MAC tag in constant time.
    fn verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), PakeError> {
        let computed = Self::mac(key, msg)?;
        // ctgrind: the verification outcome is a public accept/reject
        // decision; the comparison itself stays constant-time.
        if crate::ct::declassify_choice(computed.ct_eq(tag)) {
            Ok(())
        } else {
            Err(PakeError::ProtocolError("MAC verification failed"))
        }
    }
}
