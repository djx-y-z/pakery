//! Zeroizing shared secret type.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A shared secret that is automatically zeroized on drop.
///
/// Comparisons use constant-time equality to prevent timing side-channels.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl SharedSecret {
    /// Create a new `SharedSecret` from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Access the raw bytes of the shared secret.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SharedSecret {}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}
