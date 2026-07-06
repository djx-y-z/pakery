//! Zeroizing shared secret type.

use alloc::vec::Vec;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A shared secret that is automatically zeroized on drop.
///
/// Comparisons use constant-time equality to prevent timing side-channels.
///
/// # Cloning
///
/// This type implements [`Clone`].  Each clone is independently zeroized on
/// drop, but callers should be mindful that every clone creates an additional
/// copy of the secret material in memory.  Prefer moving over cloning where
/// possible.
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
        // ctgrind: the equality outcome is the caller's public accept/reject
        // decision; the comparison itself stays constant-time.
        crate::ct::declassify_choice(self.ct_eq(other))
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Calling `.zeroize()` on a live value must clear every secret field
    /// (roadmap item 7: catches a future field added without zeroization).
    #[test]
    fn zeroize_clears_all_secret_fields() {
        let mut secret = SharedSecret::new(vec![0xAA; 32]);
        secret.zeroize();
        assert!(secret.bytes.is_empty());
    }

    /// Equality must hold for identical secrets and fail for differing ones
    /// (roadmap item 8: a mutant replacing `eq` with `true` survived — the
    /// negative case was never asserted directly on `SharedSecret`).
    #[test]
    fn equality_distinguishes_secrets() {
        let a = SharedSecret::new(vec![0xAA; 32]);
        let b = SharedSecret::new(vec![0xAA; 32]);
        let c = SharedSecret::new(vec![0xBB; 32]);
        let short = SharedSecret::new(vec![0xAA; 16]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, short);
    }

    /// Debug output must redact the secret bytes (security convention:
    /// roadmap item 8 caught the redaction being unasserted).
    #[test]
    fn debug_redacts_secret_bytes() {
        use alloc::format;
        let rendered = format!("{:?}", SharedSecret::new(vec![0xAB; 4]));
        assert_eq!(rendered, "SharedSecret { bytes: \"[REDACTED]\" }");
    }
}
