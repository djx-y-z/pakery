//! SHA-256 implementation of the Hash trait.

use pake_core::crypto::Hash;
use sha2::Digest;

/// SHA-256 hash function.
#[derive(Clone)]
pub struct Sha256Hash {
    inner: sha2::Sha256,
}

impl Hash for Sha256Hash {
    fn new() -> Self {
        Self {
            inner: sha2::Sha256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.inner.finalize().to_vec()
    }
}
