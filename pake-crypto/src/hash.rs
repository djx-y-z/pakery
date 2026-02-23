//! SHA-512 implementation of the Hash trait.

use alloc::vec::Vec;
use pake_core::crypto::Hash;
use sha2::Digest;

/// SHA-512 hash function.
#[derive(Clone)]
pub struct Sha512Hash {
    inner: sha2::Sha512,
}

impl Hash for Sha512Hash {
    fn new() -> Self {
        Self {
            inner: sha2::Sha512::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.inner.finalize().to_vec()
    }
}
