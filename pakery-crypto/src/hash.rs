//! SHA-512 implementation of the Hash trait.

use alloc::vec::Vec;
use pakery_core::crypto::Hash;
use sha2::Digest;

// Both SHA-2 hashers this crate uses must wipe themselves on drop. digest
// implements `ZeroizeOnDrop` for them only under sha2's `zeroize` feature,
// after checking that the core and the block buffer inside are both wiped,
// so this fails to compile if the workspace manifest drops the feature.
const _: () = {
    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    let _ = wiped_on_drop::<sha2::Sha256>;
    let _ = wiped_on_drop::<sha2::Sha512>;
};

/// SHA-512 hash function.
#[derive(Clone)]
pub struct Sha512Hash {
    inner: sha2::Sha512,
}

impl Hash for Sha512Hash {
    const OUTPUT_SIZE: usize = 64;

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
