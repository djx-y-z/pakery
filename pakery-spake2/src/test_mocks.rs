//! Test-only mock ciphersuite for zeroize assert-tests (roadmap item 7).
//!
//! Only the associated types matter: the mock's `Scalar` is a plain
//! `[u8; 32]` so tests can construct protocol states directly and inspect
//! the bytes after `.zeroize()`. No cryptographic operation is ever called.

use crate::ciphersuite::Spake2Ciphersuite;
use alloc::vec::Vec;
use pakery_core::crypto::{CpaceGroup, Hash, Kdf, Mac};
use pakery_core::PakeError;
use rand_core::CryptoRng;
use zeroize::Zeroizing;

#[derive(Clone, PartialEq)]
pub(crate) struct MockPoint;

impl CpaceGroup for MockPoint {
    type Scalar = [u8; 32];

    fn scalar_mul(&self, _scalar: &Self::Scalar) -> Self {
        unimplemented!()
    }
    fn is_identity(&self) -> bool {
        unimplemented!()
    }
    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
    fn from_bytes(_bytes: &[u8]) -> Result<Self, PakeError> {
        unimplemented!()
    }
    fn from_uniform_bytes(_bytes: &[u8]) -> Result<Self, PakeError> {
        unimplemented!()
    }
    fn random_scalar(_rng: &mut impl CryptoRng) -> Self::Scalar {
        unimplemented!()
    }
    fn add(&self, _other: &Self) -> Self {
        unimplemented!()
    }
    fn negate(&self) -> Self {
        unimplemented!()
    }
    fn basepoint_mul(_scalar: &Self::Scalar) -> Self {
        unimplemented!()
    }
    fn scalar_from_wide_bytes(_bytes: &[u8]) -> Result<Self::Scalar, PakeError> {
        unimplemented!()
    }
    fn scalar_to_bytes(_scalar: &Self::Scalar) -> Vec<u8> {
        unimplemented!()
    }
}

#[derive(Clone)]
pub(crate) struct MockHash;

impl Hash for MockHash {
    const OUTPUT_SIZE: usize = 64;

    fn new() -> Self {
        unimplemented!()
    }
    fn update(&mut self, _data: &[u8]) {
        unimplemented!()
    }
    fn finalize(self) -> Vec<u8> {
        unimplemented!()
    }
}

pub(crate) struct MockKdf;

impl Kdf for MockKdf {
    fn extract(_salt: &[u8], _ikm: &[u8]) -> Zeroizing<Vec<u8>> {
        unimplemented!()
    }
    fn expand(_prk: &[u8], _info: &[u8], _len: usize) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        unimplemented!()
    }
}

pub(crate) struct MockMac;

impl Mac for MockMac {
    fn mac(_key: &[u8], _msg: &[u8]) -> Result<Vec<u8>, PakeError> {
        unimplemented!()
    }
}

pub(crate) struct MockSuite;

impl Spake2Ciphersuite for MockSuite {
    type Group = MockPoint;
    type Hash = MockHash;
    type Kdf = MockKdf;
    type Mac = MockMac;

    const NH: usize = 64;
    const M_BYTES: &'static [u8] = &[0u8; 32];
    const N_BYTES: &'static [u8] = &[0u8; 32];
}
