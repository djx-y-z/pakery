//! Test-only mock ciphersuite for zeroize assert-tests (roadmap item 7).
//!
//! Only the associated types matter: the mock OPRF client state is a plain
//! `[u8; 32]` wrapper so tests can construct protocol states directly and
//! inspect the bytes after `.zeroize()`. No cryptographic operation is ever
//! called.

use crate::ciphersuite::OpaqueCiphersuite;
use alloc::vec::Vec;
use pakery_core::crypto::{DhGroup, Hash, Kdf, Ksf, Mac, Oprf, OprfClientState};
use pakery_core::PakeError;
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

pub(crate) struct MockDh;

impl DhGroup for MockDh {
    fn diffie_hellman(_sk: &[u8], _pk: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        unimplemented!()
    }
    fn derive_keypair(_seed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), PakeError> {
        unimplemented!()
    }
    fn generate_keypair(
        _rng: &mut impl CryptoRng,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), PakeError> {
        unimplemented!()
    }
    fn public_key_from_private(_sk: &[u8]) -> Result<Vec<u8>, PakeError> {
        unimplemented!()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct MockOprfClientState {
    pub(crate) blind: [u8; 32],
}

impl OprfClientState for MockOprfClientState {
    fn finalize(
        &self,
        _password: &[u8],
        _evaluated_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        unimplemented!()
    }
}

pub(crate) struct MockOprf;

impl Oprf for MockOprf {
    type ClientState = MockOprfClientState;

    fn client_blind(
        _password: &[u8],
        _rng: &mut impl CryptoRng,
    ) -> Result<(Self::ClientState, Vec<u8>), PakeError> {
        unimplemented!()
    }
    fn server_evaluate(_oprf_key: &[u8], _blinded_bytes: &[u8]) -> Result<Vec<u8>, PakeError> {
        unimplemented!()
    }
    fn derive_key(_seed: &[u8], _info: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        unimplemented!()
    }
}

pub(crate) struct MockKsf;

impl Ksf for MockKsf {
    fn stretch(_input: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        unimplemented!()
    }
}

pub(crate) struct MockSuite;

impl OpaqueCiphersuite for MockSuite {
    type Hash = MockHash;
    type Kdf = MockKdf;
    type Mac = MockMac;
    type Dh = MockDh;
    type Oprf = MockOprf;
    type Ksf = MockKsf;

    const NN: usize = 32;
    const NSEED: usize = 32;
    const NOE: usize = 32;
    const NOK: usize = 32;
    const NM: usize = 64;
    const NH: usize = 64;
    const NPK: usize = 32;
    const NSK: usize = 32;
    const NX: usize = 64;
}
