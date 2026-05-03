//! Server long-term setup for OPAQUE.

use alloc::vec;
use alloc::vec::Vec;

use crate::ciphersuite::OpaqueCiphersuite;
use pakery_core::crypto::DhGroup;
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Server's long-term configuration: OPRF seed and authentication keypair.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ServerSetup<C: OpaqueCiphersuite> {
    oprf_seed: Vec<u8>,
    server_private_key: Vec<u8>,
    server_public_key: Vec<u8>,
    #[zeroize(skip)]
    _marker: core::marker::PhantomData<C>,
}

impl<C: OpaqueCiphersuite> ServerSetup<C> {
    /// Create a new server setup with random seed and keypair.
    pub fn new(rng: &mut impl CryptoRng) -> Result<Self, crate::OpaqueError> {
        // oprf_seed must be Nh bytes per the spec (not Nseed)
        let mut oprf_seed = vec![0u8; C::NH];
        rng.fill_bytes(&mut oprf_seed);

        let (mut server_private_key, server_public_key) = C::Dh::generate_keypair(rng)?;

        Ok(Self {
            oprf_seed,
            server_private_key: core::mem::take(&mut *server_private_key),
            server_public_key,
            _marker: core::marker::PhantomData,
        })
    }

    /// Create a server setup with pre-determined values (for testing).
    ///
    /// # Security
    ///
    /// Allows construction with arbitrary (potentially weak) keys.
    /// This method is gated behind the `test-utils` feature.
    #[cfg(feature = "test-utils")]
    pub fn new_with_key(
        oprf_seed: Vec<u8>,
        server_private_key: Vec<u8>,
        server_public_key: Vec<u8>,
    ) -> Self {
        Self {
            oprf_seed,
            server_private_key,
            server_public_key,
            _marker: core::marker::PhantomData,
        }
    }

    /// The OPRF seed.
    pub fn oprf_seed(&self) -> &[u8] {
        &self.oprf_seed
    }

    /// The server's private key.
    pub fn private_key(&self) -> &[u8] {
        &self.server_private_key
    }

    /// The server's public key.
    pub fn public_key(&self) -> &[u8] {
        &self.server_public_key
    }
}
