//! Server long-term setup for OPAQUE.

use alloc::vec;
use alloc::vec::Vec;

use crate::ciphersuite::OpaqueCiphersuite;
use pakery_core::crypto::DhGroup;
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
        crate::ciphersuite::assert_lengths::<C>();
        // oprf_seed must be Nh bytes per the spec (not Nseed).
        //
        // Zeroizing while it is a local: `generate_keypair` below is fallible,
        // and on that `?` this buffer — already filled with the server's
        // long-term secret — would otherwise drop unwiped. The struct's own
        // `ZeroizeOnDrop` only starts covering it once it is a field.
        let mut oprf_seed = Zeroizing::new(vec![0u8; C::NH]);
        rng.fill_bytes(oprf_seed.as_mut_slice());
        // ctgrind: the OPRF seed is the server's long-term secret.
        pakery_core::ct::mark_secret(&oprf_seed);

        let (mut server_private_key, server_public_key) = C::Dh::generate_keypair(rng)?;

        Ok(Self {
            oprf_seed: core::mem::take(&mut *oprf_seed),
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
        crate::ciphersuite::assert_lengths::<C>();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_mocks::MockSuite;

    /// Calling `.zeroize()` on a live value must clear every secret field
    /// (roadmap item 7: catches a future field added without zeroization).
    /// The public key is not secret, but it is not skipped either — the
    /// derive clears it along with the rest.
    #[test]
    fn zeroize_clears_all_secret_fields() {
        let mut setup = ServerSetup::<MockSuite> {
            oprf_seed: vec![0xAA; 64],
            server_private_key: vec![0xBB; 32],
            server_public_key: vec![0xCC; 32],
            _marker: core::marker::PhantomData,
        };
        setup.zeroize();
        assert!(setup.oprf_seed.is_empty());
        assert!(setup.server_private_key.is_empty());
        assert!(setup.server_public_key.is_empty());
    }
}
