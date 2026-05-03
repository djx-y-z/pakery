//! Oblivious pseudorandom function trait.

use crate::error::PakeError;
use alloc::vec::Vec;
use rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

/// Client-side OPRF state held between blind and finalize.
pub trait OprfClientState: Sized + Zeroize {
    /// Finalize the OPRF output given the password and server's evaluation.
    fn finalize(
        &self,
        password: &[u8],
        evaluated_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PakeError>;
}

/// An oblivious pseudorandom function.
pub trait Oprf {
    /// The client state type held between blind and finalize.
    type ClientState: OprfClientState;

    /// Blind a password. Returns `(state, blinded_element_bytes)`.
    fn client_blind(
        password: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::ClientState, Vec<u8>), PakeError>;

    /// Server-side: evaluate the blinded element with the given key.
    fn server_evaluate(oprf_key: &[u8], blinded_bytes: &[u8]) -> Result<Vec<u8>, PakeError>;

    /// Derive an OPRF key from a seed and info string.
    fn derive_key(seed: &[u8], info: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError>;
}
