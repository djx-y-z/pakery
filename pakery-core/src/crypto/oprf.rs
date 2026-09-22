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

    /// The serialized OPRF key length in bytes.
    ///
    /// This is OPAQUE's `Nok`. An `OpaqueCiphersuite` whose `NOK` disagrees
    /// with this value is rejected at compile time.
    const KEY_LEN: usize;

    /// The serialized OPRF group element length in bytes.
    ///
    /// This is OPAQUE's `Noe`. An `OpaqueCiphersuite` whose `NOE` disagrees
    /// with this value is rejected at compile time.
    const ELEMENT_LEN: usize;

    /// The length in bytes of [`OprfClientState::finalize`]'s output.
    ///
    /// This is OPAQUE's `Nh`: RFC 9807 derives the randomized password from
    /// `concat(oprf_output, Stretch(oprf_output))`, and §7's recommended
    /// configurations set the stretch length to `T = Nh`, so both halves are
    /// `Nh` bytes. An `OpaqueCiphersuite` whose `NH` disagrees with this
    /// value is rejected at compile time.
    ///
    /// It is declared here rather than inferred because `finalize` returns a
    /// `Vec<u8>`, whose length nothing else in this trait constrains.
    const OUTPUT_LEN: usize;

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
