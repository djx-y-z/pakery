//! OPRF operations for OPAQUE, delegating to the ciphersuite's Oprf trait.

use crate::ciphersuite::OpaqueCiphersuite;
use crate::OpaqueError;
use pake_core::crypto::{Kdf, Oprf as OprfTrait, OprfClientState as OprfClientStateTrait};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

/// State held by the client between blind and finalize.
///
/// # Zeroization caveat
///
/// The inner OPRF state (from the `voprf` crate) does not implement `Zeroize`,
/// so the OPRF blinding scalar is **not** explicitly zeroed when this type is
/// dropped.  The blind alone does not reveal the password (an attacker also
/// needs the OPRF evaluation response), and the exposure window is limited to
/// the lifetime of the login flow, but callers with strict memory-hygiene
/// requirements should be aware of this limitation.
pub struct OprfClientState<C: OpaqueCiphersuite> {
    pub(crate) state: <C::Oprf as OprfTrait>::ClientState,
}

/// Blind a password for the OPRF protocol.
///
/// Returns the client state (to keep) and the serialized blinded element (to send).
pub fn oprf_client_blind<C: OpaqueCiphersuite>(
    password: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(OprfClientState<C>, Vec<u8>), OpaqueError> {
    let (state, blinded_bytes) = C::Oprf::client_blind(password, rng)?;
    Ok((OprfClientState { state }, blinded_bytes))
}

/// Finalize the OPRF output on the client side.
pub fn oprf_client_finalize<C: OpaqueCiphersuite>(
    state: &OprfClientState<C>,
    password: &[u8],
    evaluated_bytes: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    Ok(state.state.finalize(password, evaluated_bytes)?)
}

/// Server-side OPRF evaluation: evaluate the blinded element with the given key.
pub fn oprf_server_evaluate<C: OpaqueCiphersuite>(
    oprf_key: &[u8],
    blinded_bytes: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    Ok(C::Oprf::server_evaluate(oprf_key, blinded_bytes)?)
}

/// Derive an OPRF key from the server's oprf_seed and a credential identifier.
///
/// Per RFC 9807:
/// ```text
/// seed = Expand(oprf_seed, concat(credential_id, "OprfKey"), Nseed)
/// (oprf_key, _) = OPRF.DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
/// ```
pub fn derive_oprf_key<C: OpaqueCiphersuite>(
    oprf_seed: &[u8],
    credential_id: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    let mut info = Vec::with_capacity(credential_id.len() + 7);
    info.extend_from_slice(credential_id);
    info.extend_from_slice(b"OprfKey");

    // oprf_seed is used directly as the PRK for KDF-Expand
    let seed = Zeroizing::new(C::Kdf::expand(oprf_seed, &info, C::NSEED)?);

    // Use OPRF DeriveKeyPair to get the actual scalar key
    Ok(C::Oprf::derive_key(&seed, b"OPAQUE-DeriveKeyPair")?)
}
