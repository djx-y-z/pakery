//! Envelope operations for OPAQUE (RFC 9807 Section 6.3).

use alloc::vec::Vec;

use crate::ciphersuite::OpaqueCiphersuite;
use crate::messages::Envelope;
use crate::OpaqueError;
use pakery_core::crypto::{DhGroup, Kdf, Mac};
use zeroize::Zeroizing;

/// Cleartext credentials used in the envelope auth tag computation.
///
/// ```text
/// CleartextCredentials = server_public_key
///                      || I2OSP(len(server_identity), 2) || server_identity
///                      || I2OSP(len(client_identity), 2) || client_identity
/// ```
pub fn build_cleartext_credentials(
    server_public_key: &[u8],
    server_identity: &[u8],
    client_identity: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    // Guard against I2OSP(len, 2) overflow: identities must fit in u16.
    if server_identity.len() > u16::MAX as usize {
        return Err(OpaqueError::InvalidInput(
            "server_identity exceeds u16 length",
        ));
    }
    if client_identity.len() > u16::MAX as usize {
        return Err(OpaqueError::InvalidInput(
            "client_identity exceeds u16 length",
        ));
    }

    let mut creds = Vec::with_capacity(
        server_public_key.len() + 2 + server_identity.len() + 2 + client_identity.len(),
    );
    creds.extend_from_slice(server_public_key);

    // server_identity with 2-byte big-endian length prefix
    creds.extend_from_slice(&(server_identity.len() as u16).to_be_bytes());
    creds.extend_from_slice(server_identity);

    // client_identity with 2-byte big-endian length prefix
    creds.extend_from_slice(&(client_identity.len() as u16).to_be_bytes());
    creds.extend_from_slice(client_identity);

    Ok(creds)
}

/// Helper to build info = concat(nonce, label) for envelope key derivation.
fn envelope_info(nonce: &[u8], label: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(nonce.len() + label.len());
    info.extend_from_slice(nonce);
    info.extend_from_slice(label);
    info
}

/// Store: Create an envelope during registration.
///
/// Returns `(envelope, client_public_key, masking_key, export_key)`.
#[allow(clippy::type_complexity)]
pub fn store<C: OpaqueCiphersuite>(
    randomized_pwd: &[u8],
    server_public_key: &[u8],
    server_identity: &[u8],
    client_identity: &[u8],
    nonce: &[u8],
) -> Result<(Envelope, Vec<u8>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), OpaqueError> {
    // masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    let masking_key = C::Kdf::expand(randomized_pwd, b"MaskingKey", C::NH)?;

    // auth_key = Expand(randomized_pwd, concat(nonce, "AuthKey"), Nh)
    let auth_key = C::Kdf::expand(randomized_pwd, &envelope_info(nonce, b"AuthKey"), C::NH)?;

    // export_key = Expand(randomized_pwd, concat(nonce, "ExportKey"), Nh)
    let export_key = C::Kdf::expand(randomized_pwd, &envelope_info(nonce, b"ExportKey"), C::NH)?;

    // seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nseed)
    let seed = C::Kdf::expand(
        randomized_pwd,
        &envelope_info(nonce, b"PrivateKey"),
        C::NSEED,
    )?;

    // (client_private_key, client_public_key) = DeriveAuthKeyPair(seed)
    let (_, client_public_key) = C::Dh::derive_keypair(&seed)?;

    // Resolve identities: use public keys as defaults if empty
    let client_id = if client_identity.is_empty() {
        &client_public_key
    } else {
        client_identity
    };
    let server_id = if server_identity.is_empty() {
        server_public_key
    } else {
        server_identity
    };

    let cleartext_creds = build_cleartext_credentials(server_public_key, server_id, client_id)?;

    // auth_tag = MAC(auth_key, concat(nonce, cleartext_creds))
    let mut mac_input = Vec::with_capacity(nonce.len() + cleartext_creds.len());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(&cleartext_creds);
    let auth_tag = C::Mac::mac(&auth_key, &mac_input)?;

    let envelope = Envelope {
        nonce: nonce.to_vec(),
        auth_tag,
    };

    Ok((envelope, client_public_key, masking_key, export_key))
}

/// Recover: Open an envelope during login.
///
/// Returns `(client_private_key, client_public_key, export_key)`.
#[allow(clippy::type_complexity)]
pub fn recover<C: OpaqueCiphersuite>(
    randomized_pwd: &[u8],
    server_public_key: &[u8],
    server_identity: &[u8],
    client_identity: &[u8],
    envelope: &Envelope,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, Zeroizing<Vec<u8>>), OpaqueError> {
    let nonce = &envelope.nonce;

    // auth_key = Expand(randomized_pwd, concat(nonce, "AuthKey"), Nh)
    let auth_key = C::Kdf::expand(randomized_pwd, &envelope_info(nonce, b"AuthKey"), C::NH)?;

    // export_key = Expand(randomized_pwd, concat(nonce, "ExportKey"), Nh)
    let export_key = C::Kdf::expand(randomized_pwd, &envelope_info(nonce, b"ExportKey"), C::NH)?;

    // seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nseed)
    let seed = C::Kdf::expand(
        randomized_pwd,
        &envelope_info(nonce, b"PrivateKey"),
        C::NSEED,
    )?;

    // (client_private_key, client_public_key) = DeriveAuthKeyPair(seed)
    let (client_private_key, client_public_key) = C::Dh::derive_keypair(&seed)?;

    // Resolve identities
    let client_id = if client_identity.is_empty() {
        &client_public_key
    } else {
        client_identity
    };
    let server_id = if server_identity.is_empty() {
        server_public_key
    } else {
        server_identity
    };

    let cleartext_creds = build_cleartext_credentials(server_public_key, server_id, client_id)?;

    // Verify auth_tag
    let mut mac_input = Vec::with_capacity(nonce.len() + cleartext_creds.len());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(&cleartext_creds);

    C::Mac::verify(&auth_key, &mac_input, &envelope.auth_tag)
        .map_err(|_| OpaqueError::EnvelopeRecoveryError)?;

    Ok((client_private_key, client_public_key, export_key))
}
