//! Key derivation functions for the OPAQUE protocol (RFC 9807 Section 6.4).

use alloc::vec;
use alloc::vec::Vec;

use crate::ciphersuite::OpaqueCiphersuite;
use crate::OpaqueError;
use pakery_core::crypto::{DhGroup, Hash, Kdf, Ksf};
use zeroize::Zeroizing;

/// I2OSP: Integer to Octet String Primitive (big-endian encoding).
///
/// Returns an error if `value` cannot be represented in `length` bytes.
fn i2osp(value: usize, length: usize) -> Result<Vec<u8>, OpaqueError> {
    let max: usize = match length {
        1 => 0xFF,
        2 => 0xFFFF,
        _ => usize::MAX,
    };
    if value > max {
        return Err(OpaqueError::InvalidInput(
            "I2OSP: integer too large for encoding length",
        ));
    }
    let mut out = vec![0u8; length];
    let mut v = value;
    for i in (0..length).rev() {
        out[i] = (v & 0xff) as u8;
        v >>= 8;
    }
    Ok(out)
}

/// Expand-Label per RFC 9807 Section 6.4:
///
/// ```text
/// Expand-Label(Secret, Label, Context, Length) =
///   KDF.Expand(Secret, CustomLabel, Length)
///
/// CustomLabel = I2OSP(Length, 2) || I2OSP(len("OPAQUE-" || Label), 1)
///               || "OPAQUE-" || Label || I2OSP(len(Context), 1) || Context
/// ```
pub fn expand_label<C: OpaqueCiphersuite>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    let opaque_label = [b"OPAQUE-" as &[u8], label].concat();

    let mut custom_label = Vec::new();
    custom_label.extend_from_slice(&i2osp(length, 2)?);
    custom_label.extend_from_slice(&i2osp(opaque_label.len(), 1)?);
    custom_label.extend_from_slice(&opaque_label);
    custom_label.extend_from_slice(&i2osp(context.len(), 1)?);
    custom_label.extend_from_slice(context);

    Ok(C::Kdf::expand(secret, &custom_label, length)?)
}

/// Derive-Secret per RFC 9807:
///
/// ```text
/// Derive-Secret(Secret, Label, TranscriptHash) =
///   Expand-Label(Secret, Label, TranscriptHash, Nx)
/// ```
pub fn derive_secret<C: OpaqueCiphersuite>(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    expand_label::<C>(secret, label, transcript_hash, C::NX)
}

/// Derive the randomized password from the OPRF output.
///
/// ```text
/// randomized_pwd = Extract("", concat(oprf_output, Harden(oprf_output, params)))
/// ```
pub fn derive_randomized_password<C: OpaqueCiphersuite>(
    oprf_output: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    let hardened = C::Ksf::stretch(oprf_output)?;
    let mut ikm = Zeroizing::new(Vec::with_capacity(oprf_output.len() + hardened.len()));
    ikm.extend_from_slice(oprf_output);
    ikm.extend_from_slice(&hardened);
    Ok(C::Kdf::extract(&[], &ikm))
}

/// Build the transcript preamble for the 3DH key exchange.
///
/// ```text
/// preamble = "OPAQUEv1-" || I2OSP(len(context), 2) || context
///          || I2OSP(len(client_identity), 2) || client_identity
///          || KE1
///          || I2OSP(len(server_identity), 2) || server_identity
///          || inner_ke2
/// ```
pub fn build_preamble(
    context: &[u8],
    client_identity: &[u8],
    ke1_bytes: &[u8],
    server_identity: &[u8],
    inner_ke2: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    // I2OSP(len, 2) requires values to fit in u16.
    if context.len() > u16::MAX as usize {
        return Err(OpaqueError::InvalidInput("context exceeds u16 length"));
    }
    if client_identity.len() > u16::MAX as usize {
        return Err(OpaqueError::InvalidInput(
            "client_identity exceeds u16 length",
        ));
    }
    if server_identity.len() > u16::MAX as usize {
        return Err(OpaqueError::InvalidInput(
            "server_identity exceeds u16 length",
        ));
    }

    let mut preamble = Vec::new();
    preamble.extend_from_slice(b"OPAQUEv1-");

    // context with 2-byte length prefix
    preamble.extend_from_slice(&i2osp(context.len(), 2)?);
    preamble.extend_from_slice(context);

    // client_identity with 2-byte length prefix
    preamble.extend_from_slice(&i2osp(client_identity.len(), 2)?);
    preamble.extend_from_slice(client_identity);

    // KE1 (no length prefix — fixed size)
    preamble.extend_from_slice(ke1_bytes);

    // server_identity with 2-byte length prefix
    preamble.extend_from_slice(&i2osp(server_identity.len(), 2)?);
    preamble.extend_from_slice(server_identity);

    // inner_ke2 (no length prefix — fixed size)
    preamble.extend_from_slice(inner_ke2);

    Ok(preamble)
}

/// Derive the handshake keys (km2, km3, session_key) from the TripleDH ikm.
///
/// Per RFC 9807 Section 6.4.2:
/// ```text
/// prk = Extract("", ikm)
/// preamble_hash = Hash(preamble)
/// handshake_secret = Derive-Secret(prk, "HandshakeSecret", preamble_hash)
/// session_key = Derive-Secret(prk, "SessionKey", preamble_hash)
/// km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
/// km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
/// ```
///
/// Returns `(km2, km3, session_key)`.
#[allow(clippy::type_complexity)]
pub fn derive_keys<C: OpaqueCiphersuite>(
    ikm: &[u8],
    preamble: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), OpaqueError> {
    let prk = C::Kdf::extract(&[], ikm);
    let preamble_hash = C::Hash::digest(preamble);

    let handshake_secret = derive_secret::<C>(&prk, b"HandshakeSecret", &preamble_hash)?;
    let session_key = derive_secret::<C>(&prk, b"SessionKey", &preamble_hash)?;

    let km2 = derive_secret::<C>(&handshake_secret, b"ServerMAC", b"")?;
    let km3 = derive_secret::<C>(&handshake_secret, b"ClientMAC", b"")?;

    Ok((km2, km3, session_key))
}

/// Compute the TripleDH shared secret.
///
/// ```text
/// ikm = concat(DH(client_eph_sk, server_eph_pk),
///              DH(client_eph_sk, server_static_pk),
///              DH(client_static_sk, server_eph_pk))
/// ```
pub fn triple_dh_ikm<C: OpaqueCiphersuite>(
    dh1_sk: &[u8],
    dh1_pk: &[u8],
    dh2_sk: &[u8],
    dh2_pk: &[u8],
    dh3_sk: &[u8],
    dh3_pk: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    let dh1 = C::Dh::diffie_hellman(dh1_sk, dh1_pk)?;
    let dh2 = C::Dh::diffie_hellman(dh2_sk, dh2_pk)?;
    let dh3 = C::Dh::diffie_hellman(dh3_sk, dh3_pk)?;

    let mut ikm = Zeroizing::new(Vec::with_capacity(dh1.len() + dh2.len() + dh3.len()));
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    Ok(ikm)
}
