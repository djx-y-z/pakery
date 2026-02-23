//! Error types for the OPAQUE protocol.

use core::fmt;

/// Errors that can occur during the OPAQUE protocol.
///
/// # Security
///
/// The distinct error variants are useful for server-side logging and
/// debugging, but they **must not** be exposed verbatim to remote clients.
/// Returning different error messages for [`ServerAuthenticationError`],
/// [`EnvelopeRecoveryError`], and [`InvalidMac`] can serve as an oracle,
/// allowing an attacker to distinguish "wrong password" from "server MAC
/// failure" from other conditions.  Always map all authentication-related
/// errors to a single opaque response before sending over the wire.
///
/// [`ServerAuthenticationError`]: OpaqueError::ServerAuthenticationError
/// [`EnvelopeRecoveryError`]: OpaqueError::EnvelopeRecoveryError
/// [`InvalidMac`]: OpaqueError::InvalidMac
#[derive(Debug)]
pub enum OpaqueError {
    /// The server's MAC did not verify during login.
    ServerAuthenticationError,
    /// The client's MAC did not verify during login.
    ClientAuthenticationError,
    /// The envelope could not be recovered (wrong password).
    EnvelopeRecoveryError,
    /// A MAC verification failed.
    InvalidMac,
    /// A message could not be deserialized.
    DeserializationError,
    /// An internal error occurred.
    InternalError(&'static str),
    /// Invalid input was provided.
    InvalidInput(&'static str),
}

impl fmt::Display for OpaqueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerAuthenticationError => write!(f, "server authentication failed"),
            Self::ClientAuthenticationError => write!(f, "client authentication failed"),
            Self::EnvelopeRecoveryError => write!(f, "envelope recovery failed"),
            Self::InvalidMac => write!(f, "invalid MAC"),
            Self::DeserializationError => write!(f, "deserialization error"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OpaqueError {}

impl From<pake_core::PakeError> for OpaqueError {
    fn from(e: pake_core::PakeError) -> Self {
        match e {
            pake_core::PakeError::InvalidInput(msg) => OpaqueError::InvalidInput(msg),
            pake_core::PakeError::InvalidPoint => OpaqueError::InternalError("invalid point"),
            pake_core::PakeError::IdentityPoint => OpaqueError::InternalError("identity point"),
            pake_core::PakeError::ProtocolError(msg) => OpaqueError::InternalError(msg),
        }
    }
}

impl From<OpaqueError> for pake_core::PakeError {
    fn from(e: OpaqueError) -> Self {
        match e {
            OpaqueError::InvalidInput(msg) => pake_core::PakeError::InvalidInput(msg),
            _ => pake_core::PakeError::ProtocolError("OPAQUE error"),
        }
    }
}
