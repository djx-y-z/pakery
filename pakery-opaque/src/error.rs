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

impl From<pakery_core::PakeError> for OpaqueError {
    fn from(e: pakery_core::PakeError) -> Self {
        match e {
            pakery_core::PakeError::InvalidInput(msg) => OpaqueError::InvalidInput(msg),
            pakery_core::PakeError::InvalidPoint => OpaqueError::InternalError("invalid point"),
            pakery_core::PakeError::IdentityPoint => OpaqueError::InternalError("identity point"),
            pakery_core::PakeError::ProtocolError(msg) => OpaqueError::InternalError(msg),
        }
    }
}

impl From<OpaqueError> for pakery_core::PakeError {
    fn from(e: OpaqueError) -> Self {
        match e {
            OpaqueError::InvalidInput(msg) => pakery_core::PakeError::InvalidInput(msg),
            _ => pakery_core::PakeError::ProtocolError("OPAQUE error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use pakery_core::PakeError;

    #[test]
    fn display_output_per_variant() {
        assert_eq!(
            OpaqueError::ServerAuthenticationError.to_string(),
            "server authentication failed"
        );
        assert_eq!(
            OpaqueError::ClientAuthenticationError.to_string(),
            "client authentication failed"
        );
        assert_eq!(
            OpaqueError::EnvelopeRecoveryError.to_string(),
            "envelope recovery failed"
        );
        assert_eq!(OpaqueError::InvalidMac.to_string(), "invalid MAC");
        assert_eq!(
            OpaqueError::DeserializationError.to_string(),
            "deserialization error"
        );
        assert_eq!(
            OpaqueError::InternalError("oprf").to_string(),
            "internal error: oprf"
        );
        assert_eq!(
            OpaqueError::InvalidInput("length").to_string(),
            "invalid input: length"
        );
    }

    #[test]
    fn from_pake_error_maps_every_variant() {
        assert!(matches!(
            OpaqueError::from(PakeError::InvalidInput("x")),
            OpaqueError::InvalidInput("x")
        ));
        assert!(matches!(
            OpaqueError::from(PakeError::InvalidPoint),
            OpaqueError::InternalError("invalid point")
        ));
        assert!(matches!(
            OpaqueError::from(PakeError::IdentityPoint),
            OpaqueError::InternalError("identity point")
        ));
        assert!(matches!(
            OpaqueError::from(PakeError::ProtocolError("x")),
            OpaqueError::InternalError("x")
        ));
    }

    #[test]
    fn into_pake_error_maps_every_variant() {
        assert!(matches!(
            PakeError::from(OpaqueError::InvalidInput("x")),
            PakeError::InvalidInput("x")
        ));
        for e in [
            OpaqueError::ServerAuthenticationError,
            OpaqueError::ClientAuthenticationError,
            OpaqueError::EnvelopeRecoveryError,
            OpaqueError::InvalidMac,
            OpaqueError::DeserializationError,
            OpaqueError::InternalError("x"),
        ] {
            assert!(matches!(
                PakeError::from(e),
                PakeError::ProtocolError("OPAQUE error")
            ));
        }
    }
}
