//! SPAKE2-specific error types.

use core::fmt;

/// Errors that can occur during SPAKE2 protocol execution.
#[derive(Debug)]
pub enum Spake2Error {
    /// A received point could not be decoded as a valid group element.
    InvalidPoint,
    /// A computed or received point is the group identity element.
    IdentityPoint,
    /// MAC confirmation of the peer's key failed.
    ConfirmationFailed,
    /// An internal protocol error occurred.
    InternalError(&'static str),
}

impl fmt::Display for Spake2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Spake2Error::InvalidPoint => write!(f, "invalid point encoding"),
            Spake2Error::IdentityPoint => write!(f, "identity point encountered"),
            Spake2Error::ConfirmationFailed => write!(f, "key confirmation failed"),
            Spake2Error::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Spake2Error {}

impl From<pakery_core::PakeError> for Spake2Error {
    fn from(e: pakery_core::PakeError) -> Self {
        match e {
            pakery_core::PakeError::InvalidPoint => Spake2Error::InvalidPoint,
            pakery_core::PakeError::IdentityPoint => Spake2Error::IdentityPoint,
            pakery_core::PakeError::ProtocolError(msg) => Spake2Error::InternalError(msg),
            pakery_core::PakeError::InvalidInput(msg) => Spake2Error::InternalError(msg),
        }
    }
}

impl From<Spake2Error> for pakery_core::PakeError {
    fn from(e: Spake2Error) -> Self {
        match e {
            Spake2Error::InvalidPoint => pakery_core::PakeError::InvalidPoint,
            Spake2Error::IdentityPoint => pakery_core::PakeError::IdentityPoint,
            Spake2Error::ConfirmationFailed => {
                pakery_core::PakeError::ProtocolError("key confirmation failed")
            }
            Spake2Error::InternalError(msg) => pakery_core::PakeError::ProtocolError(msg),
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
            Spake2Error::InvalidPoint.to_string(),
            "invalid point encoding"
        );
        assert_eq!(
            Spake2Error::IdentityPoint.to_string(),
            "identity point encountered"
        );
        assert_eq!(
            Spake2Error::ConfirmationFailed.to_string(),
            "key confirmation failed"
        );
        assert_eq!(
            Spake2Error::InternalError("kdf").to_string(),
            "internal error: kdf"
        );
    }

    #[test]
    fn from_pake_error_maps_every_variant() {
        assert!(matches!(
            Spake2Error::from(PakeError::InvalidPoint),
            Spake2Error::InvalidPoint
        ));
        assert!(matches!(
            Spake2Error::from(PakeError::IdentityPoint),
            Spake2Error::IdentityPoint
        ));
        assert!(matches!(
            Spake2Error::from(PakeError::ProtocolError("x")),
            Spake2Error::InternalError("x")
        ));
        assert!(matches!(
            Spake2Error::from(PakeError::InvalidInput("x")),
            Spake2Error::InternalError("x")
        ));
    }

    #[test]
    fn into_pake_error_maps_every_variant() {
        assert!(matches!(
            PakeError::from(Spake2Error::InvalidPoint),
            PakeError::InvalidPoint
        ));
        assert!(matches!(
            PakeError::from(Spake2Error::IdentityPoint),
            PakeError::IdentityPoint
        ));
        assert!(matches!(
            PakeError::from(Spake2Error::ConfirmationFailed),
            PakeError::ProtocolError("key confirmation failed")
        ));
        assert!(matches!(
            PakeError::from(Spake2Error::InternalError("x")),
            PakeError::ProtocolError("x")
        ));
    }
}
