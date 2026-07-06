//! SPAKE2+-specific error types.

use core::fmt;

/// Errors that can occur during SPAKE2+ protocol execution.
#[derive(Debug)]
pub enum Spake2PlusError {
    /// A received point could not be decoded as a valid group element.
    InvalidPoint,
    /// A computed or received point is the group identity element.
    IdentityPoint,
    /// MAC confirmation of the peer's key failed.
    ConfirmationFailed,
    /// An internal protocol error occurred.
    InternalError(&'static str),
}

impl fmt::Display for Spake2PlusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Spake2PlusError::InvalidPoint => write!(f, "invalid point encoding"),
            Spake2PlusError::IdentityPoint => write!(f, "identity point encountered"),
            Spake2PlusError::ConfirmationFailed => write!(f, "key confirmation failed"),
            Spake2PlusError::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Spake2PlusError {}

impl From<pakery_core::PakeError> for Spake2PlusError {
    fn from(e: pakery_core::PakeError) -> Self {
        match e {
            pakery_core::PakeError::InvalidPoint => Spake2PlusError::InvalidPoint,
            pakery_core::PakeError::IdentityPoint => Spake2PlusError::IdentityPoint,
            pakery_core::PakeError::ProtocolError(msg) => Spake2PlusError::InternalError(msg),
            pakery_core::PakeError::InvalidInput(msg) => Spake2PlusError::InternalError(msg),
        }
    }
}

impl From<Spake2PlusError> for pakery_core::PakeError {
    fn from(e: Spake2PlusError) -> Self {
        match e {
            Spake2PlusError::InvalidPoint => pakery_core::PakeError::InvalidPoint,
            Spake2PlusError::IdentityPoint => pakery_core::PakeError::IdentityPoint,
            Spake2PlusError::ConfirmationFailed => {
                pakery_core::PakeError::ProtocolError("key confirmation failed")
            }
            Spake2PlusError::InternalError(msg) => pakery_core::PakeError::ProtocolError(msg),
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
            Spake2PlusError::InvalidPoint.to_string(),
            "invalid point encoding"
        );
        assert_eq!(
            Spake2PlusError::IdentityPoint.to_string(),
            "identity point encountered"
        );
        assert_eq!(
            Spake2PlusError::ConfirmationFailed.to_string(),
            "key confirmation failed"
        );
        assert_eq!(
            Spake2PlusError::InternalError("kdf").to_string(),
            "internal error: kdf"
        );
    }

    #[test]
    fn from_pake_error_maps_every_variant() {
        assert!(matches!(
            Spake2PlusError::from(PakeError::InvalidPoint),
            Spake2PlusError::InvalidPoint
        ));
        assert!(matches!(
            Spake2PlusError::from(PakeError::IdentityPoint),
            Spake2PlusError::IdentityPoint
        ));
        assert!(matches!(
            Spake2PlusError::from(PakeError::ProtocolError("x")),
            Spake2PlusError::InternalError("x")
        ));
        assert!(matches!(
            Spake2PlusError::from(PakeError::InvalidInput("x")),
            Spake2PlusError::InternalError("x")
        ));
    }

    #[test]
    fn into_pake_error_maps_every_variant() {
        assert!(matches!(
            PakeError::from(Spake2PlusError::InvalidPoint),
            PakeError::InvalidPoint
        ));
        assert!(matches!(
            PakeError::from(Spake2PlusError::IdentityPoint),
            PakeError::IdentityPoint
        ));
        assert!(matches!(
            PakeError::from(Spake2PlusError::ConfirmationFailed),
            PakeError::ProtocolError("key confirmation failed")
        ));
        assert!(matches!(
            PakeError::from(Spake2PlusError::InternalError("x")),
            PakeError::ProtocolError("x")
        ));
    }
}
