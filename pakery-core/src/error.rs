//! Common error types for PAKE protocols.

use core::fmt;

/// Errors that can occur during PAKE protocol execution.
#[derive(Debug)]
pub enum PakeError {
    /// A received point could not be decoded as a valid group element.
    InvalidPoint,
    /// A computed or received point is the group identity element.
    IdentityPoint,
    /// Invalid input was provided.
    InvalidInput(&'static str),
    /// A protocol-level error occurred.
    ProtocolError(&'static str),
}

impl fmt::Display for PakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PakeError::InvalidPoint => write!(f, "invalid point encoding"),
            PakeError::IdentityPoint => write!(f, "identity point encountered"),
            PakeError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            PakeError::ProtocolError(msg) => write!(f, "protocol error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PakeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn display_output_per_variant() {
        assert_eq!(
            PakeError::InvalidPoint.to_string(),
            "invalid point encoding"
        );
        assert_eq!(
            PakeError::IdentityPoint.to_string(),
            "identity point encountered"
        );
        assert_eq!(
            PakeError::InvalidInput("bad length").to_string(),
            "invalid input: bad length"
        );
        assert_eq!(
            PakeError::ProtocolError("mac mismatch").to_string(),
            "protocol error: mac mismatch"
        );
    }
}
