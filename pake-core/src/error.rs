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
