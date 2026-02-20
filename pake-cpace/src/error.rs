//! CPace-specific error types.

use core::fmt;

/// Errors that can occur during CPace protocol execution.
#[derive(Debug)]
pub enum CpaceError {
    /// A received point could not be decoded as a valid group element.
    InvalidPoint,
    /// A computed or received point is the group identity element.
    IdentityPoint,
}

impl fmt::Display for CpaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CpaceError::InvalidPoint => write!(f, "invalid point encoding"),
            CpaceError::IdentityPoint => write!(f, "identity point encountered"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CpaceError {}

impl From<CpaceError> for pake_core::PakeError {
    fn from(e: CpaceError) -> Self {
        match e {
            CpaceError::InvalidPoint => pake_core::PakeError::InvalidPoint,
            CpaceError::IdentityPoint => pake_core::PakeError::IdentityPoint,
        }
    }
}
