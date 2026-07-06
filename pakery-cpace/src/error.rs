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

impl From<pakery_core::PakeError> for CpaceError {
    fn from(e: pakery_core::PakeError) -> Self {
        match e {
            pakery_core::PakeError::IdentityPoint => CpaceError::IdentityPoint,
            _ => CpaceError::InvalidPoint,
        }
    }
}

impl From<CpaceError> for pakery_core::PakeError {
    fn from(e: CpaceError) -> Self {
        match e {
            CpaceError::InvalidPoint => pakery_core::PakeError::InvalidPoint,
            CpaceError::IdentityPoint => pakery_core::PakeError::IdentityPoint,
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
            CpaceError::InvalidPoint.to_string(),
            "invalid point encoding"
        );
        assert_eq!(
            CpaceError::IdentityPoint.to_string(),
            "identity point encountered"
        );
    }

    #[test]
    fn from_pake_error_maps_every_variant() {
        assert!(matches!(
            CpaceError::from(PakeError::IdentityPoint),
            CpaceError::IdentityPoint
        ));
        assert!(matches!(
            CpaceError::from(PakeError::InvalidPoint),
            CpaceError::InvalidPoint
        ));
        assert!(matches!(
            CpaceError::from(PakeError::InvalidInput("x")),
            CpaceError::InvalidPoint
        ));
        assert!(matches!(
            CpaceError::from(PakeError::ProtocolError("x")),
            CpaceError::InvalidPoint
        ));
    }

    #[test]
    fn into_pake_error_maps_every_variant() {
        assert!(matches!(
            PakeError::from(CpaceError::InvalidPoint),
            PakeError::InvalidPoint
        ));
        assert!(matches!(
            PakeError::from(CpaceError::IdentityPoint),
            PakeError::IdentityPoint
        ));
    }
}
