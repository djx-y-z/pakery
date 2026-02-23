//! Key stretching function trait.

use crate::error::PakeError;
use alloc::vec::Vec;

/// A key stretching function (KSF) used to harden passwords.
pub trait Ksf {
    /// Stretch the input bytes.
    fn stretch(input: &[u8]) -> Result<Vec<u8>, PakeError>;
}

/// Identity key stretching function (pass-through).
///
/// **WARNING: Not suitable for production.**  This KSF applies no work factor
/// and returns the input unchanged.  It exists solely for RFC test vectors
/// that specify no password hardening.  In production, use a proper KSF such
/// as Argon2id (see `pake-crypto::Argon2idKsf`).
pub struct IdentityKsf;

impl Ksf for IdentityKsf {
    fn stretch(input: &[u8]) -> Result<Vec<u8>, PakeError> {
        Ok(input.to_vec())
    }
}
