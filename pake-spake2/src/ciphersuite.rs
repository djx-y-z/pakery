//! SPAKE2 ciphersuite trait.

use pake_core::crypto::{CpaceGroup, Hash, Kdf, Mac};

/// Defines a SPAKE2 ciphersuite: group, hash, KDF, MAC, and protocol constants.
pub trait Spake2Ciphersuite: Sized + 'static {
    /// The prime-order group used for the protocol.
    type Group: CpaceGroup;
    /// The hash function used for transcript hashing.
    type Hash: Hash;
    /// The key derivation function.
    type Kdf: Kdf;
    /// The message authentication code.
    type Mac: Mac;

    /// Hash output length in bytes (e.g. 64 for SHA-512).
    const NH: usize;
    /// Pre-computed M point (compressed).
    const M_BYTES: &'static [u8];
    /// Pre-computed N point (compressed).
    const N_BYTES: &'static [u8];
}
