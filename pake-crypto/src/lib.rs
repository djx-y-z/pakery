//! Concrete cryptographic implementations for PAKE protocols.
//!
//! Provides implementations of the traits defined in `pake-core::crypto`
//! backed by well-known cryptographic crates.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

// SHA-512 primitives: shared by ristretto255 and p256 (CPace P-256 needs SHA-512)
#[cfg(any(feature = "ristretto255", feature = "p256"))]
pub mod hash;
#[cfg(any(feature = "ristretto255", feature = "p256"))]
pub mod kdf;
#[cfg(any(feature = "ristretto255", feature = "p256"))]
pub mod mac;

#[cfg(feature = "argon2")]
pub mod ksf;
#[cfg(feature = "ristretto255")]
pub mod oprf_ristretto;
#[cfg(feature = "ristretto255")]
pub mod ristretto255;
#[cfg(feature = "ristretto255")]
pub mod spake2_constants;

// P-256 modules
#[cfg(feature = "p256")]
pub mod hash_sha256;
#[cfg(feature = "p256")]
pub mod kdf_sha256;
#[cfg(feature = "p256")]
pub mod mac_sha256;
#[cfg(feature = "p256")]
pub mod p256_group;
#[cfg(feature = "p256")]
pub mod spake2_constants_p256;

// SHA-512 re-exports
#[cfg(any(feature = "ristretto255", feature = "p256"))]
pub use hash::Sha512Hash;
#[cfg(any(feature = "ristretto255", feature = "p256"))]
pub use kdf::HkdfSha512;
#[cfg(any(feature = "ristretto255", feature = "p256"))]
pub use mac::HmacSha512;

#[cfg(feature = "argon2")]
pub use ksf::Argon2idKsf;
#[cfg(feature = "ristretto255")]
pub use oprf_ristretto::Ristretto255Oprf;
#[cfg(feature = "ristretto255")]
pub use ristretto255::{Ristretto255Dh, Ristretto255Group};
#[cfg(feature = "ristretto255")]
pub use spake2_constants::{SPAKE2_M_COMPRESSED, SPAKE2_N_COMPRESSED, SPAKE2_S_COMPRESSED};

// P-256 re-exports
#[cfg(feature = "p256")]
pub use hash_sha256::Sha256Hash;
#[cfg(feature = "p256")]
pub use kdf_sha256::HkdfSha256;
#[cfg(feature = "p256")]
pub use mac_sha256::HmacSha256;
#[cfg(feature = "p256")]
pub use p256_group::P256Group;
#[cfg(feature = "p256")]
pub use spake2_constants_p256::{SPAKE2_P256_M_COMPRESSED, SPAKE2_P256_N_COMPRESSED};
