//! Concrete cryptographic implementations for PAKE protocols.
//!
//! Provides implementations of the traits defined in `pake-core::crypto`
//! backed by well-known cryptographic crates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "ristretto255")]
pub mod hash;
#[cfg(feature = "ristretto255")]
pub mod kdf;
#[cfg(feature = "argon2")]
pub mod ksf;
#[cfg(feature = "ristretto255")]
pub mod mac;
#[cfg(feature = "ristretto255")]
pub mod oprf_ristretto;
#[cfg(feature = "ristretto255")]
pub mod ristretto255;
#[cfg(feature = "ristretto255")]
pub mod spake2_constants;

#[cfg(feature = "ristretto255")]
pub use hash::Sha512Hash;
#[cfg(feature = "ristretto255")]
pub use kdf::HkdfSha512;
#[cfg(feature = "argon2")]
pub use ksf::Argon2idKsf;
#[cfg(feature = "ristretto255")]
pub use mac::HmacSha512;
#[cfg(feature = "ristretto255")]
pub use oprf_ristretto::Ristretto255Oprf;
#[cfg(feature = "ristretto255")]
pub use ristretto255::{Ristretto255Dh, Ristretto255Group};
#[cfg(feature = "ristretto255")]
pub use spake2_constants::{SPAKE2_M_COMPRESSED, SPAKE2_N_COMPRESSED, SPAKE2_S_COMPRESSED};
