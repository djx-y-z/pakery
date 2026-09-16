//! Concrete cryptographic implementations for PAKE protocols.
//!
//! Provides implementations of the traits defined in `pakery-core::crypto`
//! backed by well-known cryptographic crates.

#![cfg_attr(not(feature = "std"), no_std)]
// docs.rs passes `--cfg docsrs` (see `[package.metadata.docs.rs]`), which
// turns this on and makes rustdoc label every `#[cfg(feature = ...)]` item
// with the feature that gates it. Inert everywhere else, so stable builds
// never see a `feature(...)` attribute.
#![cfg_attr(docsrs, feature(doc_cfg))]
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
#[cfg(any(feature = "ristretto255", feature = "p256"))]
pub(crate) mod oprf_common;
#[cfg(feature = "ristretto255")]
pub mod oprf_ristretto;
#[cfg(feature = "ristretto255")]
pub mod ristretto255;
#[cfg(feature = "ristretto255")]
pub mod spake2_constants;

#[cfg(feature = "p256")]
pub mod oprf_p256;
#[cfg(feature = "p256")]
pub mod p256_dh;

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

// Pre-built ciphersuites
#[cfg(any(
    feature = "cpace",
    feature = "spake2",
    feature = "spake2plus",
    feature = "opaque"
))]
pub mod suites;

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
pub use oprf_p256::P256Oprf;
#[cfg(feature = "p256")]
pub use p256_dh::P256Dh;
#[cfg(feature = "p256")]
pub use p256_group::P256Group;
#[cfg(feature = "p256")]
pub use spake2_constants_p256::{SPAKE2_P256_M_COMPRESSED, SPAKE2_P256_N_COMPRESSED};

// Pre-built ciphersuite re-exports
#[cfg(all(feature = "cpace", feature = "p256"))]
pub use suites::CpaceP256;
#[cfg(all(feature = "cpace", feature = "ristretto255"))]
pub use suites::CpaceRistretto255;
#[cfg(all(feature = "opaque", feature = "p256"))]
pub use suites::OpaqueP256;
#[cfg(all(feature = "opaque", feature = "p256", feature = "argon2"))]
pub use suites::OpaqueP256Argon2;
#[cfg(all(feature = "opaque", feature = "ristretto255"))]
pub use suites::OpaqueRistretto255;
#[cfg(all(feature = "opaque", feature = "ristretto255", feature = "argon2"))]
pub use suites::OpaqueRistretto255Argon2;
#[cfg(all(feature = "spake2", feature = "p256"))]
pub use suites::Spake2P256;
#[cfg(all(feature = "spake2plus", feature = "p256"))]
pub use suites::Spake2PlusP256;
#[cfg(all(feature = "spake2plus", feature = "ristretto255"))]
pub use suites::Spake2PlusRistretto255;
#[cfg(all(feature = "spake2", feature = "ristretto255"))]
pub use suites::Spake2Ristretto255;
