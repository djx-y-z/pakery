//! SPAKE2 balanced PAKE protocol implementation.
//!
//! Implements the SPAKE2 protocol per RFC 9382 with pluggable ciphersuites.

#![cfg_attr(not(feature = "std"), no_std)]
// docs.rs passes `--cfg docsrs` (see `[package.metadata.docs.rs]`), which
// turns this on and makes rustdoc label every `#[cfg(feature = ...)]` item
// with the feature that gates it. Inert everywhere else, so stable builds
// never see a `feature(...)` attribute.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod ciphersuite;
pub mod encoding;
pub mod error;
pub mod party_a;
pub mod party_b;
#[cfg(test)]
pub(crate) mod test_mocks;
pub mod transcript;

pub use ciphersuite::Spake2Ciphersuite;
pub use error::Spake2Error;
pub use party_a::{PartyA, PartyAState};
pub use party_b::{PartyB, PartyBState};
pub use transcript::Spake2Output;
