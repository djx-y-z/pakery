//! CPace balanced PAKE protocol implementation.
//!
//! Implements the CPace protocol per draft-irtf-cfrg-cpace-18 with
//! pluggable ciphersuites.

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
pub mod error;
pub mod generator;
pub mod initiator;
pub mod responder;
pub mod transcript;

pub use ciphersuite::CpaceCiphersuite;
pub use error::CpaceError;
pub use initiator::{CpaceInitiator, CpaceOutput, InitiatorState};
pub use responder::CpaceResponder;
pub use transcript::CpaceMode;
