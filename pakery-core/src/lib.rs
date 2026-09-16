//! Core utilities shared across PAKE protocol implementations.
//!
//! Provides encoding helpers (LEB128, length-value concatenation),
//! a zeroizing `SharedSecret` type, and common error types.

#![cfg_attr(not(feature = "std"), no_std)]
// docs.rs passes `--cfg docsrs` (see `[package.metadata.docs.rs]`), which
// turns this on and makes rustdoc label every `#[cfg(feature = ...)]` item
// with the feature that gates it. Inert everywhere else, so stable builds
// never see a `feature(...)` attribute.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod crypto;
pub mod ct;
pub mod encoding;
pub mod error;
pub mod secret;

pub use error::PakeError;
pub use secret::SharedSecret;
