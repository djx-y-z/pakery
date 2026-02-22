//! SPAKE2 balanced PAKE protocol implementation.
//!
//! Implements the SPAKE2 protocol per RFC 9382 with pluggable ciphersuites.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod ciphersuite;
pub mod encoding;
pub mod error;
pub mod party_a;
pub mod party_b;
pub mod transcript;

pub use ciphersuite::Spake2Ciphersuite;
pub use error::Spake2Error;
pub use party_a::{PartyA, PartyAState};
pub use party_b::{PartyB, PartyBState};
pub use transcript::Spake2Output;
