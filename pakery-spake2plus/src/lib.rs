//! SPAKE2+ augmented PAKE protocol implementation.
//!
//! Implements the SPAKE2+ protocol per RFC 9383 with pluggable ciphersuites.
//! Unlike balanced SPAKE2, the server (Verifier) stores only a verifier
//! `(w0, L)` derived from the password — not the password itself.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod ciphersuite;
pub mod encoding;
pub mod error;
pub mod prover;
pub mod registration;
pub mod transcript;
pub mod verifier;

pub use ciphersuite::Spake2PlusCiphersuite;
pub use error::Spake2PlusError;
pub use prover::{Prover, ProverOutput, ProverState};
pub use registration::compute_verifier;
pub use transcript::Spake2PlusOutput;
pub use verifier::{Verifier, VerifierState};
