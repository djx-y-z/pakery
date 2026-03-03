//! OPAQUE augmented PAKE protocol (RFC 9807).
//!
//! OPAQUE allows a client to authenticate to a server using a password
//! without the server ever learning the password. The server stores only
//! a registration record derived from the password.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

extern crate alloc;

pub mod ciphersuite;
pub mod envelope;
pub mod error;
pub mod key_derivation;
pub mod login;
pub mod messages;
pub mod oprf;
pub mod registration;
pub mod server_setup;

pub use ciphersuite::OpaqueCiphersuite;
pub use error::OpaqueError;
pub use login::{ClientLogin, ClientLoginState, ServerLogin, ServerLoginState};
pub use messages::{
    CredentialResponse, Envelope, RegistrationRecord, RegistrationRequest, RegistrationResponse,
    KE1, KE2, KE3,
};
pub use registration::{ClientRegistration, ClientRegistrationState, ServerRegistration};
pub use server_setup::ServerSetup;
