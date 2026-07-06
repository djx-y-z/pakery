//! Registration helper for computing the SPAKE2+ verifier.
//!
//! During registration, the Prover derives `(w0, w1)` from the password
//! (via password stretching), then computes `L = w1*G` and sends `(w0, L)`
//! to the Verifier for storage.

use alloc::vec::Vec;
use pakery_core::crypto::CpaceGroup;

use crate::ciphersuite::Spake2PlusCiphersuite;

/// Compute the verifier point `L = w1*G` from the scalar `w1`.
///
/// The password stretching (e.g. PBKDF/Argon2 to derive w0, w1) is the
/// caller's responsibility.
pub fn compute_verifier<C: Spake2PlusCiphersuite>(
    w1: &<C::Group as CpaceGroup>::Scalar,
) -> Vec<u8> {
    let l_bytes = C::Group::basepoint_mul(w1).to_bytes();
    // ctgrind: L is transmitted to the Verifier at registration — treated as
    // public wire data for constant-time purposes (its secrecy is a storage
    // concern, not a timing one).
    pakery_core::ct::declassify(&l_bytes);
    l_bytes
}
