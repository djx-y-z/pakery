//! SPAKE2+ Verifier (server) state machine.
//!
//! The Verifier stores `(w0, L)` where `L = w1*G`. It does not know
//! the password or `w1` directly.

use alloc::vec::Vec;
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use pakery_core::crypto::CpaceGroup;
use pakery_core::SharedSecret;

use crate::ciphersuite::Spake2PlusCiphersuite;
use crate::encoding::build_transcript;
use crate::error::Spake2PlusError;
use crate::transcript::{derive_key_schedule, Spake2PlusOutput};

/// State held by the Verifier between sending (shareV, confirmV) and receiving confirmP.
pub struct VerifierState {
    expected_confirm_p: Vec<u8>,
    session_key: SharedSecret,
}

impl Zeroize for VerifierState {
    fn zeroize(&mut self) {
        self.expected_confirm_p.zeroize();
        // SharedSecret also zeroizes on its own drop; clearing it here keeps
        // `zeroize()` exhaustive over every secret field.
        self.session_key.zeroize();
    }
}

impl Drop for VerifierState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl VerifierState {
    /// Finish the SPAKE2+ protocol by verifying the Prover's confirmation MAC.
    pub fn finish(mut self, confirm_p: &[u8]) -> Result<Spake2PlusOutput, Spake2PlusError> {
        // ctgrind: the verification outcome is a public accept/reject
        // decision; the comparison itself stays constant-time.
        if !pakery_core::ct::declassify_choice(self.expected_confirm_p.ct_eq(confirm_p)) {
            return Err(Spake2PlusError::ConfirmationFailed);
        }

        // Move session_key out; the placeholder empty secret is dropped
        // (and zeroized) when `self` drops.
        let session_key =
            core::mem::replace(&mut self.session_key, SharedSecret::new(alloc::vec![]));
        Ok(Spake2PlusOutput { session_key })
    }
}

/// SPAKE2+ Verifier: processes the Prover's first message and generates the response.
pub struct Verifier<C: Spake2PlusCiphersuite>(core::marker::PhantomData<C>);

impl<C: Spake2PlusCiphersuite> Verifier<C> {
    /// Start the SPAKE2+ protocol as the Verifier.
    ///
    /// `w0` is the password-derived scalar stored during registration.
    /// `l_bytes` is the verifier point `L = w1*G` stored during registration.
    ///
    /// Returns `(shareV_bytes, confirmV, state)` where `shareV_bytes` and `confirmV`
    /// are sent to the Prover.
    pub fn start(
        share_p_bytes: &[u8],
        w0: &<C::Group as CpaceGroup>::Scalar,
        l_bytes: &[u8],
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>, VerifierState), Spake2PlusError> {
        let y = C::Group::random_scalar(rng);
        Self::start_inner(
            share_p_bytes,
            w0,
            l_bytes,
            &y,
            context,
            id_prover,
            id_verifier,
        )
    }

    /// Start with a deterministic scalar (for testing).
    ///
    /// # Security
    ///
    /// Using a non-random scalar completely breaks security.
    /// This method is gated behind the `test-utils` feature and must
    /// only be used for RFC test vector validation.
    #[cfg(feature = "test-utils")]
    pub fn start_with_scalar(
        share_p_bytes: &[u8],
        w0: &<C::Group as CpaceGroup>::Scalar,
        l_bytes: &[u8],
        y: &<C::Group as CpaceGroup>::Scalar,
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, VerifierState), Spake2PlusError> {
        Self::start_inner(
            share_p_bytes,
            w0,
            l_bytes,
            y,
            context,
            id_prover,
            id_verifier,
        )
    }

    fn start_inner(
        share_p_bytes: &[u8],
        w0: &<C::Group as CpaceGroup>::Scalar,
        l_bytes: &[u8],
        y: &<C::Group as CpaceGroup>::Scalar,
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, VerifierState), Spake2PlusError> {
        // Decode shareP and reject identity (defense-in-depth)
        let share_p = C::Group::from_bytes(share_p_bytes)?;
        if share_p.is_identity() {
            return Err(Spake2PlusError::IdentityPoint);
        }

        // Decode M from ciphersuite constants
        let m = C::Group::from_bytes(C::M_BYTES)?;

        // Decode L (verifier point)
        let l = C::Group::from_bytes(l_bytes)?;

        // Decode N from ciphersuite constants
        let n = C::Group::from_bytes(C::N_BYTES)?;

        // shareV = y*G + w0*N
        let y_g = C::Group::basepoint_mul(y);
        let w0_n = n.scalar_mul(w0);
        let share_v = y_g.add(&w0_n);

        let share_v_bytes = share_v.to_bytes();
        // ctgrind: shareV is the wire key share — public by protocol design.
        pakery_core::ct::declassify(&share_v_bytes);

        // tmp = shareP - w0*M (= x*G)
        let w0_m = m.scalar_mul(w0);
        let tmp = share_p.add(&w0_m.negate());

        // Z = y * tmp (= y*x*G)
        let z = tmp.scalar_mul(y);

        // V = y * L (= y*w1*G)
        let v = l.scalar_mul(y);

        // Check Z != identity, V != identity
        if z.is_identity() {
            return Err(Spake2PlusError::IdentityPoint);
        }
        if v.is_identity() {
            return Err(Spake2PlusError::IdentityPoint);
        }

        let z_bytes = Zeroizing::new(z.to_bytes());
        let v_bytes = Zeroizing::new(v.to_bytes());
        let w0_bytes = Zeroizing::new(C::Group::scalar_to_bytes(w0));
        // ctgrind: Z, V, and w0 are secret transcript inputs (P-256 group
        // ops launder taint through the scalar parse, so re-mark at the
        // byte boundary).
        pakery_core::ct::mark_secret(&z_bytes);
        pakery_core::ct::mark_secret(&v_bytes);
        pakery_core::ct::mark_secret(&w0_bytes);

        // Use canonical group element encoding for M and N in the transcript
        // (same encoding as all other group elements, e.g. uncompressed for P-256).
        let m_bytes = m.to_bytes();
        let n_bytes = n.to_bytes();

        // Build transcript TT (10 fields)
        let tt = build_transcript(
            context,
            id_prover,
            id_verifier,
            &m_bytes,
            &n_bytes,
            share_p_bytes,
            &share_v_bytes,
            &z_bytes,
            &v_bytes,
            &w0_bytes,
        );

        // Derive key schedule
        let mut ks = derive_key_schedule::<C>(&tt, share_p_bytes, &share_v_bytes)?;

        let state = VerifierState {
            expected_confirm_p: core::mem::take(&mut ks.confirm_p),
            session_key: core::mem::replace(&mut ks.session_key, SharedSecret::new(Vec::new())),
        };

        let confirm_v = core::mem::take(&mut ks.confirm_v);
        // ctgrind: confirmV goes on the wire — public once sent. The
        // expected confirmP stays secret until compared.
        pakery_core::ct::declassify(&confirm_v);
        Ok((share_v_bytes, confirm_v, state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The manual `Zeroize` impl (called from `Drop`) must clear every
    /// secret field (roadmap item 7: catches a future field added without
    /// zeroization).
    #[test]
    fn zeroize_clears_all_secret_fields() {
        let mut state = VerifierState {
            expected_confirm_p: alloc::vec![0xAA; 64],
            session_key: SharedSecret::new(alloc::vec![0xBB; 32]),
        };
        state.zeroize();
        assert!(state.expected_confirm_p.is_empty());
        assert!(state.session_key.as_bytes().is_empty());
    }
}
