//! SPAKE2+ Prover (client) state machine.
//!
//! The Prover knows the password and derives `(w0, w1)` from it.

use alloc::vec::Vec;
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use pake_core::crypto::CpaceGroup;
use pake_core::SharedSecret;

use crate::ciphersuite::Spake2PlusCiphersuite;
use crate::encoding::build_transcript;
use crate::error::Spake2PlusError;
use crate::transcript::derive_key_schedule;

/// State held by the Prover between sending shareP and receiving (shareV, confirmV).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProverState<C: Spake2PlusCiphersuite> {
    x: <C::Group as CpaceGroup>::Scalar,
    w0: <C::Group as CpaceGroup>::Scalar,
    w1: <C::Group as CpaceGroup>::Scalar,
    share_p_bytes: Vec<u8>,
    context: Vec<u8>,
    id_prover: Vec<u8>,
    id_verifier: Vec<u8>,
    #[zeroize(skip)]
    _marker: core::marker::PhantomData<C>,
}

/// Output returned by the Prover after verifying confirmV.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProverOutput {
    /// The shared session key.
    #[zeroize(skip)]
    pub session_key: SharedSecret,
    /// The Prover's confirmation MAC to send to the Verifier.
    pub confirm_p: Vec<u8>,
}

/// SPAKE2+ Prover: generates the first message and processes the Verifier's response.
pub struct Prover<C: Spake2PlusCiphersuite>(core::marker::PhantomData<C>);

impl<C: Spake2PlusCiphersuite> Prover<C> {
    /// Start the SPAKE2+ protocol as the Prover.
    ///
    /// `w0` and `w1` are the password-derived scalars. The caller is responsible
    /// for password stretching.
    ///
    /// Returns `(shareP_bytes, state)` where `shareP_bytes` is sent to the Verifier.
    pub fn start(
        w0: &<C::Group as CpaceGroup>::Scalar,
        w1: &<C::Group as CpaceGroup>::Scalar,
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, ProverState<C>), Spake2PlusError> {
        let x = C::Group::random_scalar(rng);
        Self::start_inner(w0, w1, &x, context, id_prover, id_verifier)
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
        w0: &<C::Group as CpaceGroup>::Scalar,
        w1: &<C::Group as CpaceGroup>::Scalar,
        x: &<C::Group as CpaceGroup>::Scalar,
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
    ) -> Result<(Vec<u8>, ProverState<C>), Spake2PlusError> {
        Self::start_inner(w0, w1, x, context, id_prover, id_verifier)
    }

    fn start_inner(
        w0: &<C::Group as CpaceGroup>::Scalar,
        w1: &<C::Group as CpaceGroup>::Scalar,
        x: &<C::Group as CpaceGroup>::Scalar,
        context: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
    ) -> Result<(Vec<u8>, ProverState<C>), Spake2PlusError> {
        // Decode M from ciphersuite constants
        let m = C::Group::from_bytes(C::M_BYTES)?;

        // shareP = x*G + w0*M
        let x_g = C::Group::basepoint_mul(x);
        let w0_m = m.scalar_mul(w0);
        let share_p = x_g.add(&w0_m);

        let share_p_bytes = share_p.to_bytes();

        let state = ProverState {
            x: x.clone(),
            w0: w0.clone(),
            w1: w1.clone(),
            share_p_bytes: share_p_bytes.clone(),
            context: context.to_vec(),
            id_prover: id_prover.to_vec(),
            id_verifier: id_verifier.to_vec(),
            _marker: core::marker::PhantomData,
        };

        Ok((share_p_bytes, state))
    }
}

impl<C: Spake2PlusCiphersuite> ProverState<C> {
    /// Finish the SPAKE2+ protocol by processing the Verifier's response.
    ///
    /// The Prover receives `(shareV_bytes, confirm_v)` from the Verifier,
    /// verifies `confirm_v`, and returns `ProverOutput` containing the session
    /// key and `confirm_p` to send back.
    pub fn finish(
        self,
        share_v_bytes: &[u8],
        confirm_v: &[u8],
    ) -> Result<ProverOutput, Spake2PlusError> {
        // Decode shareV
        let share_v = C::Group::from_bytes(share_v_bytes)?;

        // Decode N from ciphersuite constants
        let n = C::Group::from_bytes(C::N_BYTES)?;

        // tmp = shareV - w0*N (= y*G)
        let w0_n = n.scalar_mul(&self.w0);
        let tmp = share_v.add(&w0_n.negate());

        // Z = x * tmp (= x*y*G, since cofactor h=1 for ristretto255)
        let z = tmp.scalar_mul(&self.x);

        // V = w1 * tmp (= w1*y*G)
        let v = tmp.scalar_mul(&self.w1);

        // Check Z != identity, V != identity
        if z.is_identity() {
            return Err(Spake2PlusError::IdentityPoint);
        }
        if v.is_identity() {
            return Err(Spake2PlusError::IdentityPoint);
        }

        let z_bytes = Zeroizing::new(z.to_bytes());
        let v_bytes = Zeroizing::new(v.to_bytes());
        let w0_bytes = Zeroizing::new(C::Group::scalar_to_bytes(&self.w0));

        // Decode M and N to get canonical group element encoding for transcript.
        // This ensures M/N use the same encoding as other group elements (e.g.
        // uncompressed SEC1 for P-256), regardless of how they are stored in the
        // ciphersuite constants.
        let m = C::Group::from_bytes(C::M_BYTES)?;
        let n_point = C::Group::from_bytes(C::N_BYTES)?;
        let m_bytes = m.to_bytes();
        let n_bytes = n_point.to_bytes();

        // Build transcript TT (10 fields)
        let tt = build_transcript(
            &self.context,
            &self.id_prover,
            &self.id_verifier,
            &m_bytes,
            &n_bytes,
            &self.share_p_bytes,
            share_v_bytes,
            &z_bytes,
            &v_bytes,
            &w0_bytes,
        );

        // Derive key schedule
        let ks = derive_key_schedule::<C>(&tt, &self.share_p_bytes, share_v_bytes)?;

        // Verify confirmV: MAC(K_confirmV, shareP)
        if !bool::from(ks.confirm_v.ct_eq(confirm_v)) {
            return Err(Spake2PlusError::ConfirmationFailed);
        }

        Ok(ProverOutput {
            session_key: ks.session_key,
            confirm_p: ks.confirm_p,
        })
    }
}
