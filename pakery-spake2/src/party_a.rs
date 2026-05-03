//! SPAKE2 Party A (initiator) state machine.

use alloc::vec::Vec;
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use pakery_core::crypto::CpaceGroup;

use crate::ciphersuite::Spake2Ciphersuite;
use crate::encoding::build_transcript;
use crate::error::Spake2Error;
use crate::transcript::{derive_key_schedule, Spake2Output};

/// State held by Party A between sending pA and receiving pB.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PartyAState<C: Spake2Ciphersuite> {
    x: <C::Group as CpaceGroup>::Scalar,
    w: <C::Group as CpaceGroup>::Scalar,
    pa_bytes: Vec<u8>,
    identity_a: Vec<u8>,
    identity_b: Vec<u8>,
    aad: Vec<u8>,
    #[zeroize(skip)]
    _marker: core::marker::PhantomData<C>,
}

/// SPAKE2 Party A: generates the first message and processes the response.
pub struct PartyA<C: Spake2Ciphersuite>(core::marker::PhantomData<C>);

impl<C: Spake2Ciphersuite> PartyA<C> {
    /// Start the SPAKE2 protocol as Party A.
    ///
    /// `w` is the password scalar (derived from the password via hashing to a wide byte string
    /// then reducing mod the group order).
    ///
    /// Returns `(pA_bytes, state)` where `pA_bytes` is sent to Party B.
    pub fn start(
        w: &<C::Group as CpaceGroup>::Scalar,
        identity_a: &[u8],
        identity_b: &[u8],
        aad: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<(Vec<u8>, PartyAState<C>), Spake2Error> {
        let x = C::Group::random_scalar(rng);
        Self::start_inner(w.clone(), x, identity_a, identity_b, aad)
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
        w: &<C::Group as CpaceGroup>::Scalar,
        x: &<C::Group as CpaceGroup>::Scalar,
        identity_a: &[u8],
        identity_b: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, PartyAState<C>), Spake2Error> {
        Self::start_inner(w.clone(), x.clone(), identity_a, identity_b, aad)
    }

    fn start_inner(
        w: <C::Group as CpaceGroup>::Scalar,
        x: <C::Group as CpaceGroup>::Scalar,
        identity_a: &[u8],
        identity_b: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, PartyAState<C>), Spake2Error> {
        // Decode M from ciphersuite constants
        let m = C::Group::from_bytes(C::M_BYTES)?;

        // pA = x*G + w*M
        let x_g = C::Group::basepoint_mul(&x);
        let w_m = m.scalar_mul(&w);
        let pa = x_g.add(&w_m);

        let pa_bytes = pa.to_bytes();

        let state = PartyAState {
            x,
            w,
            pa_bytes: pa_bytes.clone(),
            identity_a: identity_a.to_vec(),
            identity_b: identity_b.to_vec(),
            aad: aad.to_vec(),
            _marker: core::marker::PhantomData,
        };

        Ok((pa_bytes, state))
    }
}

impl<C: Spake2Ciphersuite> PartyAState<C> {
    /// Finish the SPAKE2 protocol by processing Party B's message.
    ///
    /// Returns the protocol output containing session key and confirmation MACs.
    pub fn finish(self, pb_bytes: &[u8]) -> Result<Spake2Output, Spake2Error> {
        // Decode pB and reject identity (defense-in-depth)
        let pb = C::Group::from_bytes(pb_bytes)?;
        if pb.is_identity() {
            return Err(Spake2Error::IdentityPoint);
        }

        // Decode N
        let n = C::Group::from_bytes(C::N_BYTES)?;

        // K = x * (pB - w*N)
        let w_n = n.scalar_mul(&self.w);
        let pb_minus_wn = pb.add(&w_n.negate());
        let k = pb_minus_wn.scalar_mul(&self.x);

        // Check K != identity
        if k.is_identity() {
            return Err(Spake2Error::IdentityPoint);
        }

        let k_bytes = Zeroizing::new(k.to_bytes());
        let w_bytes = Zeroizing::new(C::Group::scalar_to_bytes(&self.w));

        // Build transcript
        let tt = build_transcript(
            &self.identity_a,
            &self.identity_b,
            &self.pa_bytes,
            pb_bytes,
            &k_bytes,
            &w_bytes,
        );

        // Derive key schedule (Party A)
        derive_key_schedule::<C>(&tt, &self.aad, true)
    }
}
