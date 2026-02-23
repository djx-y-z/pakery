//! SPAKE2 Party B (responder) state machine.

use alloc::vec::Vec;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use pake_core::crypto::CpaceGroup;

use crate::ciphersuite::Spake2Ciphersuite;
use crate::encoding::build_transcript;
use crate::error::Spake2Error;
use crate::transcript::{derive_key_schedule, Spake2Output};

/// State held by Party B between sending pB and receiving pA.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PartyBState<C: Spake2Ciphersuite> {
    y: <C::Group as CpaceGroup>::Scalar,
    w: <C::Group as CpaceGroup>::Scalar,
    pb_bytes: Vec<u8>,
    identity_a: Vec<u8>,
    identity_b: Vec<u8>,
    aad: Vec<u8>,
    #[zeroize(skip)]
    _marker: core::marker::PhantomData<C>,
}

/// SPAKE2 Party B: generates the response and processes Party A's message.
pub struct PartyB<C: Spake2Ciphersuite>(core::marker::PhantomData<C>);

impl<C: Spake2Ciphersuite> PartyB<C> {
    /// Start the SPAKE2 protocol as Party B.
    ///
    /// `w` is the password scalar (same as Party A's).
    ///
    /// Returns `(pB_bytes, state)` where `pB_bytes` is sent to Party A.
    pub fn start(
        w: &<C::Group as CpaceGroup>::Scalar,
        identity_a: &[u8],
        identity_b: &[u8],
        aad: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, PartyBState<C>), Spake2Error> {
        let y = C::Group::random_scalar(rng);
        Self::start_inner(w, &y, identity_a, identity_b, aad)
    }

    /// Start with a deterministic scalar (for testing).
    pub fn start_with_scalar(
        w: &<C::Group as CpaceGroup>::Scalar,
        y: &<C::Group as CpaceGroup>::Scalar,
        identity_a: &[u8],
        identity_b: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, PartyBState<C>), Spake2Error> {
        Self::start_inner(w, y, identity_a, identity_b, aad)
    }

    fn start_inner(
        w: &<C::Group as CpaceGroup>::Scalar,
        y: &<C::Group as CpaceGroup>::Scalar,
        identity_a: &[u8],
        identity_b: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, PartyBState<C>), Spake2Error> {
        // Decode N from ciphersuite constants
        let n = C::Group::from_bytes(C::N_BYTES)?;

        // pB = y*G + w*N
        let y_g = C::Group::basepoint_mul(y);
        let w_n = n.scalar_mul(w);
        let pb = y_g.add(&w_n);

        let pb_bytes = pb.to_bytes();

        let state = PartyBState {
            y: y.clone(),
            w: w.clone(),
            pb_bytes: pb_bytes.clone(),
            identity_a: identity_a.to_vec(),
            identity_b: identity_b.to_vec(),
            aad: aad.to_vec(),
            _marker: core::marker::PhantomData,
        };

        Ok((pb_bytes, state))
    }
}

impl<C: Spake2Ciphersuite> PartyBState<C> {
    /// Finish the SPAKE2 protocol by processing Party A's message.
    ///
    /// Returns the protocol output containing session key and confirmation MACs.
    pub fn finish(self, pa_bytes: &[u8]) -> Result<Spake2Output, Spake2Error> {
        // Decode pA
        let pa = C::Group::from_bytes(pa_bytes)?;

        // Decode M
        let m = C::Group::from_bytes(C::M_BYTES)?;

        // K = y * (pA - w*M)
        let w_m = m.scalar_mul(&self.w);
        let pa_minus_wm = pa.add(&w_m.negate());
        let k = pa_minus_wm.scalar_mul(&self.y);

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
            pa_bytes,
            &self.pb_bytes,
            &k_bytes,
            &w_bytes,
        );

        // Derive key schedule (Party B)
        derive_key_schedule::<C>(&tt, &self.aad, false)
    }
}
