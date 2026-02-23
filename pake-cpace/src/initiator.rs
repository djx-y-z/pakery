//! CPace initiator state machine.

use alloc::vec::Vec;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ciphersuite::CpaceCiphersuite;
use crate::error::CpaceError;
use crate::generator::calculate_generator;
use crate::transcript::{derive_isk, derive_session_id, CpaceMode};
use pake_core::crypto::CpaceGroup;
use pake_core::SharedSecret;

/// Output of a completed CPace protocol run.
pub struct CpaceOutput {
    /// The intermediate session key.
    pub isk: SharedSecret,
    /// Optional session ID output.
    pub session_id: Vec<u8>,
}

/// State held by the initiator between sending its share and receiving the responder's share.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InitiatorState<C: CpaceCiphersuite> {
    scalar: <C::Group as CpaceGroup>::Scalar,
    ya_bytes: Vec<u8>,
    ad_a: Vec<u8>,
    sid: Vec<u8>,
    #[zeroize(skip)]
    _marker: core::marker::PhantomData<C>,
}

/// CPace initiator: generates the first message and processes the response.
pub struct CpaceInitiator<C: CpaceCiphersuite>(core::marker::PhantomData<C>);

impl<C: CpaceCiphersuite> CpaceInitiator<C> {
    /// Start the CPace protocol as initiator.
    ///
    /// Returns `(Ya_bytes, state)` where `Ya_bytes` is sent to the responder.
    pub fn start(
        password: &[u8],
        ci: &[u8],
        sid: &[u8],
        ad_initiator: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, InitiatorState<C>), CpaceError> {
        let g = calculate_generator::<C>(password, ci, sid)?;
        let ya = C::Group::random_scalar(rng);
        let ya_point = g.scalar_mul(&ya);
        let ya_bytes = ya_point.to_bytes();

        let state = InitiatorState {
            scalar: ya,
            ya_bytes: ya_bytes.clone(),
            ad_a: ad_initiator.to_vec(),
            sid: sid.to_vec(),
            _marker: core::marker::PhantomData,
        };

        Ok((ya_bytes, state))
    }
}

impl<C: CpaceCiphersuite> InitiatorState<C> {
    /// Finish the CPace protocol by processing the responder's share.
    ///
    /// Returns the protocol output containing the ISK and session ID.
    pub fn finish(
        self,
        responder_share: &[u8],
        ad_responder: &[u8],
        mode: CpaceMode,
    ) -> Result<CpaceOutput, CpaceError> {
        // Decode Yb
        let yb = C::Group::from_bytes(responder_share).map_err(|_| CpaceError::InvalidPoint)?;

        // Check Yb != identity
        if yb.is_identity() {
            return Err(CpaceError::IdentityPoint);
        }

        // K = ya * Yb
        let k = yb.scalar_mul(&self.scalar);

        // Check K != identity
        if k.is_identity() {
            return Err(CpaceError::IdentityPoint);
        }

        let k_bytes = Zeroizing::new(k.to_bytes());

        // Derive ISK
        let isk = derive_isk::<C>(
            &self.sid,
            &k_bytes,
            &self.ya_bytes,
            &self.ad_a,
            responder_share,
            ad_responder,
            mode,
        );

        // Derive session ID
        let session_id = derive_session_id::<C>(
            &self.ya_bytes,
            &self.ad_a,
            responder_share,
            ad_responder,
            mode,
        );

        Ok(CpaceOutput { isk, session_id })
    }
}
