//! CPace initiator state machine.

use alloc::vec::Vec;
use group::{Group, GroupEncoding};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::CpaceCiphersuite;
use crate::error::CpaceError;
use crate::generator::calculate_generator;
use crate::transcript::{derive_isk, derive_session_id, CpaceMode};
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
    #[zeroize(skip)]
    scalar: <C::Group as Group>::Scalar,
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
        let g = calculate_generator::<C>(password, ci, sid);
        let ya = C::sample_scalar(rng);
        let ya_point = g * ya;
        let ya_bytes = ya_point.to_bytes().as_ref().to_vec();

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
        let repr = <C::Group as GroupEncoding>::Repr::default();
        let mut repr = repr;
        let repr_slice = repr.as_mut();
        if responder_share.len() != repr_slice.len() {
            return Err(CpaceError::InvalidPoint);
        }
        repr_slice.copy_from_slice(responder_share);

        let yb: C::Group =
            Option::from(C::Group::from_bytes(&repr)).ok_or(CpaceError::InvalidPoint)?;

        // Check Yb != identity
        if bool::from(yb.is_identity()) {
            return Err(CpaceError::IdentityPoint);
        }

        // K = ya * Yb
        let k = yb * self.scalar;

        // Check K != identity
        if bool::from(k.is_identity()) {
            return Err(CpaceError::IdentityPoint);
        }

        let k_bytes = k.to_bytes().as_ref().to_vec();

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
