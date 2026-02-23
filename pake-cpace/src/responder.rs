//! CPace responder (one-shot).

use alloc::vec::Vec;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::ciphersuite::CpaceCiphersuite;
use crate::error::CpaceError;
use crate::generator::calculate_generator;
use crate::initiator::CpaceOutput;
use crate::transcript::{derive_isk, derive_session_id, CpaceMode};
use pake_core::crypto::CpaceGroup;

/// CPace responder: processes the initiator's message and produces the response in one step.
pub struct CpaceResponder<C: CpaceCiphersuite>(core::marker::PhantomData<C>);

impl<C: CpaceCiphersuite> CpaceResponder<C> {
    /// Respond to an initiator's CPace message.
    ///
    /// Returns `(Yb_bytes, output)` where `Yb_bytes` is sent back to the initiator.
    #[allow(clippy::too_many_arguments)]
    pub fn respond(
        initiator_share: &[u8],
        password: &[u8],
        ci: &[u8],
        sid: &[u8],
        ad_initiator: &[u8],
        ad_responder: &[u8],
        mode: CpaceMode,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, CpaceOutput), CpaceError> {
        // Decode Ya
        let ya = C::Group::from_bytes(initiator_share).map_err(|_| CpaceError::InvalidPoint)?;

        // Check Ya != identity
        if ya.is_identity() {
            return Err(CpaceError::IdentityPoint);
        }

        // Calculate generator
        let g = calculate_generator::<C>(password, ci, sid)?;

        // Sample yb, compute Yb = yb * g
        let mut yb_scalar = C::Group::random_scalar(rng);
        let yb_point = g.scalar_mul(&yb_scalar);
        let yb_bytes = yb_point.to_bytes();

        // K = yb * Ya
        let k = ya.scalar_mul(&yb_scalar);
        yb_scalar.zeroize();

        // Check K != identity
        if k.is_identity() {
            return Err(CpaceError::IdentityPoint);
        }

        let k_bytes = k.to_bytes();

        // Derive ISK
        let isk = derive_isk::<C>(
            sid,
            &k_bytes,
            initiator_share,
            ad_initiator,
            &yb_bytes,
            ad_responder,
            mode,
        );

        // Derive session ID
        let session_id =
            derive_session_id::<C>(initiator_share, ad_initiator, &yb_bytes, ad_responder, mode);

        Ok((yb_bytes, CpaceOutput { isk, session_id }))
    }
}
