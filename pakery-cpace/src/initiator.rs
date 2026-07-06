//! CPace initiator state machine.

use alloc::vec::Vec;
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ciphersuite::CpaceCiphersuite;
use crate::error::CpaceError;
use crate::generator::calculate_generator;
use crate::transcript::{derive_isk, derive_session_id, CpaceMode};
use pakery_core::crypto::CpaceGroup;
use pakery_core::SharedSecret;

/// Output of a completed CPace protocol run.
///
/// This type intentionally does NOT derive `ZeroizeOnDrop`: `isk`
/// already self-zeroizes via [`SharedSecret`]'s impl, and `session_id`
/// is public bytes (not secret material — it's typically exchanged or
/// logged). Pattern destructure is permitted.
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
        rng: &mut impl CryptoRng,
    ) -> Result<(Vec<u8>, InitiatorState<C>), CpaceError> {
        // ctgrind: the password is the protocol's secret input.
        pakery_core::ct::mark_secret(password);
        let g = calculate_generator::<C>(password, ci, sid)?;
        let ya = C::Group::random_scalar(rng);
        let ya_point = g.scalar_mul(&ya);
        let ya_bytes = ya_point.to_bytes();
        // ctgrind: Ya is the wire key share — public by protocol design.
        pakery_core::ct::declassify(&ya_bytes);

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
        // ctgrind: the raw DH result K is secret key material (P-256 group
        // ops launder taint through the scalar parse, so re-mark at the byte
        // boundary).
        pakery_core::ct::mark_secret(&k_bytes);

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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use pakery_core::PakeError;

    /// Minimal mock group: only the associated `Scalar` type matters for
    /// constructing an `InitiatorState`; no group operation is ever called.
    #[derive(Clone, PartialEq)]
    struct MockPoint;

    impl CpaceGroup for MockPoint {
        type Scalar = [u8; 32];

        fn scalar_mul(&self, _scalar: &Self::Scalar) -> Self {
            unimplemented!()
        }
        fn is_identity(&self) -> bool {
            unimplemented!()
        }
        fn to_bytes(&self) -> Vec<u8> {
            unimplemented!()
        }
        fn from_bytes(_bytes: &[u8]) -> Result<Self, PakeError> {
            unimplemented!()
        }
        fn from_uniform_bytes(_bytes: &[u8]) -> Result<Self, PakeError> {
            unimplemented!()
        }
        fn random_scalar(_rng: &mut impl CryptoRng) -> Self::Scalar {
            unimplemented!()
        }
        fn add(&self, _other: &Self) -> Self {
            unimplemented!()
        }
        fn negate(&self) -> Self {
            unimplemented!()
        }
        fn basepoint_mul(_scalar: &Self::Scalar) -> Self {
            unimplemented!()
        }
        fn scalar_from_wide_bytes(_bytes: &[u8]) -> Result<Self::Scalar, PakeError> {
            unimplemented!()
        }
        fn scalar_to_bytes(_scalar: &Self::Scalar) -> Vec<u8> {
            unimplemented!()
        }
    }

    #[derive(Clone)]
    struct MockHash;

    impl pakery_core::crypto::Hash for MockHash {
        const OUTPUT_SIZE: usize = 64;

        fn new() -> Self {
            unimplemented!()
        }
        fn update(&mut self, _data: &[u8]) {
            unimplemented!()
        }
        fn finalize(self) -> Vec<u8> {
            unimplemented!()
        }
    }

    struct MockSuite;

    impl CpaceCiphersuite for MockSuite {
        type Group = MockPoint;
        type Hash = MockHash;
        const DSI: &'static [u8] = b"CPaceMock";
        const HASH_BLOCK_SIZE: usize = 128;
        const FIELD_SIZE_BYTES: usize = 32;
    }

    /// Calling `.zeroize()` on a live value must clear every secret field
    /// (roadmap item 7: catches a future field added without zeroization).
    #[test]
    fn zeroize_clears_all_secret_fields() {
        let mut state = InitiatorState::<MockSuite> {
            scalar: [0xAA; 32],
            ya_bytes: vec![0xBB; 32],
            ad_a: vec![0xCC; 8],
            sid: vec![0xDD; 16],
            _marker: core::marker::PhantomData,
        };
        state.zeroize();
        assert_eq!(state.scalar, [0u8; 32]);
        assert!(state.ya_bytes.is_empty());
        assert!(state.ad_a.is_empty());
        assert!(state.sid.is_empty());
    }
}
