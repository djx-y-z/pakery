//! Ristretto255 OPRF implementation.

use alloc::vec::Vec;
use pake_core::crypto::oprf::{Oprf, OprfClientState};
use pake_core::PakeError;
use rand_core::CryptoRngCore;

/// Client state for the Ristretto255 OPRF.
pub struct Ristretto255OprfClientState {
    state: voprf::OprfClient<voprf::Ristretto255>,
}

impl OprfClientState for Ristretto255OprfClientState {
    fn finalize(&self, password: &[u8], evaluated_bytes: &[u8]) -> Result<Vec<u8>, PakeError> {
        let evaluated =
            voprf::EvaluationElement::<voprf::Ristretto255>::deserialize(evaluated_bytes)
                .map_err(|_| PakeError::InvalidInput("invalid OPRF evaluation element"))?;
        let output = self
            .state
            .finalize(password, &evaluated)
            .map_err(|_| PakeError::ProtocolError("OPRF finalize failed"))?;
        Ok(output.to_vec())
    }
}

/// Ristretto255 OPRF.
pub struct Ristretto255Oprf;

impl Oprf for Ristretto255Oprf {
    type ClientState = Ristretto255OprfClientState;

    fn client_blind(
        password: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ClientState, Vec<u8>), PakeError> {
        let result = voprf::OprfClient::<voprf::Ristretto255>::blind(password, rng)
            .map_err(|_| PakeError::ProtocolError("OPRF blind failed"))?;
        let blinded_bytes = result.message.serialize().to_vec();
        Ok((
            Ristretto255OprfClientState {
                state: result.state,
            },
            blinded_bytes,
        ))
    }

    fn server_evaluate(oprf_key: &[u8], blinded_bytes: &[u8]) -> Result<Vec<u8>, PakeError> {
        let server = voprf::OprfServer::<voprf::Ristretto255>::new_with_key(oprf_key)
            .map_err(|_| PakeError::InvalidInput("invalid OPRF key"))?;
        let blinded = voprf::BlindedElement::<voprf::Ristretto255>::deserialize(blinded_bytes)
            .map_err(|_| PakeError::InvalidInput("invalid blinded element"))?;
        let evaluated = server.blind_evaluate(&blinded);
        Ok(evaluated.serialize().to_vec())
    }

    fn derive_key(seed: &[u8], info: &[u8]) -> Result<Vec<u8>, PakeError> {
        let server = voprf::OprfServer::<voprf::Ristretto255>::new_from_seed(seed, info)
            .map_err(|_| PakeError::ProtocolError("OPRF DeriveKeyPair failed"))?;
        Ok(server.serialize().to_vec())
    }
}
