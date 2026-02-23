//! Registration protocol for OPAQUE (RFC 9807 Section 5).

use crate::ciphersuite::OpaqueCiphersuite;
use crate::envelope;
use crate::key_derivation::derive_randomized_password;
use crate::messages::{RegistrationRecord, RegistrationRequest, RegistrationResponse};
use crate::oprf::{self, OprfClientState};
use crate::server_setup::ServerSetup;
use crate::OpaqueError;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Client-side registration state held between start and finish.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientRegistrationState<C: OpaqueCiphersuite> {
    #[zeroize(skip)]
    oprf_state: OprfClientState<C>,
    password: Vec<u8>,
}

/// Client-side registration operations.
pub struct ClientRegistration<C: OpaqueCiphersuite>(core::marker::PhantomData<C>);

impl<C: OpaqueCiphersuite> ClientRegistration<C> {
    /// Start registration by blinding the password.
    ///
    /// Returns `(RegistrationRequest, state)`.
    pub fn start(
        password: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(RegistrationRequest, ClientRegistrationState<C>), OpaqueError> {
        let (oprf_state, blinded_message) = oprf::oprf_client_blind::<C>(password, rng)?;

        let request = RegistrationRequest { blinded_message };
        let state = ClientRegistrationState {
            oprf_state,
            password: password.to_vec(),
        };

        Ok((request, state))
    }
}

impl<C: OpaqueCiphersuite> ClientRegistrationState<C> {
    /// Finish registration after receiving the server's response.
    ///
    /// Returns `(RegistrationRecord, export_key)`.
    pub fn finish(
        self,
        response: &RegistrationResponse,
        server_identity: &[u8],
        client_identity: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(RegistrationRecord, Zeroizing<Vec<u8>>), OpaqueError> {
        // Finalize OPRF
        let oprf_output = Zeroizing::new(oprf::oprf_client_finalize::<C>(
            &self.oprf_state,
            &self.password,
            &response.evaluated_message,
        )?);

        // Derive randomized password
        let randomized_pwd = Zeroizing::new(derive_randomized_password::<C>(&oprf_output)?);

        // Generate envelope nonce
        let mut nonce = vec![0u8; C::NN];
        rng.fill_bytes(&mut nonce);

        // Store envelope
        let (env, client_public_key, masking_key, export_key) = envelope::store::<C>(
            &randomized_pwd,
            &response.server_public_key,
            server_identity,
            client_identity,
            &nonce,
        )?;

        let record = RegistrationRecord {
            client_public_key,
            masking_key,
            envelope: env,
        };

        Ok((record, export_key))
    }

    /// Finish registration with a pre-determined nonce (for test vectors).
    pub fn finish_with_nonce(
        self,
        response: &RegistrationResponse,
        server_identity: &[u8],
        client_identity: &[u8],
        nonce: &[u8],
    ) -> Result<(RegistrationRecord, Zeroizing<Vec<u8>>), OpaqueError> {
        let oprf_output = Zeroizing::new(oprf::oprf_client_finalize::<C>(
            &self.oprf_state,
            &self.password,
            &response.evaluated_message,
        )?);
        let randomized_pwd = Zeroizing::new(derive_randomized_password::<C>(&oprf_output)?);

        let (env, client_public_key, masking_key, export_key) = envelope::store::<C>(
            &randomized_pwd,
            &response.server_public_key,
            server_identity,
            client_identity,
            nonce,
        )?;

        let record = RegistrationRecord {
            client_public_key,
            masking_key,
            envelope: env,
        };

        Ok((record, export_key))
    }
}

/// Server-side registration (stateless).
pub struct ServerRegistration<C: OpaqueCiphersuite>(core::marker::PhantomData<C>);

impl<C: OpaqueCiphersuite> ServerRegistration<C> {
    /// Process a registration request and return a response.
    pub fn start(
        setup: &ServerSetup<C>,
        request: &RegistrationRequest,
        credential_id: &[u8],
    ) -> Result<RegistrationResponse, OpaqueError> {
        // Derive OPRF key from seed
        let oprf_key = oprf::derive_oprf_key::<C>(setup.oprf_seed(), credential_id)?;

        // Evaluate OPRF
        let evaluated_message =
            oprf::oprf_server_evaluate::<C>(&oprf_key, &request.blinded_message)?;

        Ok(RegistrationResponse {
            evaluated_message,
            server_public_key: setup.public_key().to_vec(),
        })
    }
}
