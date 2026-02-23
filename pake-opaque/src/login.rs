//! Login (AKE) protocol for OPAQUE (RFC 9807 Section 6).

use alloc::vec;
use alloc::vec::Vec;

use crate::ciphersuite::OpaqueCiphersuite;
use crate::envelope;
use crate::key_derivation::{
    build_preamble, derive_keys, derive_randomized_password, triple_dh_ikm,
};
use crate::messages::{CredentialResponse, RegistrationRecord, KE1, KE2, KE3};
use crate::oprf::{self, OprfClientState};
use crate::server_setup::ServerSetup;
use crate::OpaqueError;
use pake_core::crypto::{DhGroup, Hash, Kdf, Mac};
use pake_core::SharedSecret;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Client-side login state held between start and finish.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientLoginState<C: OpaqueCiphersuite> {
    // SECURITY: voprf::OprfClient does not implement Zeroize, so the OPRF
    // blinding scalar is not explicitly zeroed on drop. See OprfClientState docs.
    #[zeroize(skip)]
    oprf_state: OprfClientState<C>,
    password: Vec<u8>,
    client_eph_sk: Vec<u8>,
    ke1_bytes: Vec<u8>,
    #[zeroize(skip)]
    _marker: core::marker::PhantomData<C>,
}

/// Client-side login operations.
pub struct ClientLogin<C: OpaqueCiphersuite>(core::marker::PhantomData<C>);

impl<C: OpaqueCiphersuite> ClientLogin<C> {
    /// Start login by blinding the password and generating an ephemeral keypair.
    ///
    /// Returns `(KE1, state)`.
    pub fn start(
        password: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(KE1, ClientLoginState<C>), OpaqueError> {
        let (oprf_state, blinded_message) = oprf::oprf_client_blind::<C>(password, rng)?;

        let mut client_nonce = vec![0u8; C::NN];
        rng.fill_bytes(&mut client_nonce);

        let mut client_eph_seed = Zeroizing::new(vec![0u8; C::NSEED]);
        rng.fill_bytes(&mut client_eph_seed);
        let (client_eph_sk, client_eph_pk) = C::Dh::derive_keypair(&client_eph_seed)?;

        let ke1 = KE1 {
            blinded_message,
            client_nonce,
            client_keyshare: client_eph_pk,
        };

        let ke1_bytes = ke1.serialize();

        let state = ClientLoginState {
            oprf_state,
            password: password.to_vec(),
            client_eph_sk,
            ke1_bytes,
            _marker: core::marker::PhantomData,
        };

        Ok((ke1, state))
    }

    /// Start login with pre-determined randomness (for test vectors).
    ///
    /// # Security
    ///
    /// Using non-random values completely breaks security.
    /// This method is gated behind the `test-utils` feature.
    #[cfg(feature = "test-utils")]
    pub fn start_with_blind_and_nonce_and_seed(
        password: &[u8],
        blind_rng: &mut impl CryptoRngCore,
        client_nonce: &[u8],
        client_keyshare_seed: &[u8],
    ) -> Result<(KE1, ClientLoginState<C>), OpaqueError> {
        let (oprf_state, blinded_message) = oprf::oprf_client_blind::<C>(password, blind_rng)?;

        let (client_eph_sk, client_eph_pk) = C::Dh::derive_keypair(client_keyshare_seed)?;

        let ke1 = KE1 {
            blinded_message,
            client_nonce: client_nonce.to_vec(),
            client_keyshare: client_eph_pk,
        };

        let ke1_bytes = ke1.serialize();

        let state = ClientLoginState {
            oprf_state,
            password: password.to_vec(),
            client_eph_sk,
            ke1_bytes,
            _marker: core::marker::PhantomData,
        };

        Ok((ke1, state))
    }
}

impl<C: OpaqueCiphersuite> ClientLoginState<C> {
    /// Finish login after receiving KE2 from the server.
    ///
    /// Returns `(KE3, session_key, export_key)`.
    pub fn finish(
        self,
        ke2: &KE2,
        context: &[u8],
        server_identity: &[u8],
        client_identity: &[u8],
    ) -> Result<(KE3, SharedSecret, Zeroizing<Vec<u8>>), OpaqueError> {
        // 1. Finalize OPRF
        let oprf_output = Zeroizing::new(oprf::oprf_client_finalize::<C>(
            &self.oprf_state,
            &self.password,
            &ke2.evaluated_message,
        )?);

        // 2. Derive randomized password
        let randomized_pwd = Zeroizing::new(derive_randomized_password::<C>(&oprf_output)?);

        // 3. Unmask credential response
        let masking_key = Zeroizing::new(C::Kdf::expand(&randomized_pwd, b"MaskingKey", C::NH)?);
        let cred_resp_size = CredentialResponse::size::<C>();

        // XOR-decrypt: credential_response_pad = Expand(masking_key, concat(masking_nonce, "CredentialResponsePad"), cred_resp_size)
        let mut pad_info = Vec::with_capacity(ke2.masking_nonce.len() + 21);
        pad_info.extend_from_slice(&ke2.masking_nonce);
        pad_info.extend_from_slice(b"CredentialResponsePad");
        let pad = Zeroizing::new(C::Kdf::expand(&masking_key, &pad_info, cred_resp_size)?);

        let mut cred_resp_bytes = Zeroizing::new(vec![0u8; cred_resp_size]);
        for i in 0..cred_resp_size {
            cred_resp_bytes[i] = ke2.masked_response[i] ^ pad[i];
        }

        let cred_resp = CredentialResponse::deserialize::<C>(&cred_resp_bytes)?;

        // 4. Recover envelope
        let (client_private_key_raw, _client_public_key, export_key) = envelope::recover::<C>(
            &randomized_pwd,
            &cred_resp.server_public_key,
            server_identity,
            client_identity,
            &cred_resp.envelope,
        )?;
        let client_private_key = Zeroizing::new(client_private_key_raw);

        // Resolve identities for preamble
        let client_id_for_preamble: &[u8] = if client_identity.is_empty() {
            &_client_public_key
        } else {
            client_identity
        };
        let server_id_for_preamble: &[u8] = if server_identity.is_empty() {
            &cred_resp.server_public_key
        } else {
            server_identity
        };

        // 5. TripleDH
        let ikm = Zeroizing::new(triple_dh_ikm::<C>(
            &self.client_eph_sk,
            &ke2.server_keyshare,
            &self.client_eph_sk,
            &cred_resp.server_public_key,
            &client_private_key,
            &ke2.server_keyshare,
        )?);

        // 6. Build preamble and derive keys
        let inner_ke2 = ke2.inner_ke2();
        let preamble = build_preamble(
            context,
            client_id_for_preamble,
            &self.ke1_bytes,
            server_id_for_preamble,
            &inner_ke2,
        )?;

        let (km2, km3, session_key) = derive_keys::<C>(&ikm, &preamble)?;
        let km2 = Zeroizing::new(km2);
        let km3 = Zeroizing::new(km3);

        // 7. Verify server MAC (compute once, verify via constant-time comparison)
        let preamble_hash = C::Hash::digest(&preamble);
        let expected_server_mac = C::Mac::mac(&km2, &preamble_hash)?;

        use subtle::ConstantTimeEq;
        if !bool::from(expected_server_mac.ct_eq(&ke2.server_mac)) {
            return Err(OpaqueError::ServerAuthenticationError);
        }

        // 8. Compute client MAC: MAC(km3, Hash(preamble || server_mac))
        let mut transcript2_input = Zeroizing::new(Vec::with_capacity(preamble.len() + expected_server_mac.len()));
        transcript2_input.extend_from_slice(&preamble);
        transcript2_input.extend_from_slice(&expected_server_mac);
        let transcript2_hash = C::Hash::digest(&transcript2_input);
        let client_mac = C::Mac::mac(&km3, &transcript2_hash)?;

        let ke3 = KE3 { client_mac };

        Ok((ke3, SharedSecret::new(session_key), export_key))
    }
}

/// Server-side login state held between start and finish.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ServerLoginState {
    expected_client_mac: Vec<u8>,
    session_key: Vec<u8>,
}

/// Server-side login operations.
pub struct ServerLogin<C: OpaqueCiphersuite>(core::marker::PhantomData<C>);

impl<C: OpaqueCiphersuite> ServerLogin<C> {
    /// Process KE1 and generate KE2.
    ///
    /// Returns `(KE2, ServerLoginState)`.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        setup: &ServerSetup<C>,
        record: &RegistrationRecord,
        ke1: &KE1,
        credential_id: &[u8],
        context: &[u8],
        server_identity: &[u8],
        client_identity: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(KE2, ServerLoginState), OpaqueError> {
        let mut server_nonce = vec![0u8; C::NN];
        rng.fill_bytes(&mut server_nonce);

        let mut server_eph_seed = Zeroizing::new(vec![0u8; C::NSEED]);
        rng.fill_bytes(&mut server_eph_seed);

        let mut masking_nonce = vec![0u8; C::NN];
        rng.fill_bytes(&mut masking_nonce);

        Self::start_inner(
            setup,
            record,
            ke1,
            credential_id,
            context,
            server_identity,
            client_identity,
            &server_nonce,
            &server_eph_seed,
            &masking_nonce,
        )
    }

    /// Start login with pre-determined randomness (for test vectors).
    ///
    /// # Security
    ///
    /// Using non-random values completely breaks security.
    /// This method is gated behind the `test-utils` feature.
    #[cfg(feature = "test-utils")]
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_nonce_and_seed(
        setup: &ServerSetup<C>,
        record: &RegistrationRecord,
        ke1: &KE1,
        credential_id: &[u8],
        context: &[u8],
        server_identity: &[u8],
        client_identity: &[u8],
        server_nonce: &[u8],
        server_keyshare_seed: &[u8],
        masking_nonce: &[u8],
    ) -> Result<(KE2, ServerLoginState), OpaqueError> {
        Self::start_inner(
            setup,
            record,
            ke1,
            credential_id,
            context,
            server_identity,
            client_identity,
            server_nonce,
            server_keyshare_seed,
            masking_nonce,
        )
    }

    /// Generate a fake KE2 for a non-existent credential identifier.
    ///
    /// Prevents user enumeration by making the server's response
    /// indistinguishable from a real login (RFC 9807 Section 6.3.2.2).
    /// The client will always fail at envelope recovery.
    ///
    /// `server_identity` and `client_identity` should match those used in
    /// [`start`](Self::start) so that the preamble structure is identical.
    /// Pass empty slices to use the default identity (the public key).
    #[allow(clippy::too_many_arguments)]
    pub fn start_fake(
        setup: &ServerSetup<C>,
        ke1: &KE1,
        credential_id: &[u8],
        context: &[u8],
        server_identity: &[u8],
        client_identity: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<KE2, OpaqueError> {
        // 1. OPRF evaluate (deterministic from oprf_seed + credential_id)
        let oprf_key = Zeroizing::new(oprf::derive_oprf_key::<C>(
            setup.oprf_seed(),
            credential_id,
        )?);
        let evaluated_message = oprf::oprf_server_evaluate::<C>(&oprf_key, &ke1.blinded_message)?;

        // 2. Random masking nonce
        let mut masking_nonce = vec![0u8; C::NN];
        rng.fill_bytes(&mut masking_nonce);

        // 3. Random masked response (indistinguishable from real XOR-encrypted data)
        let cred_resp_size = CredentialResponse::size::<C>();
        let mut masked_response = vec![0u8; cred_resp_size];
        rng.fill_bytes(&mut masked_response);

        // 4. Server ephemeral keypair
        let mut server_nonce = vec![0u8; C::NN];
        rng.fill_bytes(&mut server_nonce);
        let mut server_eph_seed = Zeroizing::new(vec![0u8; C::NSEED]);
        rng.fill_bytes(&mut server_eph_seed);
        let (server_eph_sk_raw, server_eph_pk) = C::Dh::derive_keypair(&server_eph_seed)?;
        let server_eph_sk = Zeroizing::new(server_eph_sk_raw);

        // 5. Generate a fake client public key (random valid point)
        let (_, fake_client_pk) = C::Dh::generate_keypair(rng)?;

        // 6. Resolve identities for preamble (same logic as start_inner)
        let client_id_for_preamble: &[u8] = if client_identity.is_empty() {
            &fake_client_pk
        } else {
            client_identity
        };
        let server_id_for_preamble: &[u8] = if server_identity.is_empty() {
            setup.public_key()
        } else {
            server_identity
        };

        // 7. TripleDH from server perspective (using fake client key for dh3)
        let ikm = Zeroizing::new(triple_dh_ikm::<C>(
            &server_eph_sk,
            &ke1.client_keyshare,
            setup.private_key(),
            &ke1.client_keyshare,
            &server_eph_sk,
            &fake_client_pk,
        )?);

        // 8. Build preamble and derive keys
        let inner_ke2_msg = KE2 {
            evaluated_message: evaluated_message.clone(),
            masking_nonce: masking_nonce.clone(),
            masked_response: masked_response.clone(),
            server_nonce: server_nonce.clone(),
            server_keyshare: server_eph_pk.clone(),
            server_mac: vec![],
        };

        let inner_ke2 = inner_ke2_msg.inner_ke2();
        let ke1_bytes = ke1.serialize();
        let preamble = build_preamble(
            context,
            client_id_for_preamble,
            &ke1_bytes,
            server_id_for_preamble,
            &inner_ke2,
        )?;

        let (km2, _, _) = derive_keys::<C>(&ikm, &preamble)?;
        let km2 = Zeroizing::new(km2);

        // 9. Compute server MAC
        let preamble_hash = C::Hash::digest(&preamble);
        let server_mac = C::Mac::mac(&km2, &preamble_hash)?;

        Ok(KE2 {
            evaluated_message,
            masking_nonce,
            masked_response,
            server_nonce,
            server_keyshare: server_eph_pk,
            server_mac,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn start_inner(
        setup: &ServerSetup<C>,
        record: &RegistrationRecord,
        ke1: &KE1,
        credential_id: &[u8],
        context: &[u8],
        server_identity: &[u8],
        client_identity: &[u8],
        server_nonce: &[u8],
        server_keyshare_seed: &[u8],
        masking_nonce: &[u8],
    ) -> Result<(KE2, ServerLoginState), OpaqueError> {
        // 1. OPRF evaluate
        let oprf_key = Zeroizing::new(oprf::derive_oprf_key::<C>(
            setup.oprf_seed(),
            credential_id,
        )?);
        let evaluated_message = oprf::oprf_server_evaluate::<C>(&oprf_key, &ke1.blinded_message)?;

        let masking_nonce = masking_nonce.to_vec();

        // 3. Mask credential response
        let cred_resp = CredentialResponse {
            server_public_key: setup.public_key().to_vec(),
            envelope: record.envelope.clone(),
        };
        let cred_resp_bytes = cred_resp.serialize();
        let cred_resp_size = cred_resp_bytes.len();

        let mut pad_info = Vec::with_capacity(masking_nonce.len() + 21);
        pad_info.extend_from_slice(&masking_nonce);
        pad_info.extend_from_slice(b"CredentialResponsePad");
        let pad = Zeroizing::new(C::Kdf::expand(&record.masking_key, &pad_info, cred_resp_size)?);

        let mut masked_response = vec![0u8; cred_resp_size];
        for i in 0..cred_resp_size {
            masked_response[i] = cred_resp_bytes[i] ^ pad[i];
        }

        // 4. Server ephemeral keypair
        let (server_eph_sk_raw, server_eph_pk) = C::Dh::derive_keypair(server_keyshare_seed)?;
        let server_eph_sk = Zeroizing::new(server_eph_sk_raw);

        // 5. Resolve identities
        let client_id_for_preamble: &[u8] = if client_identity.is_empty() {
            &record.client_public_key
        } else {
            client_identity
        };
        let server_id_for_preamble: &[u8] = if server_identity.is_empty() {
            setup.public_key()
        } else {
            server_identity
        };

        // 6. TripleDH from server perspective
        let ikm = Zeroizing::new(triple_dh_ikm::<C>(
            &server_eph_sk,
            &ke1.client_keyshare,
            setup.private_key(),
            &ke1.client_keyshare,
            &server_eph_sk,
            &record.client_public_key,
        )?);

        // 7. Build preamble (without server_mac — that's what inner_ke2 is)
        let inner_ke2_msg = KE2 {
            evaluated_message: evaluated_message.clone(),
            masking_nonce: masking_nonce.clone(),
            masked_response: masked_response.clone(),
            server_nonce: server_nonce.to_vec(),
            server_keyshare: server_eph_pk.clone(),
            server_mac: vec![], // placeholder, not used in inner_ke2()
        };

        let inner_ke2 = inner_ke2_msg.inner_ke2();
        let ke1_bytes = ke1.serialize();
        let preamble = build_preamble(
            context,
            client_id_for_preamble,
            &ke1_bytes,
            server_id_for_preamble,
            &inner_ke2,
        )?;

        let (km2, km3, session_key) = derive_keys::<C>(&ikm, &preamble)?;
        let km2 = Zeroizing::new(km2);
        let km3 = Zeroizing::new(km3);

        // 8. Compute server MAC
        let preamble_hash = C::Hash::digest(&preamble);
        let server_mac = C::Mac::mac(&km2, &preamble_hash)?;

        // 9. Compute expected client MAC: MAC(km3, Hash(preamble || server_mac))
        let mut transcript2_input = Zeroizing::new(Vec::with_capacity(preamble.len() + server_mac.len()));
        transcript2_input.extend_from_slice(&preamble);
        transcript2_input.extend_from_slice(&server_mac);
        let transcript2_hash = C::Hash::digest(&transcript2_input);
        let expected_client_mac = C::Mac::mac(&km3, &transcript2_hash)?;

        let ke2 = KE2 {
            evaluated_message,
            masking_nonce,
            masked_response,
            server_nonce: server_nonce.to_vec(),
            server_keyshare: server_eph_pk,
            server_mac,
        };

        let state = ServerLoginState {
            expected_client_mac,
            session_key,
        };

        Ok((ke2, state))
    }
}

impl ServerLoginState {
    /// Verify the client's MAC and return the session key.
    pub fn finish(mut self, ke3: &KE3) -> Result<SharedSecret, OpaqueError> {
        use subtle::ConstantTimeEq;
        if self.expected_client_mac.ct_eq(&ke3.client_mac).into() {
            let session_key = core::mem::take(&mut self.session_key);
            Ok(SharedSecret::new(session_key))
        } else {
            Err(OpaqueError::ClientAuthenticationError)
        }
    }
}
