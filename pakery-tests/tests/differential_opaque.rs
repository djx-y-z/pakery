//! Differential testing of pakery-opaque against opaque-ke v4 (RFC 9807).
//!
//! Differential testing (see SECURITY_TESTING.md): opaque-ke v4 implements RFC 9807
//! final and is the one same-spec peer implementation available for a
//! cross-implementation oracle. Both implementations are driven on identical
//! deterministic inputs and every protocol artifact is compared byte-for-byte:
//! registration request/response/record, KE1/KE2/KE3, export_key, session_key.
//!
//! # How inputs are forced equal
//!
//! opaque-ke has no public deterministic-input constructors (its
//! `deterministic_blind_unchecked` path is `cfg(test)`-internal), so inputs
//! are equalized as follows:
//!
//! - **Server keys / OPRF seed:** opaque-ke's `ServerSetup` is constructed via
//!   `ServerSetup::deserialize(oprf_seed || server_sk || dummy_pk)`; ours via
//!   the `test-utils` constructor `ServerSetup::new_with_key`.
//! - **Blinds:** opaque-ke samples the OPRF blind from its RNG inside
//!   `ClientRegistration::start` / `ClientLogin::start`. We feed it a
//!   chunk-per-call RNG and then *extract* the actual blind scalar from the
//!   serialized client state (its first `Nok` bytes), and replay that exact
//!   canonical scalar into our implementation through the RNG. Both groups
//!   accept canonical scalar bytes verbatim (ristretto255: 64-byte wide
//!   reduction of `scalar || zeros`; P-256: 32-byte rejection sampling), the
//!   same trick the RFC 9807 vector tests use.
//! - **Nonces and ephemeral-keypair seeds:** supplied positionally through the
//!   chunk-per-call RNG, matching opaque-ke's internal consumption order
//!   (verified against opaque-ke 4.0.1 sources, see `ChunkCallRng`); our side
//!   takes them directly via `test-utils` methods. Both sides derive ephemeral
//!   keypairs from seeds with RFC 9807 `DeriveDiffieHellmanKeyPair`, so equal
//!   seeds give equal keyshares.
//!
//! # What is compared byte-for-byte, and what is not
//!
//! Byte-compared: all six protocol messages, the registration record,
//! export_key and session_key (client and server, both implementations —
//! a four-way equality).
//!
//! Not byte-compared: nothing in the honest flow. The only opaque-ke behaviour
//! we deliberately do not differential-test is the fake-credentials path
//! (`ServerLogin` with `password_file: None` vs our `start_fake`): both sample
//! *fresh* randomness for the fake record by design, ours generates a random
//! fake client public key while opaque-ke uses the long-term `dummy_pk` from
//! `ServerSetup`, so their outputs are incomparable by construction.
//!
//! KSF: both sides use the identity KSF (`pakery_core::crypto::IdentityKsf` /
//! `opaque_ke::ksf::Identity`) so that comparison runs are fast and
//! KSF-parameter-independent.

#![cfg(feature = "differential")]

use opaque_ke::rand::{CryptoRng as KeCryptoRng, Error as KeRngError, RngCore as KeRngCore};
use opaque_ke::{
    ClientLoginFinishParameters as KeClientLoginFinishParameters,
    ClientRegistrationFinishParameters as KeClientRegistrationFinishParameters,
    CredentialFinalization as KeCredentialFinalization, CredentialRequest as KeCredentialRequest,
    CredentialResponse as KeCredentialResponse, Identifiers as KeIdentifiers,
    RegistrationRequest as KeRegistrationRequest, RegistrationResponse as KeRegistrationResponse,
    RegistrationUpload as KeRegistrationUpload, ServerLoginParameters as KeServerLoginParameters,
    ServerRegistration as KeServerRegistration,
};
use pakery_core::crypto::dh::DhGroup;
use pakery_core::crypto::IdentityKsf;
use pakery_crypto::{
    HkdfSha256, HkdfSha512, HmacSha256, HmacSha512, P256Dh, P256Oprf, Ristretto255Dh,
    Ristretto255Oprf, Sha256Hash, Sha512Hash,
};
use pakery_opaque::{
    ClientLogin, ClientRegistration, OpaqueCiphersuite, ServerLogin, ServerRegistration,
    ServerSetup,
};
use proptest::prelude::*;

// ==========================================================================
// Ciphersuites — ours and opaque-ke's, matched pairwise
// ==========================================================================

/// OPAQUE-3DH over ristretto255 + SHA-512, identity KSF (ours).
struct OurRistretto255;

impl OpaqueCiphersuite for OurRistretto255 {
    type Hash = Sha512Hash;
    type Kdf = HkdfSha512;
    type Mac = HmacSha512;
    type Dh = Ristretto255Dh;
    type Oprf = Ristretto255Oprf;
    type Ksf = IdentityKsf;

    const NN: usize = 32;
    const NSEED: usize = 32;
    const NOE: usize = 32;
    const NOK: usize = 32;
    const NM: usize = 64;
    const NH: usize = 64;
    const NPK: usize = 32;
    const NSK: usize = 32;
    const NX: usize = 64;
}

/// OPAQUE-3DH over ristretto255 + SHA-512, identity KSF (opaque-ke).
struct KeRistretto255;

impl opaque_ke::CipherSuite for KeRistretto255 {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

/// OPAQUE-3DH over P-256 + SHA-256, identity KSF (ours).
struct OurP256;

impl OpaqueCiphersuite for OurP256 {
    type Hash = Sha256Hash;
    type Kdf = HkdfSha256;
    type Mac = HmacSha256;
    type Dh = P256Dh;
    type Oprf = P256Oprf;
    type Ksf = IdentityKsf;

    const NN: usize = 32;
    const NSEED: usize = 32;
    const NOE: usize = 33;
    const NOK: usize = 32;
    const NM: usize = 32;
    const NH: usize = 32;
    const NPK: usize = 33;
    const NSK: usize = 32;
    const NX: usize = 32;
}

/// OPAQUE-3DH over P-256 + SHA-256, identity KSF (opaque-ke).
struct KeP256;

impl opaque_ke::CipherSuite for KeP256 {
    type OprfCs = p256::NistP256;
    type KeyExchange = opaque_ke::TripleDh<p256::NistP256, sha2::Sha256>;
    type Ksf = opaque_ke::ksf::Identity;
}

// ==========================================================================
// Deterministic RNGs
// ==========================================================================

/// Chunk-per-call RNG for opaque-ke (rand_core 0.6 traits via its re-export).
///
/// Every `fill_bytes` call consumes exactly one pre-planned chunk and the
/// chunk length must match the requested length exactly. This encodes
/// opaque-ke 4.0.1's internal RNG consumption order as a hard contract:
///
/// - `ClientRegistration::start`: blind material (Nok wide: 64 for
///   ristretto255 via `Scalar::random`, 32 for P-256 via rejection sampling)
/// - `ClientRegistration::finish`: envelope nonce (32)
/// - `ClientLogin::start`: blind material, client keyshare seed (32),
///   client nonce (32)
/// - `ServerLogin::start`: dummy-record masking key (Nh), masking nonce (32),
///   server keyshare seed (32), server nonce (32)
///
/// If a future opaque-ke version changes its consumption order or sizes, these
/// panics fire and the tests fail loudly instead of comparing garbage.
struct ChunkCallRng {
    chunks: Vec<Vec<u8>>,
    next: usize,
}

impl ChunkCallRng {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self { chunks, next: 0 }
    }
}

impl KeRngCore for ChunkCallRng {
    fn next_u32(&mut self) -> u32 {
        panic!("opaque-ke is expected to use fill_bytes only");
    }

    fn next_u64(&mut self) -> u64 {
        panic!("opaque-ke is expected to use fill_bytes only");
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let chunk = self
            .chunks
            .get(self.next)
            .unwrap_or_else(|| panic!("unexpected extra RNG call #{}", self.next));
        assert_eq!(
            chunk.len(),
            dest.len(),
            "RNG call #{} requested {} bytes, planned chunk holds {} — \
             opaque-ke's RNG consumption pattern changed",
            self.next,
            dest.len(),
            chunk.len()
        );
        dest.copy_from_slice(chunk);
        self.next += 1;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), KeRngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl KeCryptoRng for ChunkCallRng {}

impl Drop for ChunkCallRng {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert_eq!(
                self.next,
                self.chunks.len(),
                "planned RNG chunks left unconsumed — \
                 opaque-ke's RNG consumption pattern changed"
            );
        }
    }
}

/// Byte-stream RNG for our implementation (rand_core 0.9), zero-padded once
/// the stream is exhausted. Feeding a canonical scalar reproduces that exact
/// scalar in both groups: ristretto255 reads 64 bytes and wide-reduces
/// `scalar || zeros` back to `scalar`; P-256 reads the 32 canonical big-endian
/// bytes directly (same mechanism as the RFC 9807 vector tests).
struct ByteStreamRng {
    data: Vec<u8>,
    offset: usize,
}

impl ByteStreamRng {
    fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            offset: 0,
        }
    }
}

impl rand_core::RngCore for ByteStreamRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = self.data.get(self.offset).copied().unwrap_or(0);
            self.offset += 1;
        }
    }
}

impl rand_core::CryptoRng for ByteStreamRng {}

// ==========================================================================
// Differential driver
// ==========================================================================

/// The full set of deterministic inputs for one differential run.
#[derive(Debug, Clone)]
struct DiffInputs {
    password: Vec<u8>,
    credential_id: Vec<u8>,
    client_identity: Option<Vec<u8>>,
    server_identity: Option<Vec<u8>>,
    context: Vec<u8>,
    /// Nh bytes (64 for SHA-512, 32 for SHA-256).
    oprf_seed: Vec<u8>,
    /// Raw canonical server private key (32 bytes, group scalar).
    server_private_key: Vec<u8>,
    /// Matching server public key (Npk bytes).
    server_public_key: Vec<u8>,
    /// Any valid public key; only feeds opaque-ke's fake-credentials machinery.
    dummy_public_key: Vec<u8>,
    /// Raw RNG material for the registration blind (64 bytes ristretto255,
    /// 32 bytes P-256; P-256 material must be a valid nonzero scalar).
    blind_registration_material: Vec<u8>,
    envelope_nonce: Vec<u8>,
    /// Raw RNG material for the login blind (same shape as registration).
    blind_login_material: Vec<u8>,
    client_keyshare_seed: Vec<u8>,
    client_nonce: Vec<u8>,
    masking_nonce: Vec<u8>,
    server_keyshare_seed: Vec<u8>,
    server_nonce: Vec<u8>,
}

macro_rules! differential_driver {
    ($fn_name:ident, $ours:ty, $theirs:ty) => {
        /// Run registration + login through both implementations on identical
        /// inputs and byte-compare every protocol artifact.
        fn $fn_name(inputs: &DiffInputs) {
            let client_id = inputs.client_identity.as_deref().unwrap_or(b"");
            let server_id = inputs.server_identity.as_deref().unwrap_or(b"");
            let ke_identifiers = KeIdentifiers {
                client: inputs.client_identity.as_deref(),
                server: inputs.server_identity.as_deref(),
            };

            // --- Server setup -------------------------------------------------
            let their_setup = opaque_ke::ServerSetup::<$theirs>::deserialize(
                &[
                    inputs.oprf_seed.as_slice(),
                    &inputs.server_private_key,
                    &inputs.dummy_public_key,
                ]
                .concat(),
            )
            .expect("opaque-ke rejected the server setup bytes");
            assert_eq!(
                their_setup.keypair().public().serialize().as_slice(),
                inputs.server_public_key.as_slice(),
                "server public key derivation differs"
            );
            let our_setup = ServerSetup::<$ours>::new_with_key(
                inputs.oprf_seed.clone(),
                inputs.server_private_key.clone(),
                inputs.server_public_key.clone(),
            );

            // --- Registration: client start -----------------------------------
            let their_reg_start = opaque_ke::ClientRegistration::<$theirs>::start(
                &mut ChunkCallRng::new(vec![inputs.blind_registration_material.clone()]),
                &inputs.password,
            )
            .expect("opaque-ke registration start failed");
            // The first Nok bytes of the serialized client state are the blind.
            let blind_registration = their_reg_start.state.serialize()[..<$ours>::NOK].to_vec();

            let (our_reg_request, our_reg_state) = ClientRegistration::<$ours>::start(
                &inputs.password,
                &mut ByteStreamRng::new(&blind_registration),
            )
            .expect("our registration start failed");

            let their_reg_request = their_reg_start.message.serialize();
            assert_eq!(
                our_reg_request.serialize(),
                their_reg_request.as_slice(),
                "RegistrationRequest bytes differ"
            );

            // --- Registration: server response --------------------------------
            let their_reg_response = KeServerRegistration::<$theirs>::start(
                &their_setup,
                KeRegistrationRequest::deserialize(&their_reg_request)
                    .expect("opaque-ke rejected its own RegistrationRequest"),
                &inputs.credential_id,
            )
            .expect("opaque-ke registration response failed")
            .message
            .serialize();

            let our_reg_response = ServerRegistration::<$ours>::start(
                &our_setup,
                &our_reg_request,
                &inputs.credential_id,
            )
            .expect("our registration response failed");
            assert_eq!(
                our_reg_response.serialize(),
                their_reg_response.as_slice(),
                "RegistrationResponse bytes differ"
            );

            // --- Registration: client finish ----------------------------------
            let their_reg_finish = their_reg_start
                .state
                .finish(
                    &mut ChunkCallRng::new(vec![inputs.envelope_nonce.clone()]),
                    &inputs.password,
                    KeRegistrationResponse::deserialize(&their_reg_response)
                        .expect("opaque-ke rejected its own RegistrationResponse"),
                    KeClientRegistrationFinishParameters::new(ke_identifiers, None),
                )
                .expect("opaque-ke registration finish failed");
            let their_record = their_reg_finish.message.serialize();

            let (our_record, our_reg_export_key) = our_reg_state
                .finish_with_nonce(
                    &our_reg_response,
                    server_id,
                    client_id,
                    &inputs.envelope_nonce,
                )
                .expect("our registration finish failed");
            assert_eq!(
                our_record.serialize(),
                their_record.as_slice(),
                "RegistrationRecord bytes differ"
            );
            assert_eq!(
                our_reg_export_key.as_slice(),
                their_reg_finish.export_key.as_slice(),
                "registration export_key differs"
            );

            // --- Login: client KE1 ---------------------------------------------
            let their_login_start = opaque_ke::ClientLogin::<$theirs>::start(
                &mut ChunkCallRng::new(vec![
                    inputs.blind_login_material.clone(),
                    inputs.client_keyshare_seed.clone(),
                    inputs.client_nonce.clone(),
                ]),
                &inputs.password,
            )
            .expect("opaque-ke login start failed");
            let blind_login = their_login_start.state.serialize()[..<$ours>::NOK].to_vec();
            let their_ke1 = their_login_start.message.serialize();

            let (our_ke1, our_login_state) =
                ClientLogin::<$ours>::start_with_blind_and_nonce_and_seed(
                    &inputs.password,
                    &mut ByteStreamRng::new(&blind_login),
                    &inputs.client_nonce,
                    &inputs.client_keyshare_seed,
                )
                .expect("our login start failed");
            assert_eq!(
                our_ke1.serialize(),
                their_ke1.as_slice(),
                "KE1 bytes differ"
            );

            // --- Login: server KE2 ---------------------------------------------
            let their_password_file = KeServerRegistration::finish(
                KeRegistrationUpload::<$theirs>::deserialize(&their_record)
                    .expect("opaque-ke rejected its own RegistrationRecord"),
            );
            let their_ke2 = opaque_ke::ServerLogin::<$theirs>::start(
                // Consumption order: dummy-record masking key (Nh), masking
                // nonce, server keyshare seed, server nonce. The dummy record
                // is always sampled (enumeration-resistance), then discarded
                // because a real password file is supplied.
                &mut ChunkCallRng::new(vec![
                    vec![0xd0; <$ours>::NH],
                    inputs.masking_nonce.clone(),
                    inputs.server_keyshare_seed.clone(),
                    inputs.server_nonce.clone(),
                ]),
                &their_setup,
                Some(their_password_file),
                KeCredentialRequest::deserialize(&their_ke1)
                    .expect("opaque-ke rejected its own KE1"),
                &inputs.credential_id,
                KeServerLoginParameters {
                    context: Some(&inputs.context),
                    identifiers: ke_identifiers,
                },
            )
            .expect("opaque-ke server login start failed");

            let (our_ke2, our_server_state) = ServerLogin::<$ours>::start_with_nonce_and_seed(
                &our_setup,
                &our_record,
                &our_ke1,
                &inputs.credential_id,
                &inputs.context,
                server_id,
                client_id,
                &inputs.server_nonce,
                &inputs.server_keyshare_seed,
                &inputs.masking_nonce,
            )
            .expect("our server login start failed");
            assert_eq!(
                our_ke2.serialize(),
                their_ke2.message.serialize().as_slice(),
                "KE2 bytes differ"
            );

            // --- Login: client KE3 + keys ---------------------------------------
            let their_login_finish = their_login_start
                .state
                .finish(
                    // TripleDh consumes no RNG here; an empty plan asserts that.
                    &mut ChunkCallRng::new(vec![]),
                    &inputs.password,
                    KeCredentialResponse::deserialize(&their_ke2.message.serialize())
                        .expect("opaque-ke rejected its own KE2"),
                    KeClientLoginFinishParameters::new(Some(&inputs.context), ke_identifiers, None),
                )
                .expect("opaque-ke client login finish failed");
            let their_ke3 = their_login_finish.message.serialize();

            let (our_ke3, our_client_session_key, our_login_export_key) = our_login_state
                .finish(&our_ke2, &inputs.context, server_id, client_id)
                .expect("our client login finish failed");
            assert_eq!(
                our_ke3.serialize(),
                their_ke3.as_slice(),
                "KE3 bytes differ"
            );
            assert_eq!(
                our_login_export_key.as_slice(),
                their_login_finish.export_key.as_slice(),
                "login export_key differs"
            );
            assert_eq!(
                our_reg_export_key.as_slice(),
                our_login_export_key.as_slice(),
                "our registration/login export keys differ"
            );

            // --- Login: server finish + four-way session-key equality -----------
            let their_server_session_key = their_ke2
                .state
                .finish(
                    KeCredentialFinalization::deserialize(&their_ke3)
                        .expect("opaque-ke rejected its own KE3"),
                    KeServerLoginParameters {
                        context: Some(&inputs.context),
                        identifiers: ke_identifiers,
                    },
                )
                .expect("opaque-ke server login finish failed")
                .session_key;

            let our_server_session_key = our_server_state
                .finish(&our_ke3)
                .expect("our server login finish failed");

            assert_eq!(
                our_client_session_key.as_bytes(),
                their_login_finish.session_key.as_slice(),
                "client session keys differ across implementations"
            );
            assert_eq!(
                our_server_session_key.as_bytes(),
                their_server_session_key.as_slice(),
                "server session keys differ across implementations"
            );
            assert_eq!(
                our_client_session_key.as_bytes(),
                our_server_session_key.as_bytes(),
                "our client/server session keys differ"
            );
        }
    };
}

differential_driver!(
    run_differential_ristretto255,
    OurRistretto255,
    KeRistretto255
);
differential_driver!(run_differential_p256, OurP256, KeP256);

// ==========================================================================
// Input construction
// ==========================================================================

/// Wide blind material accepted in one RNG call by both blind samplers:
/// ristretto255 wants 64 bytes (wide reduction, nonzero w.h.p. — force a
/// nonzero byte anyway), P-256 wants a canonical nonzero 32-byte scalar
/// (clearing the top bit guarantees < n for the P-256 group order).
fn normalize_blind_material(mut raw: Vec<u8>, wide: bool) -> Vec<u8> {
    if wide {
        raw.resize(64, 0);
    } else {
        raw.resize(32, 0);
        raw[0] &= 0x7f;
    }
    if raw.iter().all(|&b| b == 0) {
        *raw.last_mut().unwrap() = 1;
    }
    raw
}

fn fixed_inputs(nh: usize, wide_blind: bool, explicit_identities: bool) -> DiffInputs {
    DiffInputs {
        password: b"correct horse battery staple".to_vec(),
        credential_id: b"user-42".to_vec(),
        client_identity: explicit_identities.then(|| b"alice".to_vec()),
        server_identity: explicit_identities.then(|| b"bob".to_vec()),
        context: b"pakery-differential".to_vec(),
        oprf_seed: vec![0x5e; nh],
        server_private_key: Vec::new(), // filled in by the caller
        server_public_key: Vec::new(),  // filled in by the caller
        dummy_public_key: Vec::new(),   // filled in by the caller
        blind_registration_material: normalize_blind_material(vec![0xa1; 64], wide_blind),
        envelope_nonce: vec![0xa2; 32],
        blind_login_material: normalize_blind_material(vec![0xb1; 64], wide_blind),
        client_keyshare_seed: vec![0xb2; 32],
        client_nonce: vec![0xb3; 32],
        masking_nonce: vec![0xc1; 32],
        server_keyshare_seed: vec![0xc2; 32],
        server_nonce: vec![0xc3; 32],
    }
}

/// Derive server long-term key material from seeds via our (RFC 9807)
/// keypair derivation and fill it into the inputs.
fn fill_server_keys<Dh: DhGroup>(inputs: &mut DiffInputs, server_seed: &[u8], dummy_seed: &[u8]) {
    let (sk, pk) = Dh::derive_keypair(server_seed).expect("server keypair derivation failed");
    let (_, dummy_pk) = Dh::derive_keypair(dummy_seed).expect("dummy keypair derivation failed");
    inputs.server_private_key = sk.to_vec();
    inputs.server_public_key = pk;
    inputs.dummy_public_key = dummy_pk;
}

// ==========================================================================
// Fixed deterministic cases
// ==========================================================================

#[test]
fn differential_ristretto255_default_identities() {
    let mut inputs = fixed_inputs(OurRistretto255::NH, true, false);
    fill_server_keys::<Ristretto255Dh>(&mut inputs, &[0x11; 32], &[0x22; 32]);
    run_differential_ristretto255(&inputs);
}

#[test]
fn differential_ristretto255_explicit_identities() {
    let mut inputs = fixed_inputs(OurRistretto255::NH, true, true);
    fill_server_keys::<Ristretto255Dh>(&mut inputs, &[0x11; 32], &[0x22; 32]);
    run_differential_ristretto255(&inputs);
}

#[test]
fn differential_p256_default_identities() {
    let mut inputs = fixed_inputs(OurP256::NH, false, false);
    fill_server_keys::<P256Dh>(&mut inputs, &[0x11; 32], &[0x22; 32]);
    run_differential_p256(&inputs);
}

#[test]
fn differential_p256_explicit_identities() {
    let mut inputs = fixed_inputs(OurP256::NH, false, true);
    fill_server_keys::<P256Dh>(&mut inputs, &[0x11; 32], &[0x22; 32]);
    run_differential_p256(&inputs);
}

// ==========================================================================
// Randomized cases (proptest, small case count — each case runs two full
// registration + login flows through both implementations)
// ==========================================================================

prop_compose! {
    fn arb_diff_inputs(nh: usize, wide_blind: bool)(
        password in prop::collection::vec(any::<u8>(), 0..48),
        credential_id in prop::collection::vec(any::<u8>(), 0..24),
        // Empty explicit identities are excluded: our API expresses "default
        // identity" as an empty slice, so `Some(b"")` is not representable.
        client_identity in prop::option::of(prop::collection::vec(any::<u8>(), 1..16)),
        server_identity in prop::option::of(prop::collection::vec(any::<u8>(), 1..16)),
        context in prop::collection::vec(any::<u8>(), 0..16),
        oprf_seed in prop::collection::vec(any::<u8>(), nh..=nh),
        server_key_seed in any::<[u8; 32]>(),
        dummy_key_seed in any::<[u8; 32]>(),
        blind_reg_raw in prop::collection::vec(any::<u8>(), 64),
        envelope_nonce in any::<[u8; 32]>(),
        blind_login_raw in prop::collection::vec(any::<u8>(), 64),
        client_keyshare_seed in any::<[u8; 32]>(),
        client_nonce in any::<[u8; 32]>(),
        masking_nonce in any::<[u8; 32]>(),
        server_keyshare_seed in any::<[u8; 32]>(),
        server_nonce in any::<[u8; 32]>(),
    ) -> (DiffInputs, [u8; 32], [u8; 32]) {
        (
            DiffInputs {
                password,
                credential_id,
                client_identity,
                server_identity,
                context,
                oprf_seed,
                server_private_key: Vec::new(),
                server_public_key: Vec::new(),
                dummy_public_key: Vec::new(),
                blind_registration_material: normalize_blind_material(blind_reg_raw, wide_blind),
                envelope_nonce: envelope_nonce.to_vec(),
                blind_login_material: normalize_blind_material(blind_login_raw, wide_blind),
                client_keyshare_seed: client_keyshare_seed.to_vec(),
                client_nonce: client_nonce.to_vec(),
                masking_nonce: masking_nonce.to_vec(),
                server_keyshare_seed: server_keyshare_seed.to_vec(),
                server_nonce: server_nonce.to_vec(),
            },
            server_key_seed,
            dummy_key_seed,
        )
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn differential_ristretto255_random(
        (mut inputs, server_seed, dummy_seed) in arb_diff_inputs(OurRistretto255::NH, true)
    ) {
        fill_server_keys::<Ristretto255Dh>(&mut inputs, &server_seed, &dummy_seed);
        run_differential_ristretto255(&inputs);
    }

    #[test]
    fn differential_p256_random(
        (mut inputs, server_seed, dummy_seed) in arb_diff_inputs(OurP256::NH, false)
    ) {
        fill_server_keys::<P256Dh>(&mut inputs, &server_seed, &dummy_seed);
        run_differential_p256(&inputs);
    }
}
