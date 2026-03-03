//! OPAQUE P-256 test vectors from draft-irtf-cfrg-opaque reference implementation.
//!
//! Vector 1: default identities (public keys).
//! Vector 2: explicit identities (client=alice, server=bob).
//!
//! Source: <https://github.com/cfrg/draft-irtf-cfrg-opaque/tree/master/poc/vectors>
#![cfg(feature = "p256")]

use pakery_core::crypto::dh::DhGroup;
use pakery_core::crypto::IdentityKsf;
use pakery_crypto::{HkdfSha256, HmacSha256, P256Dh, P256Oprf, Sha256Hash};
use pakery_opaque::messages::CredentialResponse;
use pakery_opaque::{
    ClientLogin, ClientRegistration, OpaqueCiphersuite, OpaqueError, RegistrationRequest,
    ServerLogin, ServerRegistration, ServerSetup, KE1,
};

/// OPAQUE ciphersuite: P-256 + SHA-256 + IdentityKSF.
struct OpaqueP256Sha256;

impl OpaqueCiphersuite for OpaqueP256Sha256 {
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

/// Deterministic RNG that returns pre-determined bytes, one scalar at a time.
struct SequentialRng {
    chunks: Vec<Vec<u8>>,
    index: usize,
    current_chunk: Vec<u8>,
    chunk_offset: usize,
}

impl SequentialRng {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        let current_chunk = if chunks.is_empty() {
            vec![]
        } else {
            chunks[0].clone()
        };
        Self {
            chunks,
            index: 0,
            current_chunk,
            chunk_offset: 0,
        }
    }

    fn from_single(data: &[u8]) -> Self {
        Self::new(vec![data.to_vec()])
    }
}

impl rand_core::RngCore for SequentialRng {
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
        let mut written = 0;
        while written < dest.len() {
            if self.chunk_offset >= self.current_chunk.len() {
                self.index += 1;
                if self.index < self.chunks.len() {
                    self.current_chunk = self.chunks[self.index].clone();
                    self.chunk_offset = 0;
                } else {
                    // Pad with zeros if we run out
                    for b in &mut dest[written..] {
                        *b = 0;
                    }
                    return;
                }
            }
            let available = self.current_chunk.len() - self.chunk_offset;
            let needed = dest.len() - written;
            let to_copy = available.min(needed);
            dest[written..written + to_copy].copy_from_slice(
                &self.current_chunk[self.chunk_offset..self.chunk_offset + to_copy],
            );
            self.chunk_offset += to_copy;
            written += to_copy;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for SequentialRng {}

// ==========================================================================
// Test Vector 1: Default identities (empty client_identity, empty server_identity)
// Source: cfrg/draft-irtf-cfrg-opaque poc/vectors, OPRF(P-256, SHA-256)
// ==========================================================================

mod vector1 {
    pub const OPRF_SEED: &str = "62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2";
    pub const CREDENTIAL_ID: &str = "31323334";
    pub const PASSWORD: &str = "436f7272656374486f72736542617474657279537461706c65";
    pub const ENVELOPE_NONCE: &str =
        "a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f";
    pub const MASKING_NONCE: &str =
        "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d";
    pub const SERVER_PRIVATE_KEY: &str =
        "c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5";
    pub const SERVER_PUBLIC_KEY: &str =
        "035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874";
    pub const BLIND_REGISTRATION: &str =
        "411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153";
    pub const BLIND_LOGIN: &str =
        "c497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1";
    pub const CLIENT_NONCE: &str =
        "ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1";
    pub const SERVER_NONCE: &str =
        "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1";
    pub const CLIENT_KEYSHARE_SEED: &str =
        "633b875d74d1556d2a2789309972b06db21dfcc4f5ad51d7e74d783b7cfab8dc";
    pub const SERVER_KEYSHARE_SEED: &str =
        "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f";
    pub const CONTEXT: &str = "4f50415155452d504f43";

    // Intermediates
    pub const OPRF_KEY: &str = "2dfb5cb9aa1476093be74ca0d43e5b02862a05f5d6972614d7433acdc66f7f31";
    pub const CLIENT_PUBLIC_KEY: &str =
        "03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae5214";
    pub const MASKING_KEY: &str =
        "7f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aaf";
    pub const ENVELOPE: &str = "a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8";

    // Outputs
    pub const REGISTRATION_REQUEST: &str =
        "029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8";
    pub const REGISTRATION_RESPONSE: &str = "0350d3694c00978f00a5ce7cd08a00547e4ab5fb5fc2b2f6717cdaa6c89136efef035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874";
    pub const REGISTRATION_UPLOAD: &str = "03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8";
    pub const KE1_HEX: &str = "037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6";
    pub const KE2_HEX: &str = "0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae26837b6ce688bf9af2542f04eec9ab96a1b9328812dc2f5c89182ed47fead61f09f71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a103c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b50a73b145bc87a157e8c58c0342e2047ee22ae37b63db17e0a82a30fcc4ecf7b";
    pub const KE3_HEX: &str = "e97cab4433aa39d598e76f13e768bba61c682947bdcf9936035e8a3a3ebfb66e";
    pub const EXPORT_KEY: &str = "c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b";
    pub const SESSION_KEY: &str =
        "484ad345715ccce138ca49e4ea362c6183f0949aaaa1125dc3bc3f80876e7cd1";

    pub const CLIENT_IDENTITY: &str = "";
    pub const SERVER_IDENTITY: &str = "";
}

// ==========================================================================
// Test Vector 2: Explicit identities (client=alice, server=bob)
// ==========================================================================

mod vector2 {
    pub const CLIENT_IDENTITY: &str = "616c696365";
    pub const SERVER_IDENTITY: &str = "626f62";

    // Same inputs as vector1
    pub use super::vector1::{
        BLIND_LOGIN, BLIND_REGISTRATION, CLIENT_KEYSHARE_SEED, CLIENT_NONCE, CONTEXT,
        CREDENTIAL_ID, ENVELOPE_NONCE, MASKING_NONCE, OPRF_SEED, PASSWORD, SERVER_KEYSHARE_SEED,
        SERVER_NONCE, SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY,
    };

    // Same intermediates (registration is the same except envelope)
    pub use super::vector1::{CLIENT_PUBLIC_KEY, MASKING_KEY};

    // Different envelope, registration upload, KE2, KE3, session_key due to identities
    pub const ENVELOPE: &str = "a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f4d7773a36a208a866301dbb2858e40dc5638017527cf91aef32d3848eebe0971";
    pub const REGISTRATION_UPLOAD: &str = "03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f4d7773a36a208a866301dbb2858e40dc5638017527cf91aef32d3848eebe0971";

    // Same KE1 (identity not involved in KE1)
    pub use super::vector1::KE1_HEX;

    pub const KE2_HEX: &str = "0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae268d7f106042021c80300e4c6f585980cf39fc51a4a6bba41b0729f9b240c729e5671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a103c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b84922c7e5d074838a8f278592c53f61fb59f031e85ad480c0c71086b871e1b24";
    pub const KE3_HEX: &str = "46833578cee137775f6be3f01b80748daac5a694101ad0e9e7025480552da56a";
    pub const SESSION_KEY: &str =
        "27766fabd8dd88ff37fbd0ef1a491e601d10d9f016c2b28c4bd1b0fb7511a3c3";
    pub const EXPORT_KEY: &str = "c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b";
}

fn h(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("valid hex")
}

// ==========================================================================
// P256Dh basic operations
// ==========================================================================

#[test]
fn p256_dh_derive_keypair() {
    let seed = [0x42u8; 32];
    let (sk, pk) = P256Dh::derive_keypair(&seed).unwrap();
    assert_eq!(sk.len(), 32);
    assert_eq!(pk.len(), 33); // compressed SEC1

    // Deterministic: same seed produces same keypair.
    let (sk2, pk2) = P256Dh::derive_keypair(&seed).unwrap();
    assert_eq!(sk, sk2);
    assert_eq!(pk, pk2);
}

#[test]
fn p256_dh_public_key_from_private() {
    let seed = [0xaa; 32];
    let (sk, pk) = P256Dh::derive_keypair(&seed).unwrap();
    let pk2 = P256Dh::public_key_from_private(&sk).unwrap();
    assert_eq!(pk, pk2);
}

#[test]
fn p256_dh_consistency() {
    let mut rng = rand_core::OsRng;
    let (sk_a, pk_a) = P256Dh::generate_keypair(&mut rng).unwrap();
    let (sk_b, pk_b) = P256Dh::generate_keypair(&mut rng).unwrap();

    let shared_ab = P256Dh::diffie_hellman(&sk_a, &pk_b).unwrap();
    let shared_ba = P256Dh::diffie_hellman(&sk_b, &pk_a).unwrap();
    assert_eq!(shared_ab, shared_ba);
}

#[test]
fn p256_dh_rejects_invalid_inputs() {
    let mut rng = rand_core::OsRng;
    let (sk, _pk) = P256Dh::generate_keypair(&mut rng).unwrap();

    // Invalid public key length.
    assert!(P256Dh::diffie_hellman(&sk, &[0x02; 16]).is_err());

    // Invalid scalar length.
    assert!(P256Dh::diffie_hellman(&[0u8; 16], &[0x02; 33]).is_err());

    // Invalid public key (not on curve).
    let mut bad_pk = [0xffu8; 33];
    bad_pk[0] = 0x02;
    assert!(P256Dh::diffie_hellman(&sk, &bad_pk).is_err());
}

#[test]
fn p256_dh_generate_produces_different_keys() {
    let mut rng = rand_core::OsRng;
    let (sk1, pk1) = P256Dh::generate_keypair(&mut rng).unwrap();
    let (sk2, pk2) = P256Dh::generate_keypair(&mut rng).unwrap();
    assert_ne!(sk1, sk2);
    assert_ne!(pk1, pk2);
}

#[test]
fn p256_dh_rejects_scalar_gte_order() {
    // P-256 group order n:
    // FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    // A scalar >= n must be rejected.
    let n_bytes =
        hex::decode("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551").unwrap();
    let pk = hex::decode(vector1::SERVER_PUBLIC_KEY).unwrap();
    assert!(P256Dh::diffie_hellman(&n_bytes, &pk).is_err());

    // Also test n+1.
    let mut n_plus_one = n_bytes.clone();
    // Increment last byte (0x51 -> 0x52).
    *n_plus_one.last_mut().unwrap() += 1;
    assert!(P256Dh::diffie_hellman(&n_plus_one, &pk).is_err());
}

// ==========================================================================
// RFC test vector 1: OPRF key derivation
// ==========================================================================

#[test]
fn test_oprf_key_derivation() {
    let oprf_key = pakery_opaque::oprf::derive_oprf_key::<OpaqueP256Sha256>(
        &h(vector1::OPRF_SEED),
        &h(vector1::CREDENTIAL_ID),
    )
    .unwrap();
    assert_eq!(hex::encode(&oprf_key), vector1::OPRF_KEY);
}

// ==========================================================================
// RFC test vector 1: Registration
// ==========================================================================

#[test]
fn test_registration_request() {
    let password = h(vector1::PASSWORD);
    let blind = h(vector1::BLIND_REGISTRATION);
    let mut rng = SequentialRng::from_single(&blind);

    let (request, _state) =
        ClientRegistration::<OpaqueP256Sha256>::start(&password, &mut rng).unwrap();

    assert_eq!(
        hex::encode(request.serialize()),
        vector1::REGISTRATION_REQUEST
    );
}

#[test]
fn test_registration_response() {
    let setup = ServerSetup::<OpaqueP256Sha256>::new_with_key(
        h(vector1::OPRF_SEED),
        h(vector1::SERVER_PRIVATE_KEY),
        h(vector1::SERVER_PUBLIC_KEY),
    );
    let request = RegistrationRequest {
        blinded_message: h(vector1::REGISTRATION_REQUEST),
    };

    let response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &request, &h(vector1::CREDENTIAL_ID))
            .unwrap();

    assert_eq!(
        hex::encode(response.serialize()),
        vector1::REGISTRATION_RESPONSE
    );
}

#[test]
fn test_registration_record() {
    let password = h(vector1::PASSWORD);
    let blind = h(vector1::BLIND_REGISTRATION);
    let mut rng = SequentialRng::from_single(&blind);

    let (request, state) =
        ClientRegistration::<OpaqueP256Sha256>::start(&password, &mut rng).unwrap();

    let setup = ServerSetup::<OpaqueP256Sha256>::new_with_key(
        h(vector1::OPRF_SEED),
        h(vector1::SERVER_PRIVATE_KEY),
        h(vector1::SERVER_PUBLIC_KEY),
    );

    let response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &request, &h(vector1::CREDENTIAL_ID))
            .unwrap();

    let (record, export_key) = state
        .finish_with_nonce(
            &response,
            &h(vector1::SERVER_IDENTITY),
            &h(vector1::CLIENT_IDENTITY),
            &h(vector1::ENVELOPE_NONCE),
        )
        .unwrap();

    assert_eq!(
        hex::encode(record.serialize()),
        vector1::REGISTRATION_UPLOAD
    );
    assert_eq!(hex::encode(&export_key), vector1::EXPORT_KEY);
    assert_eq!(
        hex::encode(&record.client_public_key),
        vector1::CLIENT_PUBLIC_KEY
    );
    assert_eq!(hex::encode(&record.masking_key), vector1::MASKING_KEY);
    assert_eq!(hex::encode(record.envelope.serialize()), vector1::ENVELOPE);
}

// ==========================================================================
// RFC test vector 1: Login (KE1, KE2, KE3, session key)
// ==========================================================================

#[test]
fn test_ke1() {
    let password = h(vector1::PASSWORD);
    let blind = h(vector1::BLIND_LOGIN);
    let mut blind_rng = SequentialRng::from_single(&blind);

    let (ke1, _state) = ClientLogin::<OpaqueP256Sha256>::start_with_blind_and_nonce_and_seed(
        &password,
        &mut blind_rng,
        &h(vector1::CLIENT_NONCE),
        &h(vector1::CLIENT_KEYSHARE_SEED),
    )
    .unwrap();

    assert_eq!(hex::encode(ke1.serialize()), vector1::KE1_HEX);
}

#[test]
fn test_ke2() {
    let password = h(vector1::PASSWORD);
    let blind_reg = h(vector1::BLIND_REGISTRATION);
    let mut reg_rng = SequentialRng::from_single(&blind_reg);

    let setup = ServerSetup::<OpaqueP256Sha256>::new_with_key(
        h(vector1::OPRF_SEED),
        h(vector1::SERVER_PRIVATE_KEY),
        h(vector1::SERVER_PUBLIC_KEY),
    );

    let (req, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(&password, &mut reg_rng).unwrap();

    let reg_resp =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &req, &h(vector1::CREDENTIAL_ID))
            .unwrap();

    let (record, _) = reg_state
        .finish_with_nonce(
            &reg_resp,
            &h(vector1::SERVER_IDENTITY),
            &h(vector1::CLIENT_IDENTITY),
            &h(vector1::ENVELOPE_NONCE),
        )
        .unwrap();

    let ke1 = KE1::deserialize::<OpaqueP256Sha256>(&h(vector1::KE1_HEX)).unwrap();

    let (ke2, _server_state) = ServerLogin::<OpaqueP256Sha256>::start_with_nonce_and_seed(
        &setup,
        &record,
        &ke1,
        &h(vector1::CREDENTIAL_ID),
        &h(vector1::CONTEXT),
        &h(vector1::SERVER_IDENTITY),
        &h(vector1::CLIENT_IDENTITY),
        &h(vector1::SERVER_NONCE),
        &h(vector1::SERVER_KEYSHARE_SEED),
        &h(vector1::MASKING_NONCE),
    )
    .unwrap();

    assert_eq!(hex::encode(ke2.serialize()), vector1::KE2_HEX);
}

#[test]
fn test_ke3_and_session_key() {
    let password = h(vector1::PASSWORD);
    let blind_reg = h(vector1::BLIND_REGISTRATION);
    let mut reg_rng = SequentialRng::from_single(&blind_reg);

    let setup = ServerSetup::<OpaqueP256Sha256>::new_with_key(
        h(vector1::OPRF_SEED),
        h(vector1::SERVER_PRIVATE_KEY),
        h(vector1::SERVER_PUBLIC_KEY),
    );

    let (req, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(&password, &mut reg_rng).unwrap();

    let reg_resp =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &req, &h(vector1::CREDENTIAL_ID))
            .unwrap();

    let (record, _) = reg_state
        .finish_with_nonce(
            &reg_resp,
            &h(vector1::SERVER_IDENTITY),
            &h(vector1::CLIENT_IDENTITY),
            &h(vector1::ENVELOPE_NONCE),
        )
        .unwrap();

    // Client login start
    let blind_login = h(vector1::BLIND_LOGIN);
    let mut blind_rng = SequentialRng::from_single(&blind_login);

    let (ke1, client_state) = ClientLogin::<OpaqueP256Sha256>::start_with_blind_and_nonce_and_seed(
        &password,
        &mut blind_rng,
        &h(vector1::CLIENT_NONCE),
        &h(vector1::CLIENT_KEYSHARE_SEED),
    )
    .unwrap();

    // Server login start
    let (ke2, server_state) = ServerLogin::<OpaqueP256Sha256>::start_with_nonce_and_seed(
        &setup,
        &record,
        &ke1,
        &h(vector1::CREDENTIAL_ID),
        &h(vector1::CONTEXT),
        &h(vector1::SERVER_IDENTITY),
        &h(vector1::CLIENT_IDENTITY),
        &h(vector1::SERVER_NONCE),
        &h(vector1::SERVER_KEYSHARE_SEED),
        &h(vector1::MASKING_NONCE),
    )
    .unwrap();

    // Client login finish
    let (ke3, client_session_key, client_export_key) = client_state
        .finish(
            &ke2,
            &h(vector1::CONTEXT),
            &h(vector1::SERVER_IDENTITY),
            &h(vector1::CLIENT_IDENTITY),
        )
        .unwrap();

    assert_eq!(hex::encode(ke3.serialize()), vector1::KE3_HEX);
    assert_eq!(
        hex::encode(client_session_key.as_bytes()),
        vector1::SESSION_KEY
    );
    assert_eq!(hex::encode(&client_export_key), vector1::EXPORT_KEY);

    // Server login finish
    let server_session_key = server_state.finish(&ke3).unwrap();
    assert_eq!(
        hex::encode(server_session_key.as_bytes()),
        vector1::SESSION_KEY
    );
}

// ==========================================================================
// RFC test vector 2: Explicit identities (client=alice, server=bob)
// ==========================================================================

#[test]
fn test_vector2_intermediate_values() {
    let password = h(vector2::PASSWORD);
    let blind = h(vector2::BLIND_REGISTRATION);
    let mut rng = SequentialRng::from_single(&blind);

    let (request, state) =
        ClientRegistration::<OpaqueP256Sha256>::start(&password, &mut rng).unwrap();

    let setup = ServerSetup::<OpaqueP256Sha256>::new_with_key(
        h(vector2::OPRF_SEED),
        h(vector2::SERVER_PRIVATE_KEY),
        h(vector2::SERVER_PUBLIC_KEY),
    );

    let response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &request, &h(vector2::CREDENTIAL_ID))
            .unwrap();

    let (record, _) = state
        .finish_with_nonce(
            &response,
            &h(vector2::SERVER_IDENTITY),
            &h(vector2::CLIENT_IDENTITY),
            &h(vector2::ENVELOPE_NONCE),
        )
        .unwrap();

    // Same client public key and masking key as vector1 (identities don't affect these)
    assert_eq!(
        hex::encode(&record.client_public_key),
        vector2::CLIENT_PUBLIC_KEY
    );
    assert_eq!(hex::encode(&record.masking_key), vector2::MASKING_KEY);
    // Different envelope (identities are mixed into auth_tag)
    assert_eq!(hex::encode(record.envelope.serialize()), vector2::ENVELOPE);
}

#[test]
fn test_vector2_registration_record() {
    let password = h(vector2::PASSWORD);
    let blind = h(vector2::BLIND_REGISTRATION);
    let mut rng = SequentialRng::from_single(&blind);

    let (request, state) =
        ClientRegistration::<OpaqueP256Sha256>::start(&password, &mut rng).unwrap();

    let setup = ServerSetup::<OpaqueP256Sha256>::new_with_key(
        h(vector2::OPRF_SEED),
        h(vector2::SERVER_PRIVATE_KEY),
        h(vector2::SERVER_PUBLIC_KEY),
    );

    let response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &request, &h(vector2::CREDENTIAL_ID))
            .unwrap();

    let (record, export_key) = state
        .finish_with_nonce(
            &response,
            &h(vector2::SERVER_IDENTITY),
            &h(vector2::CLIENT_IDENTITY),
            &h(vector2::ENVELOPE_NONCE),
        )
        .unwrap();

    assert_eq!(
        hex::encode(record.serialize()),
        vector2::REGISTRATION_UPLOAD
    );
    assert_eq!(hex::encode(&export_key), vector2::EXPORT_KEY);
}

#[test]
fn test_vector2_full_login() {
    // Registration
    let password = h(vector2::PASSWORD);
    let blind_reg = h(vector2::BLIND_REGISTRATION);
    let mut reg_rng = SequentialRng::from_single(&blind_reg);

    let setup = ServerSetup::<OpaqueP256Sha256>::new_with_key(
        h(vector2::OPRF_SEED),
        h(vector2::SERVER_PRIVATE_KEY),
        h(vector2::SERVER_PUBLIC_KEY),
    );

    let (req, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(&password, &mut reg_rng).unwrap();

    let reg_resp =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &req, &h(vector2::CREDENTIAL_ID))
            .unwrap();

    let (record, _) = reg_state
        .finish_with_nonce(
            &reg_resp,
            &h(vector2::SERVER_IDENTITY),
            &h(vector2::CLIENT_IDENTITY),
            &h(vector2::ENVELOPE_NONCE),
        )
        .unwrap();

    // Client login start
    let blind_login = h(vector2::BLIND_LOGIN);
    let mut blind_rng = SequentialRng::from_single(&blind_login);

    let (ke1, client_state) = ClientLogin::<OpaqueP256Sha256>::start_with_blind_and_nonce_and_seed(
        &password,
        &mut blind_rng,
        &h(vector2::CLIENT_NONCE),
        &h(vector2::CLIENT_KEYSHARE_SEED),
    )
    .unwrap();

    assert_eq!(hex::encode(ke1.serialize()), vector2::KE1_HEX);

    // Server login start
    let (ke2, server_state) = ServerLogin::<OpaqueP256Sha256>::start_with_nonce_and_seed(
        &setup,
        &record,
        &ke1,
        &h(vector2::CREDENTIAL_ID),
        &h(vector2::CONTEXT),
        &h(vector2::SERVER_IDENTITY),
        &h(vector2::CLIENT_IDENTITY),
        &h(vector2::SERVER_NONCE),
        &h(vector2::SERVER_KEYSHARE_SEED),
        &h(vector2::MASKING_NONCE),
    )
    .unwrap();

    assert_eq!(hex::encode(ke2.serialize()), vector2::KE2_HEX);

    // Client login finish
    let (ke3, client_session_key, client_export_key) = client_state
        .finish(
            &ke2,
            &h(vector2::CONTEXT),
            &h(vector2::SERVER_IDENTITY),
            &h(vector2::CLIENT_IDENTITY),
        )
        .unwrap();

    assert_eq!(hex::encode(ke3.serialize()), vector2::KE3_HEX);
    assert_eq!(
        hex::encode(client_session_key.as_bytes()),
        vector2::SESSION_KEY
    );
    assert_eq!(hex::encode(&client_export_key), vector2::EXPORT_KEY);

    // Server login finish
    let server_session_key = server_state.finish(&ke3).unwrap();
    assert_eq!(
        hex::encode(server_session_key.as_bytes()),
        vector2::SESSION_KEY
    );
}

// ==========================================================================
// Round-trip tests
// ==========================================================================

#[test]
fn test_full_roundtrip_random() {
    let mut rng = rand_core::OsRng;
    let password = b"correct horse battery staple";

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();

    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user123").unwrap();

    let (record, export_key_reg) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) = ClientLogin::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();

    let (ke2, server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup,
        &record,
        &ke1,
        b"user123",
        b"test-context",
        b"",
        b"",
        &mut rng,
    )
    .unwrap();

    let (ke3, client_session_key, export_key_login) = client_state
        .finish(&ke2, b"test-context", b"", b"")
        .unwrap();

    let server_session_key = server_state.finish(&ke3).unwrap();

    assert_eq!(client_session_key, server_session_key);
    assert_eq!(export_key_reg, export_key_login);
}

#[test]
fn login_roundtrip_with_explicit_identities() {
    let mut rng = rand_core::OsRng;
    let password = b"password123";

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, export_key_reg) = reg_state
        .finish(&reg_response, b"alice", b"bob", &mut rng)
        .unwrap();

    let (ke1, client_state) = ClientLogin::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();

    let (ke2, server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup,
        &record,
        &ke1,
        b"user1",
        b"test-context",
        b"alice",
        b"bob",
        &mut rng,
    )
    .unwrap();

    let (ke3, client_session_key, export_key_login) = client_state
        .finish(&ke2, b"test-context", b"alice", b"bob")
        .unwrap();

    let server_session_key = server_state.finish(&ke3).unwrap();

    assert_eq!(client_session_key, server_session_key);
    assert_eq!(export_key_reg, export_key_login);
}

// ==========================================================================
// Wrong password rejection
// ==========================================================================

#[test]
fn wrong_password_rejected() {
    let mut rng = rand_core::OsRng;

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password-A", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password-B", &mut rng).unwrap();

    let (ke2, _server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup, &record, &ke1, b"user1", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    let result = client_state.finish(&ke2, b"ctx", b"", b"");
    assert!(matches!(result, Err(OpaqueError::EnvelopeRecoveryError)));
}

// ==========================================================================
// Empty password edge case
// ==========================================================================

#[test]
fn test_empty_password_roundtrip() {
    let mut rng = rand_core::OsRng;
    let password = b"";

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, export_key_reg) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) = ClientLogin::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();

    let (ke2, server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup,
        &record,
        &ke1,
        b"user1",
        b"test-context",
        b"",
        b"",
        &mut rng,
    )
    .unwrap();

    let (ke3, client_session_key, export_key_login) = client_state
        .finish(&ke2, b"test-context", b"", b"")
        .unwrap();

    let server_session_key = server_state.finish(&ke3).unwrap();

    assert_eq!(
        client_session_key, server_session_key,
        "Empty password must produce matching session keys"
    );
    assert_eq!(
        export_key_reg, export_key_login,
        "Export keys must match with empty password"
    );
}

// ==========================================================================
// KE2 field tampering — corrupted components must cause authentication failure
// ==========================================================================

#[test]
fn tampered_server_mac_detected() {
    let mut rng = rand_core::OsRng;
    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();

    let (mut ke2, _server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup, &record, &ke1, b"user1", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    ke2.server_mac[0] ^= 0xff;

    let result = client_state.finish(&ke2, b"ctx", b"", b"");
    assert!(matches!(
        result,
        Err(OpaqueError::ServerAuthenticationError)
    ));
}

#[test]
fn tampered_client_mac_detected() {
    let mut rng = rand_core::OsRng;
    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();

    let (ke2, server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup, &record, &ke1, b"user1", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    let (mut ke3, _, _) = client_state.finish(&ke2, b"ctx", b"", b"").unwrap();

    ke3.client_mac[0] ^= 0xff;

    let result = server_state.finish(&ke3);
    assert!(matches!(
        result,
        Err(OpaqueError::ClientAuthenticationError)
    ));
}

#[test]
fn tampered_ke2_evaluated_message() {
    let mut rng = rand_core::OsRng;
    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let (mut ke2, _) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup, &record, &ke1, b"user", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    ke2.evaluated_message[0] ^= 0x01;

    let result = client_state.finish(&ke2, b"ctx", b"", b"");
    assert!(
        result.is_err(),
        "corrupted evaluated_message must cause authentication failure"
    );
}

#[test]
fn tampered_ke2_masked_response() {
    let mut rng = rand_core::OsRng;
    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let (mut ke2, _) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup, &record, &ke1, b"user", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    ke2.masked_response[0] ^= 0x01;

    let result = client_state.finish(&ke2, b"ctx", b"", b"");
    assert!(
        result.is_err(),
        "corrupted masked_response must cause authentication failure"
    );
}

#[test]
fn tampered_ke2_server_keyshare() {
    let mut rng = rand_core::OsRng;
    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let (mut ke2, _) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup, &record, &ke1, b"user", b"ctx", b"", b"", &mut rng,
    )
    .unwrap();

    ke2.server_keyshare[0] ^= 0x01;

    let result = client_state.finish(&ke2, b"ctx", b"", b"");
    assert!(
        result.is_err(),
        "corrupted server_keyshare must cause authentication failure"
    );
}

#[test]
fn tampered_ke1_keyshare_detected() {
    let mut rng = rand_core::OsRng;
    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user1").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (mut ke1, _client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();

    let mut bad_point = [0xffu8; 33];
    bad_point[0] = 0x02;
    ke1.client_keyshare = bad_point.to_vec();

    let result = ServerLogin::<OpaqueP256Sha256>::start(
        &setup, &record, &ke1, b"user1", b"ctx", b"", b"", &mut rng,
    );
    assert!(result.is_err());
}

// ==========================================================================
// Context mismatch
// ==========================================================================

#[test]
fn test_context_mismatch_fails() {
    let mut rng = rand_core::OsRng;
    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    let (ke1, client_state) =
        ClientLogin::<OpaqueP256Sha256>::start(b"password", &mut rng).unwrap();
    let (ke2, _server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup,
        &record,
        &ke1,
        b"user",
        b"server-ctx",
        b"",
        b"",
        &mut rng,
    )
    .unwrap();

    let result = client_state.finish(&ke2, b"client-ctx", b"", b"");
    assert!(
        matches!(result, Err(OpaqueError::ServerAuthenticationError)),
        "context mismatch must cause server authentication failure"
    );
}

// ==========================================================================
// Fake credential response (user enumeration protection)
// ==========================================================================

#[test]
fn test_fake_credential_response() {
    let mut rng = rand_core::OsRng;
    let password = b"some password";

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (ke1, _client_state) = ClientLogin::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();

    let fake_ke2 = ServerLogin::<OpaqueP256Sha256>::start_fake(
        &setup,
        &ke1,
        b"nonexistent_user",
        b"test-context",
        b"",
        b"",
        &mut rng,
    )
    .unwrap();

    let expected_size = OpaqueP256Sha256::NOE
        + OpaqueP256Sha256::NN
        + CredentialResponse::size::<OpaqueP256Sha256>()
        + OpaqueP256Sha256::NN
        + OpaqueP256Sha256::NPK
        + OpaqueP256Sha256::NM;
    assert_eq!(fake_ke2.serialize().len(), expected_size);
}

#[test]
fn test_fake_credential_client_fails() {
    let mut rng = rand_core::OsRng;
    let password = b"some password";

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    let (ke1, client_state) = ClientLogin::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();

    let fake_ke2 = ServerLogin::<OpaqueP256Sha256>::start_fake(
        &setup,
        &ke1,
        b"nonexistent_user",
        b"test-context",
        b"",
        b"",
        &mut rng,
    )
    .unwrap();

    let result = client_state.finish(&fake_ke2, b"test-context", b"", b"");
    assert!(matches!(result, Err(OpaqueError::EnvelopeRecoveryError)));
}

#[test]
fn test_fake_ke2_size_matches_real() {
    let mut rng = rand_core::OsRng;
    let password = b"test password";

    let setup = ServerSetup::<OpaqueP256Sha256>::new(&mut rng).unwrap();

    // Register
    let (reg_request, reg_state) =
        ClientRegistration::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();
    let reg_response =
        ServerRegistration::<OpaqueP256Sha256>::start(&setup, &reg_request, b"user123").unwrap();
    let (record, _) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

    // Client login start
    let (ke1, _client_state) = ClientLogin::<OpaqueP256Sha256>::start(password, &mut rng).unwrap();

    // Real KE2
    let (real_ke2, _server_state) = ServerLogin::<OpaqueP256Sha256>::start(
        &setup,
        &record,
        &ke1,
        b"user123",
        b"test-context",
        b"",
        b"",
        &mut rng,
    )
    .unwrap();

    // Fake KE2 (non-existent user)
    let fake_ke2 = ServerLogin::<OpaqueP256Sha256>::start_fake(
        &setup,
        &ke1,
        b"nonexistent_user",
        b"test-context",
        b"",
        b"",
        &mut rng,
    )
    .unwrap();

    let real_serialized = real_ke2.serialize();
    let fake_serialized = fake_ke2.serialize();

    // Total serialized size must match (critical for user enumeration resistance)
    assert_eq!(
        real_serialized.len(),
        fake_serialized.len(),
        "Fake KE2 must be same total size as real KE2"
    );

    // Individual field sizes must match
    assert_eq!(
        real_ke2.evaluated_message.len(),
        fake_ke2.evaluated_message.len(),
        "evaluated_message size mismatch"
    );
    assert_eq!(
        real_ke2.masking_nonce.len(),
        fake_ke2.masking_nonce.len(),
        "masking_nonce size mismatch"
    );
    assert_eq!(
        real_ke2.masked_response.len(),
        fake_ke2.masked_response.len(),
        "masked_response size mismatch"
    );
    assert_eq!(
        real_ke2.server_nonce.len(),
        fake_ke2.server_nonce.len(),
        "server_nonce size mismatch"
    );
    assert_eq!(
        real_ke2.server_keyshare.len(),
        fake_ke2.server_keyshare.len(),
        "server_keyshare size mismatch"
    );
    assert_eq!(
        real_ke2.server_mac.len(),
        fake_ke2.server_mac.len(),
        "server_mac size mismatch"
    );
}
