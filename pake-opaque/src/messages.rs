//! Wire-format message types for the OPAQUE protocol.

use alloc::vec::Vec;

use crate::ciphersuite::OpaqueCiphersuite;
use crate::OpaqueError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Client's first registration message containing the blinded password.
#[derive(Debug, Clone)]
pub struct RegistrationRequest {
    /// OPRF blinded element (Noe bytes).
    pub blinded_message: Vec<u8>,
}

impl RegistrationRequest {
    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        self.blinded_message.clone()
    }

    /// Deserialize from bytes.
    pub fn deserialize<C: OpaqueCiphersuite>(bytes: &[u8]) -> Result<Self, OpaqueError> {
        if bytes.len() != C::NOE {
            return Err(OpaqueError::DeserializationError);
        }
        Ok(Self {
            blinded_message: bytes.to_vec(),
        })
    }
}

/// Server's registration response containing the evaluated element and server public key.
#[derive(Debug, Clone)]
pub struct RegistrationResponse {
    /// OPRF evaluated element (Noe bytes).
    pub evaluated_message: Vec<u8>,
    /// Server's long-term public key (Npk bytes).
    pub server_public_key: Vec<u8>,
}

impl RegistrationResponse {
    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(self.evaluated_message.len() + self.server_public_key.len());
        out.extend_from_slice(&self.evaluated_message);
        out.extend_from_slice(&self.server_public_key);
        out
    }

    /// Deserialize from bytes.
    pub fn deserialize<C: OpaqueCiphersuite>(bytes: &[u8]) -> Result<Self, OpaqueError> {
        let expected = C::NOE + C::NPK;
        if bytes.len() != expected {
            return Err(OpaqueError::DeserializationError);
        }
        Ok(Self {
            evaluated_message: bytes[..C::NOE].to_vec(),
            server_public_key: bytes[C::NOE..].to_vec(),
        })
    }
}

/// Encrypted envelope containing a nonce and auth tag.
#[derive(Debug, Clone, Zeroize)]
pub struct Envelope {
    /// Random nonce (Nn bytes).
    pub nonce: Vec<u8>,
    /// Authentication tag (Nm bytes).
    pub auth_tag: Vec<u8>,
}

impl Envelope {
    /// Returns the serialized size in bytes.
    pub fn size<C: OpaqueCiphersuite>() -> usize {
        C::NN + C::NM
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.nonce.len() + self.auth_tag.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.auth_tag);
        out
    }

    /// Deserialize from bytes.
    pub fn deserialize<C: OpaqueCiphersuite>(bytes: &[u8]) -> Result<Self, OpaqueError> {
        let expected = C::NN + C::NM;
        if bytes.len() != expected {
            return Err(OpaqueError::DeserializationError);
        }
        Ok(Self {
            nonce: bytes[..C::NN].to_vec(),
            auth_tag: bytes[C::NN..].to_vec(),
        })
    }
}

/// The registration record stored by the server.
///
/// Contains `masking_key` which is a password-derived key.
/// Zeroized on drop to prevent key material from lingering in memory.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct RegistrationRecord {
    /// Client's public key (Npk bytes).
    pub client_public_key: Vec<u8>,
    /// Masking key for credential response (Nh bytes).
    pub masking_key: Vec<u8>,
    /// The encrypted envelope (Nn + Nm bytes).
    pub envelope: Envelope,
}

impl RegistrationRecord {
    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let env = self.envelope.serialize();
        let mut out =
            Vec::with_capacity(self.client_public_key.len() + self.masking_key.len() + env.len());
        out.extend_from_slice(&self.client_public_key);
        out.extend_from_slice(&self.masking_key);
        out.extend_from_slice(&env);
        out
    }

    /// Deserialize from bytes.
    pub fn deserialize<C: OpaqueCiphersuite>(bytes: &[u8]) -> Result<Self, OpaqueError> {
        let env_size = Envelope::size::<C>();
        let expected = C::NPK + C::NH + env_size;
        if bytes.len() != expected {
            return Err(OpaqueError::DeserializationError);
        }
        let mut offset = 0;
        let client_public_key = bytes[offset..offset + C::NPK].to_vec();
        offset += C::NPK;
        let masking_key = bytes[offset..offset + C::NH].to_vec();
        offset += C::NH;
        let envelope = Envelope::deserialize::<C>(&bytes[offset..])?;
        Ok(Self {
            client_public_key,
            masking_key,
            envelope,
        })
    }
}

/// Client's first login message (KE1).
#[derive(Debug, Clone)]
pub struct KE1 {
    /// OPRF blinded element (Noe bytes).
    pub blinded_message: Vec<u8>,
    /// Client nonce (Nn bytes).
    pub client_nonce: Vec<u8>,
    /// Client ephemeral public key (Npk bytes).
    pub client_keyshare: Vec<u8>,
}

impl KE1 {
    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.blinded_message.len() + self.client_nonce.len() + self.client_keyshare.len(),
        );
        out.extend_from_slice(&self.blinded_message);
        out.extend_from_slice(&self.client_nonce);
        out.extend_from_slice(&self.client_keyshare);
        out
    }

    /// Deserialize from bytes.
    pub fn deserialize<C: OpaqueCiphersuite>(bytes: &[u8]) -> Result<Self, OpaqueError> {
        let expected = C::NOE + C::NN + C::NPK;
        if bytes.len() != expected {
            return Err(OpaqueError::DeserializationError);
        }
        let mut offset = 0;
        let blinded_message = bytes[offset..offset + C::NOE].to_vec();
        offset += C::NOE;
        let client_nonce = bytes[offset..offset + C::NN].to_vec();
        offset += C::NN;
        let client_keyshare = bytes[offset..].to_vec();
        Ok(Self {
            blinded_message,
            client_nonce,
            client_keyshare,
        })
    }
}

/// Credential response embedded in KE2, masked by XOR with HKDF output.
#[derive(Debug, Clone)]
pub struct CredentialResponse {
    /// Server's long-term public key (Npk bytes).
    pub server_public_key: Vec<u8>,
    /// The encrypted envelope (Nn + Nm bytes).
    pub envelope: Envelope,
}

impl CredentialResponse {
    /// Returns the serialized size in bytes.
    pub fn size<C: OpaqueCiphersuite>() -> usize {
        C::NPK + Envelope::size::<C>()
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let env = self.envelope.serialize();
        let mut out = Vec::with_capacity(self.server_public_key.len() + env.len());
        out.extend_from_slice(&self.server_public_key);
        out.extend_from_slice(&env);
        out
    }

    /// Deserialize from bytes.
    pub fn deserialize<C: OpaqueCiphersuite>(bytes: &[u8]) -> Result<Self, OpaqueError> {
        let expected = CredentialResponse::size::<C>();
        if bytes.len() != expected {
            return Err(OpaqueError::DeserializationError);
        }
        let server_public_key = bytes[..C::NPK].to_vec();
        let envelope = Envelope::deserialize::<C>(&bytes[C::NPK..])?;
        Ok(Self {
            server_public_key,
            envelope,
        })
    }
}

/// Server's login response (KE2).
#[derive(Debug, Clone)]
pub struct KE2 {
    /// OPRF evaluated element (Noe bytes).
    pub evaluated_message: Vec<u8>,
    /// Masking nonce (Nn bytes).
    pub masking_nonce: Vec<u8>,
    /// XOR-masked credential response (Npk + Nn + Nm bytes).
    pub masked_response: Vec<u8>,
    /// Server nonce (Nn bytes).
    pub server_nonce: Vec<u8>,
    /// Server ephemeral public key (Npk bytes).
    pub server_keyshare: Vec<u8>,
    /// Server MAC (Nm bytes).
    pub server_mac: Vec<u8>,
}

impl KE2 {
    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.evaluated_message.len()
                + self.masking_nonce.len()
                + self.masked_response.len()
                + self.server_nonce.len()
                + self.server_keyshare.len()
                + self.server_mac.len(),
        );
        out.extend_from_slice(&self.evaluated_message);
        out.extend_from_slice(&self.masking_nonce);
        out.extend_from_slice(&self.masked_response);
        out.extend_from_slice(&self.server_nonce);
        out.extend_from_slice(&self.server_keyshare);
        out.extend_from_slice(&self.server_mac);
        out
    }

    /// Deserialize from bytes.
    pub fn deserialize<C: OpaqueCiphersuite>(bytes: &[u8]) -> Result<Self, OpaqueError> {
        let cred_resp_size = CredentialResponse::size::<C>();
        let expected = C::NOE + C::NN + cred_resp_size + C::NN + C::NPK + C::NM;
        if bytes.len() != expected {
            return Err(OpaqueError::DeserializationError);
        }
        let mut offset = 0;

        let evaluated_message = bytes[offset..offset + C::NOE].to_vec();
        offset += C::NOE;

        let masking_nonce = bytes[offset..offset + C::NN].to_vec();
        offset += C::NN;

        let masked_response = bytes[offset..offset + cred_resp_size].to_vec();
        offset += cred_resp_size;

        let server_nonce = bytes[offset..offset + C::NN].to_vec();
        offset += C::NN;

        let server_keyshare = bytes[offset..offset + C::NPK].to_vec();
        offset += C::NPK;

        let server_mac = bytes[offset..].to_vec();

        Ok(Self {
            evaluated_message,
            masking_nonce,
            masked_response,
            server_nonce,
            server_keyshare,
            server_mac,
        })
    }

    /// Extract the portion of KE2 used in the preamble (everything before server_mac).
    pub fn inner_ke2(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.evaluated_message.len()
                + self.masking_nonce.len()
                + self.masked_response.len()
                + self.server_nonce.len()
                + self.server_keyshare.len(),
        );
        out.extend_from_slice(&self.evaluated_message);
        out.extend_from_slice(&self.masking_nonce);
        out.extend_from_slice(&self.masked_response);
        out.extend_from_slice(&self.server_nonce);
        out.extend_from_slice(&self.server_keyshare);
        out
    }
}

/// Client's final login message (KE3).
#[derive(Debug, Clone)]
pub struct KE3 {
    /// Client MAC (Nm bytes).
    pub client_mac: Vec<u8>,
}

impl KE3 {
    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        self.client_mac.clone()
    }

    /// Deserialize from bytes.
    pub fn deserialize<C: OpaqueCiphersuite>(bytes: &[u8]) -> Result<Self, OpaqueError> {
        if bytes.len() != C::NM {
            return Err(OpaqueError::DeserializationError);
        }
        Ok(Self {
            client_mac: bytes.to_vec(),
        })
    }
}
