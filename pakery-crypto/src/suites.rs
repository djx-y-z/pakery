//! Pre-built ciphersuite structs for standard curve + hash combinations.
//!
//! These eliminate boilerplate by providing ready-to-use ciphersuite types.
//! Enable the corresponding feature flags to use them (e.g. `cpace` + `ristretto255`).

// ---------------------------------------------------------------------------
// CPace ciphersuites
// ---------------------------------------------------------------------------

/// CPace ciphersuite: Ristretto255 + SHA-512.
#[cfg(all(feature = "cpace", feature = "ristretto255"))]
pub struct CpaceRistretto255;

#[cfg(all(feature = "cpace", feature = "ristretto255"))]
impl pakery_cpace::CpaceCiphersuite for CpaceRistretto255 {
    type Group = crate::Ristretto255Group;
    type Hash = crate::Sha512Hash;

    const DSI: &'static [u8] = b"CPaceRistretto255";
    const HASH_BLOCK_SIZE: usize = 128;
    const FIELD_SIZE_BYTES: usize = 32;
}

/// CPace ciphersuite: P-256 + SHA-512.
#[cfg(all(feature = "cpace", feature = "p256"))]
pub struct CpaceP256;

#[cfg(all(feature = "cpace", feature = "p256"))]
impl pakery_cpace::CpaceCiphersuite for CpaceP256 {
    type Group = crate::P256Group;
    type Hash = crate::Sha512Hash;

    const DSI: &'static [u8] = b"CPaceP256";
    const HASH_BLOCK_SIZE: usize = 128;
    const FIELD_SIZE_BYTES: usize = 32;
}

// ---------------------------------------------------------------------------
// SPAKE2 ciphersuites
// ---------------------------------------------------------------------------

/// SPAKE2 ciphersuite: Ristretto255 + SHA-512.
#[cfg(all(feature = "spake2", feature = "ristretto255"))]
pub struct Spake2Ristretto255;

#[cfg(all(feature = "spake2", feature = "ristretto255"))]
impl pakery_spake2::Spake2Ciphersuite for Spake2Ristretto255 {
    type Group = crate::Ristretto255Group;
    type Hash = crate::Sha512Hash;
    type Kdf = crate::HkdfSha512;
    type Mac = crate::HmacSha512;

    const NH: usize = 64;
    const M_BYTES: &'static [u8] = &crate::SPAKE2_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &crate::SPAKE2_N_COMPRESSED;
}

/// SPAKE2 ciphersuite: P-256 + SHA-256.
#[cfg(all(feature = "spake2", feature = "p256"))]
pub struct Spake2P256;

#[cfg(all(feature = "spake2", feature = "p256"))]
impl pakery_spake2::Spake2Ciphersuite for Spake2P256 {
    type Group = crate::P256Group;
    type Hash = crate::Sha256Hash;
    type Kdf = crate::HkdfSha256;
    type Mac = crate::HmacSha256;

    const NH: usize = 32;
    const M_BYTES: &'static [u8] = &crate::SPAKE2_P256_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &crate::SPAKE2_P256_N_COMPRESSED;
}

// ---------------------------------------------------------------------------
// SPAKE2+ ciphersuites
// ---------------------------------------------------------------------------

/// SPAKE2+ ciphersuite: Ristretto255 + SHA-512.
#[cfg(all(feature = "spake2plus", feature = "ristretto255"))]
pub struct Spake2PlusRistretto255;

#[cfg(all(feature = "spake2plus", feature = "ristretto255"))]
impl pakery_spake2plus::Spake2PlusCiphersuite for Spake2PlusRistretto255 {
    type Group = crate::Ristretto255Group;
    type Hash = crate::Sha512Hash;
    type Kdf = crate::HkdfSha512;
    type Mac = crate::HmacSha512;

    const NH: usize = 64;
    const M_BYTES: &'static [u8] = &crate::SPAKE2_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &crate::SPAKE2_N_COMPRESSED;
}

/// SPAKE2+ ciphersuite: P-256 + SHA-256.
#[cfg(all(feature = "spake2plus", feature = "p256"))]
pub struct Spake2PlusP256;

#[cfg(all(feature = "spake2plus", feature = "p256"))]
impl pakery_spake2plus::Spake2PlusCiphersuite for Spake2PlusP256 {
    type Group = crate::P256Group;
    type Hash = crate::Sha256Hash;
    type Kdf = crate::HkdfSha256;
    type Mac = crate::HmacSha256;

    const NH: usize = 32;
    const M_BYTES: &'static [u8] = &crate::SPAKE2_P256_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &crate::SPAKE2_P256_N_COMPRESSED;
}

// ---------------------------------------------------------------------------
// OPAQUE ciphersuites
// ---------------------------------------------------------------------------

/// OPAQUE ciphersuite: Ristretto255 + SHA-512 + IdentityKSF.
///
/// Uses the identity key stretching function (no password hardening).
/// Suitable for testing; for production use [`OpaqueRistretto255Argon2`].
#[cfg(all(feature = "opaque", feature = "ristretto255"))]
pub struct OpaqueRistretto255;

#[cfg(all(feature = "opaque", feature = "ristretto255"))]
impl pakery_opaque::OpaqueCiphersuite for OpaqueRistretto255 {
    type Hash = crate::Sha512Hash;
    type Kdf = crate::HkdfSha512;
    type Mac = crate::HmacSha512;
    type Dh = crate::Ristretto255Dh;
    type Oprf = crate::Ristretto255Oprf;
    type Ksf = pakery_core::crypto::IdentityKsf;

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

/// OPAQUE ciphersuite: P-256 + SHA-256 + IdentityKSF.
///
/// Uses the identity key stretching function (no password hardening).
/// Suitable for testing; for production use [`OpaqueP256Argon2`].
#[cfg(all(feature = "opaque", feature = "p256"))]
pub struct OpaqueP256;

#[cfg(all(feature = "opaque", feature = "p256"))]
impl pakery_opaque::OpaqueCiphersuite for OpaqueP256 {
    type Hash = crate::Sha256Hash;
    type Kdf = crate::HkdfSha256;
    type Mac = crate::HmacSha256;
    type Dh = crate::P256Dh;
    type Oprf = crate::P256Oprf;
    type Ksf = pakery_core::crypto::IdentityKsf;

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

/// OPAQUE ciphersuite: Ristretto255 + SHA-512 + Argon2id.
///
/// Argon2id hardening at RFC 9106 §4's SECOND RECOMMENDED cost (64 MiB,
/// `t = 3`, `p = 4`), stretching to `Nh = 64` as RFC 9807 §7's `T = Nh`
/// requires for ristretto255-SHA512. See [`crate::ksf::DefaultArgon2Params`]
/// for why those costs and not §7's own 2 GiB option.
#[cfg(all(feature = "opaque", feature = "ristretto255", feature = "argon2"))]
pub struct OpaqueRistretto255Argon2;

#[cfg(all(feature = "opaque", feature = "ristretto255", feature = "argon2"))]
impl pakery_opaque::OpaqueCiphersuite for OpaqueRistretto255Argon2 {
    type Hash = crate::Sha512Hash;
    type Kdf = crate::HkdfSha512;
    type Mac = crate::HmacSha512;
    type Dh = crate::Ristretto255Dh;
    type Oprf = crate::Ristretto255Oprf;
    type Ksf = crate::Argon2idKsf;

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

/// OPAQUE ciphersuite: P-256 + SHA-256 + Argon2id.
///
/// Argon2id hardening at RFC 9106 §4's SECOND RECOMMENDED cost (64 MiB,
/// `t = 3`, `p = 4`), stretching to `Nh = 32` as RFC 9807 §7's `T = Nh`
/// requires for P256-SHA256. See [`crate::ksf::DefaultArgon2Params`] for why
/// those costs and not §7's own 2 GiB option.
#[cfg(all(feature = "opaque", feature = "p256", feature = "argon2"))]
pub struct OpaqueP256Argon2;

#[cfg(all(feature = "opaque", feature = "p256", feature = "argon2"))]
impl pakery_opaque::OpaqueCiphersuite for OpaqueP256Argon2 {
    type Hash = crate::Sha256Hash;
    type Kdf = crate::HkdfSha256;
    type Mac = crate::HmacSha256;
    type Dh = crate::P256Dh;
    type Oprf = crate::P256Oprf;
    type Ksf = crate::Argon2idKsfNh32;

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
