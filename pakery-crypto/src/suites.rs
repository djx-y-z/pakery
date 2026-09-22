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
///
/// # Not the draft's P-256 suite
///
/// This suite deliberately differs from draft-irtf-cfrg-cpace's
/// `CPACE-P256_XMD:SHA-256_SSWU_NU_`: it uses the DSI `CPaceP256` and SHA-512
/// rather than SHA-256, because CPace needs a hash output of at least twice
/// the field size (64 bytes for P-256) to derive the generator.
///
/// The consequence is that **no conformant CPace P-256 implementation will
/// interoperate with it**, and the draft's positive test vectors do not apply.
/// Its point-validation vectors are suite-independent and are exercised. Use
/// [`CpaceRistretto255`] where cross-implementation interoperability matters.
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
///
/// # Not an RFC 9382 suite
///
/// RFC 9382 defines M and N only for P-256, P-384, P-521, edwards25519 and
/// edwards448; ristretto255 is not among them. For other groups its Section 2
/// says to derive the points with RFC 9380 `hash_to_curve` from a seed of the
/// form `"M SPAKE2 seed OID x"`. The constants this suite uses
/// ([`crate::SPAKE2_M_COMPRESSED`], [`crate::SPAKE2_N_COMPRESSED`]) follow
/// neither that recipe nor RFC 9382 Appendix A's, so they are **this crate's
/// own**: no RFC 9382 test vector applies to this suite and it has no
/// conformant peer. Use [`Spake2P256`] where cross-implementation
/// interoperability matters.
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
///
/// # Not an RFC 9383 suite
///
/// RFC 9383, like RFC 9382, defines M and N only for P-256, P-384, P-521,
/// edwards25519 and edwards448. This suite reuses the same non-standard
/// ristretto255 constants as [`Spake2Ristretto255`], so it is **this crate's
/// own**: no RFC 9383 test vector applies to it and it has no conformant peer.
/// Use [`Spake2PlusP256`] where cross-implementation interoperability matters.
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
/// specifies for ristretto255-SHA512. The length is not configured here —
/// `pakery-opaque` passes `NH` to [`Ksf::stretch`], so it cannot disagree
/// with the constant below. See [`crate::ksf::DefaultArgon2Params`] for why
/// those costs and not §7's own 2 GiB option.
///
/// [`Ksf::stretch`]: pakery_core::crypto::Ksf::stretch
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
/// specifies for P256-SHA256 — the same [`crate::Argon2idKsf`] the SHA-512
/// suite uses, because the length comes from the call rather than from the
/// KSF type. Before `0.6.0` this suite needed a separate `Argon2idKsfNh32`,
/// and before `0.5.0` it had the wrong one. See
/// [`crate::ksf::DefaultArgon2Params`] for why those costs and not §7's own
/// 2 GiB option.
#[cfg(all(feature = "opaque", feature = "p256", feature = "argon2"))]
pub struct OpaqueP256Argon2;

#[cfg(all(feature = "opaque", feature = "p256", feature = "argon2"))]
impl pakery_opaque::OpaqueCiphersuite for OpaqueP256Argon2 {
    type Hash = crate::Sha256Hash;
    type Kdf = crate::HkdfSha256;
    type Mac = crate::HmacSha256;
    type Dh = crate::P256Dh;
    type Oprf = crate::P256Oprf;
    type Ksf = crate::Argon2idKsf;

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
