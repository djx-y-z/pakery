//! Argon2id implementation of the Ksf trait.

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use pakery_core::crypto::Ksf;
use pakery_core::PakeError;
use zeroize::Zeroizing;

/// Salt used by [`Argon2idKsfWithParams`], fixed at `zeroes(16)`.
///
/// This is the value RFC 9807 §7 names in *both* of its recommended Argon2id
/// configurations (`S = zeroes(16)`), and the value conformant OPAQUE
/// implementations use: `opaque-ke`'s `Ksf` impl hashes with
/// `&[0; argon2::RECOMMENDED_SALT_LEN]`, and `RECOMMENDED_SALT_LEN` is `16`.
/// RFC 9106 §4 independently recommends a 128-bit salt for both of its
/// Argon2id options, which this length matches.
///
/// A fixed salt is sound here because OPAQUE never feeds a raw password to the
/// KSF. The input is the OPRF output, which is already keyed by the server's
/// per-credential OPRF key, so it is unique per user without a salt.
///
/// Any other value produces envelopes a conformant peer cannot open, and it
/// fails *silently*: registration and login both succeed, and only the peer's
/// envelope recovery fails — where it presents as a wrong password. Callers
/// who genuinely need a different salt implement [`Ksf`] from scratch; the
/// escape hatch is the trait, not a knob on the default path.
const ARGON2_KSF_SALT: &[u8] = &[0u8; 16];

/// Compile-time Argon2id parameter set for use with
/// [`Argon2idKsfWithParams`].
///
/// All four constants are standard Argon2id `Params` fields.
///
/// The salt is intentionally NOT part of this trait. RFC 9807 §7 fixes it at
/// `zeroes(16)` for every recommended configuration, so exposing it would only
/// add a supported way to produce envelopes no conformant peer can open.
///
/// `OUTPUT_LEN` is **not** a free tuning knob either: RFC 9807 §7 specifies
/// `T = Nh`, the hash output length of the ciphersuite the KSF is used with.
/// It is 64 for ristretto255-SHA512 and 32 for P256-SHA256. A value that does
/// not match the suite's `Nh` changes the derived randomized password — the
/// stretched output is concatenated into the `Extract` input — and so breaks
/// interop just as silently as a wrong salt. Use [`DefaultArgon2Params`] with
/// SHA-512 suites and [`DefaultArgon2ParamsNh32`] with SHA-256 suites.
pub trait Argon2Params {
    /// Memory cost in KiB. Both bundled parameter sets use `65536` (64 MiB).
    const M_COST: u32;
    /// Iteration count. Both bundled parameter sets use `3`.
    const T_COST: u32;
    /// Parallelism. Both bundled parameter sets use `4`.
    const P_COST: u32;
    /// Output length in bytes: `Nh` of the OPAQUE ciphersuite this KSF is
    /// paired with — 64 for ristretto255-SHA512, 32 for P256-SHA256.
    const OUTPUT_LEN: usize;
}

/// Default parameter set for SHA-512 suites: RFC 9106 §4's **SECOND
/// RECOMMENDED** Argon2id option — `t = 3`, `p = 4`, `m = 2^16` (64 MiB) —
/// which §4 designates for memory-constrained environments. `OUTPUT_LEN` is
/// 64, matching `Nh` for ristretto255-SHA512.
///
/// These costs are deliberately *not* the ones RFC 9807 §7 lists. §7 names
/// RFC 9106's *first* recommended option (`m = 2^21`, 2 GiB, `t = 1`). Both
/// are standardized; 2 GiB of RAM per stretch is not a workable default for a
/// browser or a phone, and it would fail at runtime rather than at compile
/// time. Applications that can afford it should spell out an [`Argon2Params`]
/// impl with `M_COST = 1 << 21` and `T_COST = 1`.
///
/// The values also match the hardcoded `Argon2idKsf` from pakery `0.1.x`, so
/// the [`Argon2idKsf`] alias keeps existing call sites compiling unchanged.
/// The salt does not — see the release notes for `0.5.0`.
pub struct DefaultArgon2Params;

impl Argon2Params for DefaultArgon2Params {
    const M_COST: u32 = 65536;
    const T_COST: u32 = 3;
    const P_COST: u32 = 4;
    const OUTPUT_LEN: usize = 64;
}

/// Parameter set for SHA-256 suites: the costs of [`DefaultArgon2Params`] with
/// `OUTPUT_LEN = 32`, matching `Nh` for P256-SHA256 as RFC 9807 §7's
/// `T = Nh` requires.
///
/// Pair this with [`crate::suites::OpaqueP256Argon2`] and any other
/// SHA-256-based OPAQUE ciphersuite. Using [`DefaultArgon2Params`] there
/// stretches to 64 bytes where a conformant peer stretches to 32, which
/// silently changes the randomized password.
pub struct DefaultArgon2ParamsNh32;

impl Argon2Params for DefaultArgon2ParamsNh32 {
    const M_COST: u32 = DefaultArgon2Params::M_COST;
    const T_COST: u32 = DefaultArgon2Params::T_COST;
    const P_COST: u32 = DefaultArgon2Params::P_COST;
    const OUTPUT_LEN: usize = 32;
}

/// Argon2id key-stretching function with a compile-time parameter set.
///
/// The salt is fixed at `zeroes(16)` for interop with other OPAQUE
/// implementations; see [`Argon2Params`] for the rationale, and for why
/// `OUTPUT_LEN` must match the ciphersuite's `Nh`.
pub struct Argon2idKsfWithParams<P: Argon2Params>(PhantomData<P>);

impl<P: Argon2Params> Ksf for Argon2idKsfWithParams<P> {
    fn stretch(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let params = Params::new(P::M_COST, P::T_COST, P::P_COST, Some(P::OUTPUT_LEN))
            .map_err(|_| PakeError::ProtocolError("argon2 params"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = vec![0u8; P::OUTPUT_LEN];
        argon2
            .hash_password_into(input, ARGON2_KSF_SALT, &mut output)
            .map_err(|_| PakeError::ProtocolError("argon2 hash"))?;
        Ok(Zeroizing::new(output))
    }
}

/// Argon2id Ksf for SHA-512 OPAQUE suites — alias for
/// `Argon2idKsfWithParams<DefaultArgon2Params>`, stretching to 64 bytes.
///
/// Pair SHA-256 suites with [`Argon2idKsfNh32`] instead: `OUTPUT_LEN` must
/// equal the suite's `Nh`. Users who need different cost settings should
/// instantiate [`Argon2idKsfWithParams`] with their own [`Argon2Params`] impl.
pub type Argon2idKsf = Argon2idKsfWithParams<DefaultArgon2Params>;

/// Argon2id Ksf for SHA-256 OPAQUE suites — alias for
/// `Argon2idKsfWithParams<DefaultArgon2ParamsNh32>`, stretching to 32 bytes
/// as RFC 9807 §7's `T = Nh` requires for P256-SHA256.
pub type Argon2idKsfNh32 = Argon2idKsfWithParams<DefaultArgon2ParamsNh32>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters for tests that check a cost-independent property.
    /// The salt and the output length do not depend on `m`/`t`/`p`, so a fast
    /// run proves those properties in full.
    struct CheapParams64;
    impl Argon2Params for CheapParams64 {
        const M_COST: u32 = 8;
        const T_COST: u32 = 1;
        const P_COST: u32 = 1;
        const OUTPUT_LEN: usize = 64;
    }

    /// Hash `input` with `argon2` invoked by hand, bypassing the `Ksf` impl.
    fn hand_rolled_argon2<P: Argon2Params>(input: &[u8], salt: &[u8]) -> Vec<u8> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let params = Params::new(P::M_COST, P::T_COST, P::P_COST, Some(P::OUTPUT_LEN)).unwrap();
        let mut out = vec![0u8; P::OUTPUT_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(input, salt, &mut out)
            .unwrap();
        out
    }

    /// Known-answer test pinning the salt as an *observable property* rather
    /// than as a constant.
    ///
    /// The stretch is computed twice: once through the `Ksf` impl, once by
    /// calling `argon2` directly with `S = zeroes(16)` — the value RFC 9807 §7
    /// specifies and the one `opaque-ke` spells `&[0; RECOMMENDED_SALT_LEN]`.
    /// Editing `ARGON2_KSF_SALT` makes the two diverge, which an assertion of
    /// the constant against its own literal cannot detect.
    #[test]
    fn salt_is_rfc9807_zeroes_16() {
        const INPUT: &[u8] = b"pakery KSF salt conformance KAT";

        assert_eq!(
            ARGON2_KSF_SALT.len(),
            argon2::RECOMMENDED_SALT_LEN,
            "RFC 9106 §4 recommends a 128-bit salt for both Argon2id options"
        );

        let ours = Argon2idKsfWithParams::<CheapParams64>::stretch(INPUT).unwrap();
        let rfc = hand_rolled_argon2::<CheapParams64>(INPUT, &[0u8; 16]);
        assert_eq!(
            ours.as_slice(),
            rfc.as_slice(),
            "Argon2id KSF must stretch with S = zeroes(16) (RFC 9807 §7)"
        );

        // Negative control: the pre-0.5.0 salt must not reproduce the same
        // bytes, so the check above cannot pass for the wrong reason.
        let legacy = hand_rolled_argon2::<CheapParams64>(INPUT, b"OPAQUE-Argon2id");
        assert_ne!(
            ours.as_slice(),
            legacy.as_slice(),
            "the 15-byte pre-0.5.0 salt must not round-trip as zeroes(16)"
        );
    }

    /// `DefaultArgon2Params` must stay on RFC 9106 §4's SECOND RECOMMENDED
    /// Argon2id option. Costs a comparison, not an Argon2 run — it is the only
    /// guard against a silent parameter change.
    #[test]
    fn default_params_are_rfc9106_second_recommended() {
        assert_eq!(<DefaultArgon2Params as Argon2Params>::M_COST, 1 << 16); // 64 MiB
        assert_eq!(<DefaultArgon2Params as Argon2Params>::T_COST, 3);
        assert_eq!(<DefaultArgon2Params as Argon2Params>::P_COST, 4);
        // Nh for ristretto255-SHA512.
        assert_eq!(<DefaultArgon2Params as Argon2Params>::OUTPUT_LEN, 64);
    }

    /// The SHA-256 parameter set must differ from the SHA-512 one in
    /// `OUTPUT_LEN` and in nothing else: RFC 9807 §7 ties `T` to `Nh`, and
    /// leaves the cost parameters identical across both suites.
    #[test]
    fn nh32_params_differ_from_default_only_in_output_len() {
        assert_eq!(
            <DefaultArgon2ParamsNh32 as Argon2Params>::M_COST,
            <DefaultArgon2Params as Argon2Params>::M_COST
        );
        assert_eq!(
            <DefaultArgon2ParamsNh32 as Argon2Params>::T_COST,
            <DefaultArgon2Params as Argon2Params>::T_COST
        );
        assert_eq!(
            <DefaultArgon2ParamsNh32 as Argon2Params>::P_COST,
            <DefaultArgon2Params as Argon2Params>::P_COST
        );
        // Nh for P256-SHA256.
        assert_eq!(<DefaultArgon2ParamsNh32 as Argon2Params>::OUTPUT_LEN, 32);
    }

    /// The two exported aliases must stretch to their suites' `Nh`.
    #[test]
    fn aliases_stretch_to_their_suite_hash_length() {
        struct Cheap32;
        impl Argon2Params for Cheap32 {
            const M_COST: u32 = 8;
            const T_COST: u32 = 1;
            const P_COST: u32 = 1;
            const OUTPUT_LEN: usize = 32;
        }

        assert_eq!(
            Argon2idKsfWithParams::<CheapParams64>::stretch(b"x")
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            Argon2idKsfWithParams::<Cheap32>::stretch(b"x")
                .unwrap()
                .len(),
            32
        );
    }

    /// Custom params must produce an output that differs from the default.
    #[test]
    fn custom_params_differ_from_default() {
        let default_out = Argon2idKsf::stretch(b"hunter2").unwrap();
        let fast_out = Argon2idKsfWithParams::<CheapParams64>::stretch(b"hunter2").unwrap();

        assert_ne!(default_out.as_slice(), fast_out.as_slice());
        assert_eq!(default_out.len(), 64);
        assert_eq!(fast_out.len(), 64);
    }

    /// `OUTPUT_LEN` must control the length of the produced stretch output.
    #[test]
    fn output_len_controls_result_length() {
        struct Out32;
        impl Argon2Params for Out32 {
            const M_COST: u32 = 8;
            const T_COST: u32 = 1;
            const P_COST: u32 = 1;
            const OUTPUT_LEN: usize = 32;
        }

        let out32 = Argon2idKsfWithParams::<Out32>::stretch(b"x").unwrap();
        let out64 = Argon2idKsfWithParams::<CheapParams64>::stretch(b"x").unwrap();
        assert_eq!(out32.len(), 32);
        assert_eq!(out64.len(), 64);
    }
}
