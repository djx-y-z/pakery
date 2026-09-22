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

/// Compile-time Argon2id **cost** parameter set for use with
/// [`Argon2idKsfWithParams`].
///
/// All three constants are standard Argon2id `Params` fields. Cost is the
/// only thing a caller tunes here.
///
/// Two quantities are deliberately *not* in this trait:
///
/// - **The salt.** RFC 9807 §7 fixes it at `zeroes(16)` for every recommended
///   configuration, so exposing it would only add a supported way to produce
///   envelopes no conformant peer can open.
/// - **The output length.** RFC 9807 §7 writes `T = Nh` in both of its
///   recommended Argon2id configurations — the hash output length of the
///   ciphersuite the KSF is paired with — so it belongs to the *call* rather
///   than to the parameter set. [`Ksf::stretch`] takes it as an
///   argument and `pakery-opaque` passes `Nh`. Before `0.6.0` it was a
///   constant here, and a parameter set paired with the wrong suite silently
///   changed the derived randomized password — which is exactly what
///   `OpaqueP256Argon2` did before `0.5.0`.
pub trait Argon2Params {
    /// Memory cost in KiB. The bundled parameter set uses `65536` (64 MiB).
    const M_COST: u32;
    /// Iteration count. The bundled parameter set uses `3`.
    const T_COST: u32;
    /// Parallelism. The bundled parameter set uses `4`.
    const P_COST: u32;
}

/// Default cost parameters: RFC 9106 §4's **SECOND RECOMMENDED** Argon2id
/// option — `t = 3`, `p = 4`, `m = 2^16` (64 MiB) — which §4 designates for
/// memory-constrained environments.
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
}

/// Argon2id key-stretching function with a compile-time cost parameter set.
///
/// The salt is fixed at `zeroes(16)` for interop with other OPAQUE
/// implementations; see [`Argon2Params`] for the rationale, and for why the
/// output length is an argument rather than a constant.
pub struct Argon2idKsfWithParams<P: Argon2Params>(PhantomData<P>);

impl<P: Argon2Params> Ksf for Argon2idKsfWithParams<P> {
    /// Stretch to exactly `output_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PakeError::ProtocolError`] if `argon2` rejects the cost
    /// parameters or `output_len` (it enforces `MIN_OUTPUT_LEN = 4`), or if
    /// the hash itself fails — which since `argon2` `0.6` includes running
    /// out of memory for the `m`-KiB block array, where `0.5` aborted the
    /// process instead.
    fn stretch(input: &[u8], output_len: usize) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let params = Params::new(P::M_COST, P::T_COST, P::P_COST, Some(output_len))
            .map_err(|_| PakeError::ProtocolError("argon2 params"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = vec![0u8; output_len];
        argon2
            .hash_password_into(input, ARGON2_KSF_SALT, &mut output)
            .map_err(|_| PakeError::ProtocolError("argon2 hash"))?;
        Ok(Zeroizing::new(output))
    }
}

/// Argon2id `Ksf` at the default costs — alias for
/// `Argon2idKsfWithParams<DefaultArgon2Params>`.
///
/// It serves every OPAQUE suite: the stretch length comes from the call, so
/// the same type is correct for `Nh = 64` and `Nh = 32`. Users who need
/// different cost settings should instantiate [`Argon2idKsfWithParams`] with
/// their own [`Argon2Params`] impl.
pub type Argon2idKsf = Argon2idKsfWithParams<DefaultArgon2Params>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap costs for tests that check a cost-independent property. The salt
    /// and the output length do not depend on `m`/`t`/`p`, so a fast run
    /// proves those properties in full.
    struct CheapParams;
    impl Argon2Params for CheapParams {
        const M_COST: u32 = 8;
        const T_COST: u32 = 1;
        const P_COST: u32 = 1;
    }

    /// Hash `input` with `argon2` invoked by hand, bypassing the `Ksf` impl.
    fn hand_rolled_argon2<P: Argon2Params>(
        input: &[u8],
        salt: &[u8],
        output_len: usize,
    ) -> Vec<u8> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let params = Params::new(P::M_COST, P::T_COST, P::P_COST, Some(output_len)).unwrap();
        let mut out = vec![0u8; output_len];
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

        let ours = Argon2idKsfWithParams::<CheapParams>::stretch(INPUT, 64).unwrap();
        let rfc = hand_rolled_argon2::<CheapParams>(INPUT, &[0u8; 16], 64);
        assert_eq!(
            ours.as_slice(),
            rfc.as_slice(),
            "Argon2id KSF must stretch with S = zeroes(16) (RFC 9807 §7)"
        );

        // Negative control: the pre-0.5.0 salt must not reproduce the same
        // bytes, so the check above cannot pass for the wrong reason.
        let legacy = hand_rolled_argon2::<CheapParams>(INPUT, b"OPAQUE-Argon2id", 64);
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
    }

    /// The requested length — not anything on the type — must determine the
    /// output length, at both values `Nh` takes in the shipped suites.
    ///
    /// This is what replaces the `0.5.0` wiring test: a single KSF type now
    /// serves both suites, so the property to pin is that the argument is
    /// honoured rather than that two aliases were paired correctly.
    #[test]
    fn requested_length_determines_the_output_length() {
        for output_len in [32usize, 64] {
            let out = Argon2idKsfWithParams::<CheapParams>::stretch(b"x", output_len).unwrap();
            assert_eq!(
                out.len(),
                output_len,
                "stretch ignored the requested output length"
            );
        }
    }

    /// Two different requested lengths must not merely truncate one another:
    /// Argon2 mixes the tag length into the hash, so `T` genuinely changes
    /// the bytes. This is what makes a wrong `T` an interop break rather than
    /// a shortened copy of the same value.
    #[test]
    fn a_different_length_is_a_different_value() {
        let out32 = Argon2idKsfWithParams::<CheapParams>::stretch(b"x", 32).unwrap();
        let out64 = Argon2idKsfWithParams::<CheapParams>::stretch(b"x", 64).unwrap();
        assert_ne!(out32.as_slice(), &out64[..32]);
    }

    /// A length `argon2` cannot produce must be an error, not a panic and not
    /// a silently different length. `MIN_OUTPUT_LEN` is 4.
    #[test]
    fn a_length_argon2_rejects_is_an_error() {
        for output_len in [0usize, 1, 3] {
            assert!(
                Argon2idKsfWithParams::<CheapParams>::stretch(b"x", output_len).is_err(),
                "stretch accepted output_len = {output_len}, below argon2's MIN_OUTPUT_LEN"
            );
        }
        assert!(Argon2idKsfWithParams::<CheapParams>::stretch(b"x", 4).is_ok());
    }

    /// Custom costs must produce an output that differs from the default.
    #[test]
    fn custom_params_differ_from_default() {
        let default_out = Argon2idKsf::stretch(b"hunter2", 64).unwrap();
        let fast_out = Argon2idKsfWithParams::<CheapParams>::stretch(b"hunter2", 64).unwrap();

        assert_ne!(default_out.as_slice(), fast_out.as_slice());
        assert_eq!(default_out.len(), 64);
        assert_eq!(fast_out.len(), 64);
    }
}
