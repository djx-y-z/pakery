//! Argon2id implementation of the Ksf trait.

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use pakery_core::crypto::Ksf;
use pakery_core::PakeError;
use zeroize::Zeroizing;

/// Salt used by [`Argon2idKsfWithParams`].
///
/// Fixed at `b"OPAQUE-Argon2id"` for cross-implementation interop — any user
/// that picks a different salt produces incompatible OPAQUE envelopes. Callers
/// who need a non-default salt must implement [`Ksf`] from scratch.
const ARGON2_KSF_SALT: &[u8] = b"OPAQUE-Argon2id";

/// Compile-time Argon2id parameter set for use with
/// [`Argon2idKsfWithParams`].
///
/// All four constants are standard Argon2id `Params` fields. The salt is
/// intentionally NOT part of this trait — see [`Argon2idKsfWithParams`] for
/// the rationale.
pub trait Argon2Params {
    /// Memory cost in KiB. Default Argon2id production: `65536` (64 MiB).
    const M_COST: u32;
    /// Iteration count. Default Argon2id production: `3`.
    const T_COST: u32;
    /// Parallelism. Default Argon2id production: `4`.
    const P_COST: u32;
    /// Output length in bytes. Typical: `64` (matches `Nx` for the
    /// Ristretto255 + SHA-512 OPAQUE ciphersuite).
    const OUTPUT_LEN: usize;
}

/// Default parameter set matching the hardcoded `Argon2idKsf` from pakery
/// `0.1.x`. Used as the type parameter of the [`Argon2idKsf`] alias to keep
/// existing call sites working without code change.
pub struct DefaultArgon2Params;

impl Argon2Params for DefaultArgon2Params {
    const M_COST: u32 = 65536;
    const T_COST: u32 = 3;
    const P_COST: u32 = 4;
    const OUTPUT_LEN: usize = 64;
}

/// Argon2id key-stretching function with a compile-time parameter set.
///
/// The salt is fixed at `b"OPAQUE-Argon2id"` to preserve interop with other
/// OPAQUE implementations; see [`Argon2Params`] for the rationale.
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

/// Production-tuned Argon2id Ksf — alias for
/// `Argon2idKsfWithParams<DefaultArgon2Params>`. Kept for backward
/// compatibility with pakery `0.1.x`; new users that need different cost or
/// output-length settings should instantiate [`Argon2idKsfWithParams`] with
/// their own [`Argon2Params`] impl.
pub type Argon2idKsf = Argon2idKsfWithParams<DefaultArgon2Params>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Backward-compatibility check: the default `Argon2idKsf` alias must
    /// produce a stretch output bit-exact to pakery `0.1.x` for a fixed input.
    /// Any drift here breaks OPAQUE record compatibility for upgrading users.
    /// The pinned vector below was captured from the v0.2.0 alias before this
    /// test was added — `DefaultArgon2Params` is already known to match the
    /// hardcoded v0.1.x parameter set by inspection (m=65536, t=3, p=4,
    /// len=64, salt=`b"OPAQUE-Argon2id"`), so the pin doubles as a
    /// regression guard against any future change to `DefaultArgon2Params`.
    #[test]
    fn default_alias_matches_v0_1_config() {
        assert_eq!(<DefaultArgon2Params as Argon2Params>::M_COST, 65536);
        assert_eq!(<DefaultArgon2Params as Argon2Params>::T_COST, 3);
        assert_eq!(<DefaultArgon2Params as Argon2Params>::P_COST, 4);
        assert_eq!(<DefaultArgon2Params as Argon2Params>::OUTPUT_LEN, 64);
        assert_eq!(ARGON2_KSF_SALT, b"OPAQUE-Argon2id");

        let out = Argon2idKsf::stretch(b"correct horse battery staple").unwrap();
        // Pinned bit-exact reference, captured from the v0.2.0 alias before
        // this test was added. The alias uses the same parameter set as the
        // hardcoded v0.1.x `Argon2idKsf::stretch` impl, so this pin is a
        // proxy for v0.1.x compatibility.
        const EXPECTED: [u8; 64] = [
            0x7d, 0x7d, 0xbc, 0x32, 0x79, 0xd7, 0xca, 0xac, 0xd7, 0x7f, 0x4f, 0x94, 0x07, 0x17,
            0xc1, 0x17, 0x4f, 0x4f, 0x03, 0x68, 0xab, 0x23, 0x8c, 0xb2, 0xf7, 0xef, 0xab, 0x6f,
            0xf0, 0x22, 0x52, 0x5d, 0x8d, 0x76, 0x8e, 0xc5, 0xcd, 0x86, 0xe8, 0x52, 0x99, 0xe1,
            0x8e, 0x42, 0x18, 0x29, 0x09, 0x21, 0xd1, 0x25, 0xfe, 0x8e, 0x4d, 0xb7, 0x19, 0xf3,
            0x45, 0x6c, 0x80, 0xd9, 0xef, 0xe5, 0x9b, 0x3e,
        ];
        assert_eq!(
            out.as_slice(),
            EXPECTED.as_slice(),
            "Argon2idKsf stretch must match pinned v0.1.x output"
        );
    }

    /// Custom params must produce an output that differs from the default.
    #[test]
    fn custom_params_differ_from_default() {
        struct FastParams;
        impl Argon2Params for FastParams {
            const M_COST: u32 = 8;
            const T_COST: u32 = 1;
            const P_COST: u32 = 1;
            const OUTPUT_LEN: usize = 64;
        }

        let default_out = Argon2idKsf::stretch(b"hunter2").unwrap();
        let fast_out = Argon2idKsfWithParams::<FastParams>::stretch(b"hunter2").unwrap();

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

        struct Out64;
        impl Argon2Params for Out64 {
            const M_COST: u32 = 8;
            const T_COST: u32 = 1;
            const P_COST: u32 = 1;
            const OUTPUT_LEN: usize = 64;
        }

        let out32 = Argon2idKsfWithParams::<Out32>::stretch(b"x").unwrap();
        let out64 = Argon2idKsfWithParams::<Out64>::stretch(b"x").unwrap();
        assert_eq!(out32.len(), 32);
        assert_eq!(out64.len(), 64);
    }
}
