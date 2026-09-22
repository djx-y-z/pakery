//! Key stretching function trait.

use crate::error::PakeError;
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// A key stretching function (KSF) used to harden passwords.
///
/// # The output length is a property of the call, not of the implementation
///
/// RFC 9807 §7 writes `T = Nh` in both of its recommended Argon2id
/// configurations, tying the stretch output length to the ciphersuite the KSF
/// is used with — so the caller, the only party that knows `Nh`, passes it
/// in. The same shape appears underneath: `argon2`, `scrypt` and `pbkdf2` all
/// take the output length at the call rather than as a property of the type
/// (each also carries one on its `Params`, but the low-level entry point
/// writes into a caller-supplied slice). The conformant OPAQUE implementation
/// this crate differential-tests against spells its KSF `hash<L>`, mapping
/// `L` to `L`; it reads the length off the input type rather than taking it
/// as an argument, which is a different way of reaching the same conclusion —
/// the length is not an associated constant of the implementation.
///
/// Before `0.6.0` the length was an associated constant of the implementation
/// instead, which is not where it can live: [`IdentityKsf`] backs both a
/// 64-byte and a 32-byte OPAQUE suite, so no single constant on the type is
/// right for both. Pinning it to the type is what let `OpaqueP256Argon2`
/// stretch to 64 bytes against a suite whose `Nh` is 32 — see the `0.5.0`
/// changelog.
///
/// An implementation that cannot produce exactly `output_len` bytes must
/// return an error rather than a shorter or longer result. The output is
/// concatenated into the input that derives the randomized password, so its
/// length changes the derived value, and a wrong length breaks interoperation
/// with a conformant peer *silently* — registration and login both succeed,
/// and only the peer fails to open the envelope, where it presents as a wrong
/// password.
pub trait Ksf {
    /// Stretch `input` into exactly `output_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if this KSF cannot produce `output_len` bytes, or if
    /// the underlying primitive fails.
    fn stretch(input: &[u8], output_len: usize) -> Result<Zeroizing<Vec<u8>>, PakeError>;
}

/// Identity key stretching function (pass-through).
///
/// **WARNING: Not suitable for production.**  This KSF applies no work factor
/// and returns the input unchanged.  It exists solely for RFC test vectors
/// that specify no password hardening.  In production, use a proper KSF such
/// as Argon2id (see `pakery-crypto::Argon2idKsf`).
///
/// Being length-preserving, it can only serve a call whose `output_len`
/// already equals the input length, and it rejects any other. In OPAQUE both
/// are `Nh`: the input is the OPRF output and `output_len` is `Nh`. That is
/// enforced rather than assumed — `pakery-opaque` asserts
/// `Oprf::OUTPUT_LEN == Nh` at compile time from every entry point, and
/// re-checks the bytes it actually received before calling the KSF, since a
/// declared length is not a returned one.
pub struct IdentityKsf;

impl Ksf for IdentityKsf {
    fn stretch(input: &[u8], output_len: usize) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        if input.len() != output_len {
            return Err(PakeError::InvalidInput(
                "IdentityKsf is length-preserving and cannot stretch to a different length",
            ));
        }
        Ok(Zeroizing::new(input.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// At the only length it can serve, `IdentityKsf` is a pass-through.
    #[test]
    fn identity_passes_the_input_through_at_its_own_length() {
        let input = vec![0xA5u8; 64];
        let out = IdentityKsf::stretch(&input, 64).expect("length-preserving call must succeed");
        assert_eq!(out.as_slice(), input.as_slice());
    }

    /// Both `Nh` values the shipped identity-KSF suites use.
    #[test]
    fn identity_serves_both_shipped_nh_values() {
        assert_eq!(IdentityKsf::stretch(&[0x11; 64], 64).unwrap().len(), 64);
        assert_eq!(IdentityKsf::stretch(&[0x11; 32], 32).unwrap().len(), 32);
    }

    /// A mismatch must be an error, not a silent truncation, extension or
    /// pass-through at the wrong length.
    ///
    /// This is the whole content of the impl beyond the copy: without it,
    /// `IdentityKsf` would return `Nh`-disagreeing bytes for any caller that
    /// hands it an input of the wrong size, which is the defect class
    /// `0.6.0` closes. Deleting the guard must fail a test.
    #[test]
    fn identity_rejects_a_length_it_cannot_produce() {
        for (input_len, output_len) in [(64usize, 32usize), (32, 64), (0, 32), (64, 0)] {
            let err = IdentityKsf::stretch(&vec![0u8; input_len], output_len);
            assert!(
                err.is_err(),
                "IdentityKsf accepted input_len={input_len} for output_len={output_len}"
            );
        }
    }
}
