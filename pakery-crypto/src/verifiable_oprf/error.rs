//! Errors of the verifiable OPRF modes.

use core::fmt;

/// An error from the RFC 9497 VOPRF or POPRF implementation.
///
/// The first five variants are the errors RFC 9497 names (§3.2.1, §5.3). The
/// other three are this crate's: the 2^16 - 1 byte bound on inputs and the
/// shape of a batch, which the RFC states without naming an error, and
/// [`InputMismatch`](Self::InputMismatch), a caller error the RFC's interface
/// leaves undetected. [`Deserialize`](Self::Deserialize) also rejects a zero
/// secret key.
///
/// The split is by who is at fault. In `finalize`, the server's response is
/// blamed by [`Deserialize`](Self::Deserialize) (a malformed evaluated element
/// or proof) and by [`Verify`](Self::Verify) (a well-formed response that does
/// not verify); `InputMismatch`, [`InvalidInput`](Self::InvalidInput) (a
/// zeroized state, or an `info` whose tweaked key is the identity) and the
/// length and batch errors concern the caller's own arguments.
///
/// Errors are deliberately coarse. None of them carries data, and none of them
/// distinguishes *which* element of a batch failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VoprfError {
    /// RFC 9497 `DeserializeError`: the bytes are not the canonical encoding of
    /// a group element other than the identity, or of a scalar. A wrong length
    /// is reported here, and so is a zero secret key.
    Deserialize,
    /// RFC 9497 `InvalidInputError`: the private input hashes to the identity
    /// element, or the POPRF tweaked key `pkS + HashToScalar(framedInfo)·G` is
    /// the identity, or a blind is zero — a caller-supplied one that reduces
    /// to zero, or that of a client state which was zeroized.
    InvalidInput,
    /// RFC 9497 `InverseError`: `skS + HashToScalar(framedInfo)` is zero, so the
    /// POPRF tweaked key has no inverse. Only a party that knows `skS` can
    /// choose such an `info`; RFC 9497 §3.3.3 treats this as a signal to rotate
    /// the key.
    Inverse,
    /// RFC 9497 `VerifyError`: the DLEQ proof does not verify against the
    /// server's public key (VOPRF) or tweaked key (POPRF). The server answered
    /// with another key, evaluated under another POPRF `info` than the client
    /// blinded with, or the response was altered — the client cannot tell
    /// which.
    Verify,
    /// RFC 9497 `DeriveKeyPairError`: 256 consecutive derivation attempts
    /// produced the zero scalar.
    DeriveKeyPair,
    /// An input or `info` longer than 2^16 - 1 bytes, which RFC 9497 inputs
    /// cannot be: they are length-prefixed with two bytes (§1.2, §5.1).
    InputTooLong,
    /// A batch that is empty, holds more than 2^16 - 1 elements, or whose lists
    /// differ in length.
    Batch,
    /// `finalize` was given an input, or a POPRF `info`, other than the one the
    /// client state was blinded with — or, in the POPRF, a state blinded by a
    /// client holding another public key (a VOPRF state does not depend on the
    /// key). Not an RFC 9497 error: the proof covers neither the
    /// input nor how the client derived its tweaked key, so without this check
    /// such a call would return a wrong output or a misleading
    /// [`Verify`](Self::Verify).
    InputMismatch,
}

impl fmt::Display for VoprfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VoprfError::Deserialize => "invalid group element or scalar encoding",
            VoprfError::InvalidInput => "input maps to an invalid group element",
            VoprfError::Inverse => "tweaked private key has no inverse",
            VoprfError::Verify => "proof verification failed",
            VoprfError::DeriveKeyPair => "key derivation produced no valid key",
            VoprfError::InputTooLong => "input longer than 65535 bytes",
            VoprfError::Batch => "invalid batch",
            VoprfError::InputMismatch => "finalize input differs from the blinded one",
        })
    }
}

// `core::error::Error` is stable since Rust 1.81, below the 1.88 MSRV, so the
// impl does not depend on `std`: a `no_std` build gets it as well.
impl core::error::Error for VoprfError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn display_output_per_variant() {
        let all = [
            VoprfError::Deserialize,
            VoprfError::InvalidInput,
            VoprfError::Inverse,
            VoprfError::Verify,
            VoprfError::DeriveKeyPair,
            VoprfError::InputTooLong,
            VoprfError::Batch,
            VoprfError::InputMismatch,
        ];
        let rendered: alloc::vec::Vec<_> = all.iter().map(ToString::to_string).collect();
        assert_eq!(
            rendered,
            [
                "invalid group element or scalar encoding",
                "input maps to an invalid group element",
                "tweaked private key has no inverse",
                "proof verification failed",
                "key derivation produced no valid key",
                "input longer than 65535 bytes",
                "invalid batch",
                "finalize input differs from the blinded one",
            ]
        );
    }
}
