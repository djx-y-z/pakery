//! Key derivation functions for the OPAQUE protocol (RFC 9807 Section 6.4).

use alloc::vec;
use alloc::vec::Vec;

use crate::ciphersuite::OpaqueCiphersuite;
use crate::OpaqueError;
use pakery_core::crypto::{DhGroup, Hash, Kdf, Ksf};
use zeroize::Zeroizing;

/// I2OSP: Integer to Octet String Primitive (big-endian encoding).
///
/// Returns an error if `value` cannot be represented in `length` bytes.
fn i2osp(value: usize, length: usize) -> Result<Vec<u8>, OpaqueError> {
    let max: usize = match length {
        1 => 0xFF,
        2 => 0xFFFF,
        _ => usize::MAX,
    };
    if value > max {
        return Err(OpaqueError::InvalidInput(
            "I2OSP: integer too large for encoding length",
        ));
    }
    let mut out = vec![0u8; length];
    let mut v = value;
    for i in (0..length).rev() {
        out[i] = (v & 0xff) as u8;
        v >>= 8;
    }
    Ok(out)
}

/// Expand-Label per RFC 9807 Section 6.4:
///
/// ```text
/// Expand-Label(Secret, Label, Context, Length) =
///   KDF.Expand(Secret, CustomLabel, Length)
///
/// CustomLabel = I2OSP(Length, 2) || I2OSP(len("OPAQUE-" || Label), 1)
///               || "OPAQUE-" || Label || I2OSP(len(Context), 1) || Context
/// ```
pub fn expand_label<C: OpaqueCiphersuite>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    let opaque_label = [b"OPAQUE-" as &[u8], label].concat();

    let mut custom_label = Vec::new();
    custom_label.extend_from_slice(&i2osp(length, 2)?);
    custom_label.extend_from_slice(&i2osp(opaque_label.len(), 1)?);
    custom_label.extend_from_slice(&opaque_label);
    custom_label.extend_from_slice(&i2osp(context.len(), 1)?);
    custom_label.extend_from_slice(context);

    Ok(C::Kdf::expand(secret, &custom_label, length)?)
}

/// Derive-Secret per RFC 9807:
///
/// ```text
/// Derive-Secret(Secret, Label, TranscriptHash) =
///   Expand-Label(Secret, Label, TranscriptHash, Nx)
/// ```
pub fn derive_secret<C: OpaqueCiphersuite>(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    expand_label::<C>(secret, label, transcript_hash, C::NX)
}

/// Derive the randomized password from the OPRF output.
///
/// ```text
/// randomized_pwd = Extract("", concat(oprf_output, Harden(oprf_output, params)))
/// ```
pub fn derive_randomized_password<C: OpaqueCiphersuite>(
    oprf_output: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    // Both halves of the `Extract` input below are `Nh` bytes. The stretched
    // half is checked after the call; this is the other half. `assert_lengths`
    // pins `Oprf::OUTPUT_LEN == C::NH` at compile time from every entry point,
    // but that constrains what an `Oprf` *declares*, not what `finalize`
    // returns — it returns a `Vec<u8>`. This is the check tied to the bytes.
    if oprf_output.len() != C::NH {
        return Err(OpaqueError::InternalError("OPRF output length != Nh"));
    }
    let hardened = C::Ksf::stretch(oprf_output, C::NH)?;
    // RFC 9807 §7 writes `T = Nh` in both of its recommended Argon2id
    // configurations, and the line below concatenates the result into the
    // `Extract` input — so a KSF that returns
    // some other length silently changes `randomized_pwd`, and the envelope
    // it produces is one no conformant peer can open. `stretch` is *told*
    // `Nh`; this verifies it was honoured, which is the only check tied to
    // the bytes rather than to a declaration. It covers hand-written KSFs
    // too, which is where the remaining risk lives.
    if hardened.len() != C::NH {
        return Err(OpaqueError::InternalError(
            "KSF output length != Nh (RFC 9807 §7: T = Nh)",
        ));
    }
    let mut ikm = Zeroizing::new(Vec::with_capacity(oprf_output.len() + hardened.len()));
    ikm.extend_from_slice(oprf_output);
    ikm.extend_from_slice(&hardened);
    Ok(C::Kdf::extract(&[], &ikm))
}

/// Build the transcript preamble for the 3DH key exchange.
///
/// ```text
/// preamble = "OPAQUEv1-" || I2OSP(len(context), 2) || context
///          || I2OSP(len(client_identity), 2) || client_identity
///          || KE1
///          || I2OSP(len(server_identity), 2) || server_identity
///          || inner_ke2
/// ```
pub fn build_preamble(
    context: &[u8],
    client_identity: &[u8],
    ke1_bytes: &[u8],
    server_identity: &[u8],
    inner_ke2: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    // I2OSP(len, 2) requires values to fit in u16.
    if context.len() > u16::MAX as usize {
        return Err(OpaqueError::InvalidInput("context exceeds u16 length"));
    }
    if client_identity.len() > u16::MAX as usize {
        return Err(OpaqueError::InvalidInput(
            "client_identity exceeds u16 length",
        ));
    }
    if server_identity.len() > u16::MAX as usize {
        return Err(OpaqueError::InvalidInput(
            "server_identity exceeds u16 length",
        ));
    }

    let mut preamble = Vec::new();
    preamble.extend_from_slice(b"OPAQUEv1-");

    // context with 2-byte length prefix
    preamble.extend_from_slice(&i2osp(context.len(), 2)?);
    preamble.extend_from_slice(context);

    // client_identity with 2-byte length prefix
    preamble.extend_from_slice(&i2osp(client_identity.len(), 2)?);
    preamble.extend_from_slice(client_identity);

    // KE1 (no length prefix — fixed size)
    preamble.extend_from_slice(ke1_bytes);

    // server_identity with 2-byte length prefix
    preamble.extend_from_slice(&i2osp(server_identity.len(), 2)?);
    preamble.extend_from_slice(server_identity);

    // inner_ke2 (no length prefix — fixed size)
    preamble.extend_from_slice(inner_ke2);

    Ok(preamble)
}

/// Derive the handshake keys (km2, km3, session_key) from the TripleDH ikm.
///
/// Per RFC 9807 Section 6.4.2:
/// ```text
/// prk = Extract("", ikm)
/// preamble_hash = Hash(preamble)
/// handshake_secret = Derive-Secret(prk, "HandshakeSecret", preamble_hash)
/// session_key = Derive-Secret(prk, "SessionKey", preamble_hash)
/// km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
/// km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
/// ```
///
/// Returns `(km2, km3, session_key)`.
#[allow(clippy::type_complexity)]
pub fn derive_keys<C: OpaqueCiphersuite>(
    ikm: &[u8],
    preamble: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), OpaqueError> {
    let prk = C::Kdf::extract(&[], ikm);
    let preamble_hash = C::Hash::digest(preamble);

    let handshake_secret = derive_secret::<C>(&prk, b"HandshakeSecret", &preamble_hash)?;
    let session_key = derive_secret::<C>(&prk, b"SessionKey", &preamble_hash)?;

    let km2 = derive_secret::<C>(&handshake_secret, b"ServerMAC", b"")?;
    let km3 = derive_secret::<C>(&handshake_secret, b"ClientMAC", b"")?;

    Ok((km2, km3, session_key))
}

/// Compute the TripleDH shared secret.
///
/// ```text
/// ikm = concat(DH(client_eph_sk, server_eph_pk),
///              DH(client_eph_sk, server_static_pk),
///              DH(client_static_sk, server_eph_pk))
/// ```
pub fn triple_dh_ikm<C: OpaqueCiphersuite>(
    dh1_sk: &[u8],
    dh1_pk: &[u8],
    dh2_sk: &[u8],
    dh2_pk: &[u8],
    dh3_sk: &[u8],
    dh3_pk: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    let dh1 = C::Dh::diffie_hellman(dh1_sk, dh1_pk)?;
    let dh2 = C::Dh::diffie_hellman(dh2_sk, dh2_pk)?;
    let dh3 = C::Dh::diffie_hellman(dh3_sk, dh3_pk)?;

    let mut ikm = Zeroizing::new(Vec::with_capacity(dh1.len() + dh2.len() + dh3.len()));
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    Ok(ikm)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A KSF that ignores the length it was handed must make
    /// [`derive_randomized_password`] fail, not change `randomized_pwd`.
    ///
    /// RFC 9807 §7 writes `T = Nh` in both of its recommended Argon2id
    /// configurations, and the result is concatenated into the `Extract` input — so a wrong length produces an
    /// envelope no conformant peer can open, and it does so *silently*:
    /// registration and login both succeed on this side. Since `0.6.0` the
    /// length is passed to the KSF rather than declared on it, which makes a
    /// mismatch unrepresentable for a KSF that honours its argument; an
    /// implementation that does not is the one remaining way in, and it is
    /// the shape a hand-written downstream KSF can still take.
    ///
    /// The mock suite's `Kdf::extract` is `unimplemented!()`, so this also
    /// shows the rejection happens *before* the stretched bytes are used.
    /// The opposite direction — the guard rejecting a correct length — needs
    /// no test of its own: every protocol flow in the workspace runs through
    /// this function.
    #[test]
    fn a_ksf_that_ignores_the_requested_length_is_rejected() {
        use crate::test_mocks::{MockDh, MockHash, MockKdf, MockMac, MockOprf};
        use pakery_core::crypto::Ksf;
        use pakery_core::PakeError;

        /// Returns `len` bytes whatever it is asked for.
        struct FixedLenKsf<const LEN: usize>;

        impl<const LEN: usize> Ksf for FixedLenKsf<LEN> {
            fn stretch(_input: &[u8], _output_len: usize) -> Result<Zeroizing<Vec<u8>>, PakeError> {
                Ok(Zeroizing::new(vec![0xABu8; LEN]))
            }
        }

        struct WrongLenSuite<const LEN: usize>;

        impl<const LEN: usize> OpaqueCiphersuite for WrongLenSuite<LEN> {
            type Hash = MockHash;
            type Kdf = MockKdf;
            type Mac = MockMac;
            type Dh = MockDh;
            type Oprf = MockOprf;
            type Ksf = FixedLenKsf<LEN>;

            const NOE: usize = 32;
            const NOK: usize = 32;
            const NM: usize = 64;
            const NH: usize = 64;
            const NPK: usize = 32;
            const NSK: usize = 32;
            const NX: usize = 64;
        }

        // Both directions of wrong: shorter than Nh and longer than Nh.
        for result in [
            derive_randomized_password::<WrongLenSuite<32>>(&[0u8; 64]),
            derive_randomized_password::<WrongLenSuite<65>>(&[0u8; 64]),
        ] {
            match result {
                Err(OpaqueError::InternalError(msg)) => {
                    assert!(
                        msg.contains("T = Nh"),
                        "rejected for the wrong reason: {msg}"
                    )
                }
                Err(other) => panic!("rejected for the wrong reason: {other}"),
                Ok(_) => panic!("a KSF output disagreeing with Nh was accepted"),
            }
        }
    }

    /// An OPRF output that is not `Nh` bytes must be rejected before it
    /// reaches the KSF.
    ///
    /// `assert_lengths` pins `Oprf::OUTPUT_LEN == C::NH` at compile time, but
    /// that is a declaration: `finalize` returns a `Vec<u8>` and nothing
    /// compares the two. This is the check tied to the bytes, and it is the
    /// half the compile-time assertion cannot reach.
    ///
    /// `MockKsf::stretch` is `unimplemented!()`, so reaching it panics — which
    /// is what makes this also a test that the rejection happens *first*,
    /// before any work is done on the wrong-length input.
    #[test]
    fn an_oprf_output_that_is_not_nh_is_rejected() {
        use crate::test_mocks::MockSuite;

        // MockSuite declares NH = 64. Both directions of wrong.
        for len in [32usize, 63, 65, 128] {
            match derive_randomized_password::<MockSuite>(&vec![0u8; len]) {
                Err(OpaqueError::InternalError(msg)) => assert!(
                    msg.contains("OPRF output length"),
                    "rejected for the wrong reason: {msg}"
                ),
                Err(other) => panic!("rejected for the wrong reason: {other}"),
                Ok(_) => panic!("an OPRF output of {len} bytes was accepted against NH = 64"),
            }
        }
    }

    /// There must be exactly one `Ksf` stretch call in this crate, and the
    /// `T = Nh` check must sit right behind it.
    ///
    /// The check above is a property of *this* call site, not of the trait,
    /// so a second call added later would reopen the hole while every test
    /// still passed. Scanning the source is crude — it is also the only thing
    /// that fails when someone forgets, exactly as
    /// `every_entry_point_asserts_lengths` is for `assert_lengths`.
    ///
    /// It walks `src/` rather than naming the files, and it compares with
    /// whitespace removed. Both are deliberate: a hardcoded list does not see
    /// a file added later, and a literal substring does not see an extra
    /// space before the parenthesis. Each was fail-open by one token.
    #[cfg(feature = "std")]
    #[test]
    fn the_only_ksf_stretch_call_is_followed_by_the_length_check() {
        use crate::source_scan::{rust_sources, squash};

        // Assembled at compile time so this very line is not a match.
        const NEEDLE: &str = concat!("Ksf", "::stretch(");

        let mut found = 0;
        for (name, src) in rust_sources() {
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if line.trim_start().starts_with("//") || !squash(line).contains(NEEDLE) {
                    continue;
                }
                assert_eq!(
                    name,
                    "key_derivation.rs",
                    "{name}:{}: the stretch call belongs in derive_randomized_password, \
                     where the T = Nh check guards it",
                    i + 1
                );
                let window = lines[i..(i + 12).min(lines.len())].join("\n");
                assert!(
                    window.contains("hardened.len() != C::NH"),
                    "{name}:{}: a stretch call must be followed by the T = Nh check",
                    i + 1
                );
                found += 1;
            }
        }
        assert_eq!(found, 1, "expected exactly one stretch call, found {found}");
    }

    /// Boundary behavior of the private I2OSP helper (roadmap item 8: the
    /// per-length `max` match arms and the `>` guard were unconstrained).
    #[test]
    fn i2osp_rejects_values_exceeding_length() {
        assert_eq!(i2osp(0xFF, 1).unwrap(), vec![0xFF]);
        assert!(i2osp(0x100, 1).is_err());
        assert_eq!(i2osp(0xFFFF, 2).unwrap(), vec![0xFF, 0xFF]);
        assert!(i2osp(0x1_0000, 2).is_err());
    }

    /// Big-endian layout with leading zero padding.
    #[test]
    fn i2osp_encodes_big_endian() {
        assert_eq!(i2osp(0x0102, 2).unwrap(), vec![0x01, 0x02]);
        assert_eq!(i2osp(7, 2).unwrap(), vec![0x00, 0x07]);
    }

    /// Boundary values for the preamble length guards (roadmap item 8).
    /// The exact guard messages are asserted because the `i2osp` calls
    /// further down would also reject oversized lengths, just with a
    /// different message — a mutated guard is distinguishable only by it.
    #[test]
    fn build_preamble_length_guards() {
        let max = vec![0u8; u16::MAX as usize];
        let over = vec![0u8; u16::MAX as usize + 1];
        assert!(build_preamble(&max, &max, b"ke1", &max, b"ke2").is_ok());
        assert!(matches!(
            build_preamble(&over, b"", b"", b"", b""),
            Err(OpaqueError::InvalidInput("context exceeds u16 length"))
        ));
        assert!(matches!(
            build_preamble(b"", &over, b"", b"", b""),
            Err(OpaqueError::InvalidInput(
                "client_identity exceeds u16 length"
            ))
        ));
        assert!(matches!(
            build_preamble(b"", b"", b"", &over, b""),
            Err(OpaqueError::InvalidInput(
                "server_identity exceeds u16 length"
            ))
        ));
    }
}
