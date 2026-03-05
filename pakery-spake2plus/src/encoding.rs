//! RFC 9383 transcript encoding.
//!
//! SPAKE2+ uses 8-byte little-endian length prefixes (same as SPAKE2).
//! The transcript has 10 fields (vs 6 in SPAKE2).

use alloc::vec::Vec;
use zeroize::Zeroizing;

/// Encode a length as 8-byte little-endian.
fn encode_le_u64(len: usize) -> [u8; 8] {
    (len as u64).to_le_bytes()
}

/// Append LE64(len) || data to buf.
fn append_lv(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&encode_le_u64(data.len()));
    buf.extend_from_slice(data);
}

/// Build the SPAKE2+ transcript TT per RFC 9383 section 3.3.
///
/// ```text
/// TT = len(Context)    || Context
///   || len(idProver)   || idProver
///   || len(idVerifier) || idVerifier
///   || len(M)          || M
///   || len(N)          || N
///   || len(shareP)     || shareP
///   || len(shareV)     || shareV
///   || len(Z)          || Z
///   || len(V)          || V
///   || len(w0)         || w0
/// ```
#[allow(clippy::too_many_arguments)]
pub fn build_transcript(
    context: &[u8],
    id_prover: &[u8],
    id_verifier: &[u8],
    m: &[u8],
    n: &[u8],
    share_p: &[u8],
    share_v: &[u8],
    z: &[u8],
    v: &[u8],
    w0: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut tt = Vec::new();
    append_lv(&mut tt, context);
    append_lv(&mut tt, id_prover);
    append_lv(&mut tt, id_verifier);
    append_lv(&mut tt, m);
    append_lv(&mut tt, n);
    append_lv(&mut tt, share_p);
    append_lv(&mut tt, share_v);
    append_lv(&mut tt, z);
    append_lv(&mut tt, v);
    append_lv(&mut tt, w0);
    Zeroizing::new(tt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_le_u64() {
        assert_eq!(encode_le_u64(0), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(encode_le_u64(1), [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(encode_le_u64(256), [0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_append_lv() {
        let mut buf = Vec::new();
        append_lv(&mut buf, b"test");
        assert_eq!(buf.len(), 8 + 4);
        assert_eq!(&buf[..8], &[4, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&buf[8..], b"test");
    }

    #[test]
    fn test_build_transcript_10_fields() {
        let tt = build_transcript(
            b"ctx", b"P", b"V", b"MM", b"NN", b"sP", b"sV", b"ZZ", b"VV", b"w",
        );
        // 10 fields: each has 8-byte LE length prefix
        // 3 + 1 + 1 + 2 + 2 + 2 + 2 + 2 + 2 + 1 = 18 bytes data + 10*8 = 80 prefix
        assert_eq!(tt.len(), 80 + 18);
    }

    #[test]
    fn test_build_transcript_empty_fields() {
        let tt = build_transcript(b"", b"", b"", b"M", b"N", b"", b"", b"", b"", b"");
        // 10 fields: 0+0+0+1+1+0+0+0+0+0 = 2 bytes data + 80 prefix
        assert_eq!(tt.len(), 82);
    }

    #[test]
    fn test_transcript_field_order() {
        let tt = build_transcript(b"C", b"P", b"V", b"M", b"N", b"sP", b"sV", b"Z", b"V", b"w");
        // Check first field: context = "C"
        assert_eq!(&tt[0..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(tt[8], b'C');
        // Check second field: idProver = "P"
        assert_eq!(&tt[9..17], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(tt[17], b'P');
    }
}
