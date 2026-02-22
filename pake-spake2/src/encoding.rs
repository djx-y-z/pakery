//! RFC 9382 transcript encoding.
//!
//! SPAKE2 uses 8-byte little-endian length prefixes (not LEB128).

use alloc::vec::Vec;

/// Encode a length as 8-byte little-endian.
fn encode_le_u64(len: usize) -> [u8; 8] {
    (len as u64).to_le_bytes()
}

/// Append LE64(len) || data to buf.
fn append_lv(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&encode_le_u64(data.len()));
    buf.extend_from_slice(data);
}

/// Build the SPAKE2 transcript TT per RFC 9382 §4.
///
/// ```text
/// TT = len(A)  || A
///   || len(B)  || B
///   || len(S)  || S
///   || len(T)  || T
///   || len(K)  || K
///   || len(w)  || w
/// ```
///
/// Where S = pA, T = pB for the directed case.
pub fn build_transcript(
    identity_a: &[u8],
    identity_b: &[u8],
    pa: &[u8],
    pb: &[u8],
    k: &[u8],
    w: &[u8],
) -> Vec<u8> {
    let mut tt = Vec::new();
    append_lv(&mut tt, identity_a);
    append_lv(&mut tt, identity_b);
    append_lv(&mut tt, pa);
    append_lv(&mut tt, pb);
    append_lv(&mut tt, k);
    append_lv(&mut tt, w);
    tt
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
    fn test_build_transcript_empty_identities() {
        let tt = build_transcript(b"", b"", b"pa", b"pb", b"k", b"w");
        // 6 fields: each has 8-byte length prefix
        // empty + empty + 2 + 2 + 1 + 1 = 6 bytes of data + 6*8 = 48 prefix
        assert_eq!(tt.len(), 48 + 0 + 0 + 2 + 2 + 1 + 1);
    }
}
