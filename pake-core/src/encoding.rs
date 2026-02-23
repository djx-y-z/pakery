//! Encoding utilities: LEB128, length-value concatenation, and ordered concatenation.
//!
//! These implement the encoding functions specified in draft-irtf-cfrg-cpace.

use alloc::vec::Vec;

/// Encode a `usize` value using unsigned LEB128 encoding.
pub fn leb128_encode(mut value: usize) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if value == 0 {
            break;
        }
    }
    result
}

/// Prepend the LEB128-encoded length of `data` to `data`.
///
/// Returns `len(data) || data` where `len()` uses unsigned LEB128.
pub fn prepend_len(data: &[u8]) -> Vec<u8> {
    let mut result = leb128_encode(data.len());
    result.extend_from_slice(data);
    result
}

/// Length-value concatenation: concatenate `prepend_len(arg)` for each argument.
pub fn lv_cat(args: &[&[u8]]) -> Vec<u8> {
    let mut result = Vec::new();
    for arg in args {
        result.extend_from_slice(&prepend_len(arg));
    }
    result
}

/// Ordered concatenation of two byte slices.
///
/// If `a > b` lexicographically: returns `b"oc" || a || b`
/// Otherwise: returns `b"oc" || b || a`
///
/// # Security
///
/// The lexicographic comparison (`a > b`) is **not** constant-time. This is
/// intentional: the inputs are public protocol messages (party identifiers or
/// key shares) that are already visible to any network observer, so the
/// comparison does not leak secret information.
pub fn o_cat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(2 + a.len() + b.len());
    result.extend_from_slice(b"oc");
    if a > b {
        result.extend_from_slice(a);
        result.extend_from_slice(b);
    } else {
        result.extend_from_slice(b);
        result.extend_from_slice(a);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leb128_zero() {
        assert_eq!(leb128_encode(0), vec![0x00]);
    }

    #[test]
    fn test_leb128_small() {
        assert_eq!(leb128_encode(4), vec![0x04]);
        assert_eq!(leb128_encode(127), vec![0x7F]);
    }

    #[test]
    fn test_leb128_128() {
        assert_eq!(leb128_encode(128), vec![0x80, 0x01]);
    }

    #[test]
    fn test_prepend_len_empty() {
        assert_eq!(prepend_len(b""), vec![0x00]);
    }

    #[test]
    fn test_prepend_len_four() {
        assert_eq!(prepend_len(b"1234"), vec![0x04, 0x31, 0x32, 0x33, 0x34]);
    }

    #[test]
    fn test_prepend_len_128_bytes() {
        let data: Vec<u8> = (0..128u8).collect();
        let result = prepend_len(&data);
        assert_eq!(result[0], 0x80);
        assert_eq!(result[1], 0x01);
        assert_eq!(&result[2..], &data[..]);
    }

    #[test]
    fn test_lv_cat() {
        let result = lv_cat(&[b"1234", b"5", b"", b"678"]);
        let expected: Vec<u8> = vec![
            0x04, 0x31, 0x32, 0x33, 0x34, // prepend_len("1234")
            0x01, 0x35, // prepend_len("5")
            0x00, // prepend_len("")
            0x03, 0x36, 0x37, 0x38, // prepend_len("678")
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_o_cat_a_greater() {
        // "b" > "a" is false, "a" > "b" is false => a <= b => oc || b || a
        let result = o_cat(b"a", b"b");
        assert_eq!(result, b"ocba");
    }

    #[test]
    fn test_o_cat_b_greater() {
        let result = o_cat(b"b", b"a");
        assert_eq!(result, b"ocba");
    }

    #[test]
    fn test_o_cat_equal() {
        let result = o_cat(b"x", b"x");
        assert_eq!(result, b"ocxx");
    }
}
