//! Shared OPRF helpers for RFC 9497 base mode implementations.

use alloc::vec;
use alloc::vec::Vec;

use digest::core_api::BlockSizeUser;
use digest::Digest;
use pake_core::PakeError;

/// I2OSP(value, 2) — big-endian 2-byte encoding (RFC 3447 Section 4.1).
pub fn i2osp_2(value: usize) -> Result<[u8; 2], PakeError> {
    u16::try_from(value)
        .map(|v| v.to_be_bytes())
        .map_err(|_| PakeError::InvalidInput("I2OSP: value exceeds 2 bytes"))
}

/// `expand_message_xmd` — RFC 9380 Section 5.3.1.
///
/// `H`: a hash function implementing `Digest + BlockSizeUser`.
/// `msg`: input message as concatenated slices.
/// `dst`: domain separation tag (must be <= 255 bytes).
/// `len_in_bytes`: desired output length.
pub fn expand_message_xmd<H: Digest + BlockSizeUser>(
    msg: &[&[u8]],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Vec<u8>, PakeError> {
    let b_in_bytes = <H as Digest>::output_size();
    let s_in_bytes = <H as BlockSizeUser>::block_size();
    let ell = len_in_bytes.div_ceil(b_in_bytes);

    if ell > 255 || len_in_bytes == 0 || len_in_bytes > 65535 || dst.len() > 255 {
        return Err(PakeError::InvalidInput(
            "expand_message_xmd: invalid parameters",
        ));
    }

    let l_i_b_str = i2osp_2(len_in_bytes)?;
    let dst_len_byte = dst.len() as u8;

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0,1) || DST_prime)
    let mut h0 = H::new();
    h0.update(vec![0u8; s_in_bytes]); // Z_pad
    for m in msg {
        h0.update(m);
    }
    h0.update(l_i_b_str);
    h0.update([0u8]); // I2OSP(0, 1)
    h0.update(dst);
    h0.update([dst_len_byte]);
    let b_0 = h0.finalize();

    // b_1 = H(b_0 || I2OSP(1,1) || DST_prime)
    let mut h1 = H::new();
    h1.update(&b_0);
    h1.update([1u8]);
    h1.update(dst);
    h1.update([dst_len_byte]);
    let b_1 = h1.finalize();

    let mut uniform_bytes = Vec::with_capacity(ell * b_in_bytes);
    uniform_bytes.extend_from_slice(&b_1);

    let mut b_prev = b_1;
    for i in 2..=ell {
        let mut h = H::new();
        // strxor(b_0, b_{i-1})
        for (a, b) in b_0.iter().zip(b_prev.iter()) {
            h.update([a ^ b]);
        }
        h.update([i as u8]);
        h.update(dst);
        h.update([dst_len_byte]);
        b_prev = h.finalize();
        uniform_bytes.extend_from_slice(&b_prev);
    }

    uniform_bytes.truncate(len_in_bytes);
    Ok(uniform_bytes)
}

/// Finalize the OPRF output (RFC 9497 Section 3.3.1).
///
/// ```text
/// Output = Hash(I2OSP(len(input),2) || input || I2OSP(len(element),2) || element || "Finalize")
/// ```
pub fn finalize_hash<H: Digest>(input: &[u8], element_bytes: &[u8]) -> Result<Vec<u8>, PakeError> {
    let input_len = i2osp_2(input.len())?;
    let elem_len = i2osp_2(element_bytes.len())?;

    let mut h = H::new();
    h.update(input_len);
    h.update(input);
    h.update(elem_len);
    h.update(element_bytes);
    h.update(b"Finalize");
    Ok(h.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn i2osp_2_basic() {
        assert_eq!(i2osp_2(0).unwrap(), [0x00, 0x00]);
        assert_eq!(i2osp_2(1).unwrap(), [0x00, 0x01]);
        assert_eq!(i2osp_2(256).unwrap(), [0x01, 0x00]);
        assert_eq!(i2osp_2(65535).unwrap(), [0xFF, 0xFF]);
    }

    #[test]
    fn i2osp_2_overflow() {
        assert!(i2osp_2(65536).is_err());
    }

    #[test]
    fn expand_message_xmd_rejects_zero_length() {
        assert!(expand_message_xmd::<sha2::Sha256>(&[b"msg"], b"dst", 0).is_err());
    }

    #[test]
    fn expand_message_xmd_rejects_long_dst() {
        let long_dst = [0u8; 256];
        assert!(expand_message_xmd::<sha2::Sha256>(&[b"msg"], &long_dst, 32).is_err());
    }

    // ======================================================================
    // RFC 9380 Section K.1 — expand_message_xmd(SHA-256)
    // DST = "QUUX-V01-CS02-with-expander-SHA256-128"
    // ======================================================================

    const SHA256_DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";

    #[test]
    fn rfc9380_sha256_xmd_empty_32() {
        let result = expand_message_xmd::<sha2::Sha256>(&[b""], SHA256_DST, 0x20).unwrap();
        assert_eq!(
            result,
            hex("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
        );
    }

    #[test]
    fn rfc9380_sha256_xmd_abc_32() {
        let result = expand_message_xmd::<sha2::Sha256>(&[b"abc"], SHA256_DST, 0x20).unwrap();
        assert_eq!(
            result,
            hex("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615")
        );
    }

    #[test]
    fn rfc9380_sha256_xmd_abcdef_32() {
        let result =
            expand_message_xmd::<sha2::Sha256>(&[b"abcdef0123456789"], SHA256_DST, 0x20).unwrap();
        assert_eq!(
            result,
            hex("eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1")
        );
    }

    #[test]
    fn rfc9380_sha256_xmd_q128_32() {
        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let result = expand_message_xmd::<sha2::Sha256>(&[msg], SHA256_DST, 0x20).unwrap();
        assert_eq!(
            result,
            hex("b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9")
        );
    }

    #[test]
    fn rfc9380_sha256_xmd_a512_32() {
        let mut msg = Vec::with_capacity(517);
        msg.extend_from_slice(b"a512_");
        msg.extend(core::iter::repeat(b'a').take(512));
        let result = expand_message_xmd::<sha2::Sha256>(&[&msg], SHA256_DST, 0x20).unwrap();
        assert_eq!(
            result,
            hex("4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c")
        );
    }

    #[test]
    fn rfc9380_sha256_xmd_empty_128() {
        let result = expand_message_xmd::<sha2::Sha256>(&[b""], SHA256_DST, 0x80).unwrap();
        assert_eq!(
            result,
            hex("af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced")
        );
    }

    #[test]
    fn rfc9380_sha256_xmd_abc_128() {
        let result = expand_message_xmd::<sha2::Sha256>(&[b"abc"], SHA256_DST, 0x80).unwrap();
        assert_eq!(
            result,
            hex("abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40")
        );
    }

    // ======================================================================
    // RFC 9380 Section K.3 — expand_message_xmd(SHA-512)
    // DST = "QUUX-V01-CS02-with-expander-SHA512-256"
    // ======================================================================

    const SHA512_DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA512-256";

    #[test]
    fn rfc9380_sha512_xmd_empty_32() {
        let result = expand_message_xmd::<sha2::Sha512>(&[b""], SHA512_DST, 0x20).unwrap();
        assert_eq!(
            result,
            hex("6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba")
        );
    }

    #[test]
    fn rfc9380_sha512_xmd_abc_32() {
        let result = expand_message_xmd::<sha2::Sha512>(&[b"abc"], SHA512_DST, 0x20).unwrap();
        assert_eq!(
            result,
            hex("0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc")
        );
    }

    #[test]
    fn rfc9380_sha512_xmd_abcdef_32() {
        let result =
            expand_message_xmd::<sha2::Sha512>(&[b"abcdef0123456789"], SHA512_DST, 0x20).unwrap();
        assert_eq!(
            result,
            hex("087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58")
        );
    }

    #[test]
    fn rfc9380_sha512_xmd_empty_128() {
        let result = expand_message_xmd::<sha2::Sha512>(&[b""], SHA512_DST, 0x80).unwrap();
        assert_eq!(
            result,
            hex("41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961")
        );
    }

    #[test]
    fn rfc9380_sha512_xmd_abc_128() {
        let result = expand_message_xmd::<sha2::Sha512>(&[b"abc"], SHA512_DST, 0x80).unwrap();
        assert_eq!(
            result,
            hex("7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b488431851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1")
        );
    }

    #[test]
    fn rfc9380_sha512_xmd_q128_32() {
        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let result = expand_message_xmd::<sha2::Sha512>(&[msg], SHA512_DST, 0x20).unwrap();
        assert_eq!(
            result,
            hex("7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3")
        );
    }

    #[test]
    fn rfc9380_sha512_xmd_a512_128() {
        let mut msg = Vec::with_capacity(517);
        msg.extend_from_slice(b"a512_");
        msg.extend(core::iter::repeat(b'a').take(512));
        let result = expand_message_xmd::<sha2::Sha512>(&[&msg], SHA512_DST, 0x80).unwrap();
        assert_eq!(
            result,
            hex("05b0bfef265dcee87654372777b7c44177e2ae4c13a27f103340d9cd11c86cb2426ffcad5bd964080c2aee97f03be1ca18e30a1f14e27bc11ebbd650f305269cc9fb1db08bf90bfc79b42a952b46daf810359e7bc36452684784a64952c343c52e5124cd1f71d474d5197fefc571a92929c9084ffe1112cf5eea5192ebff330b")
        );
    }
}
