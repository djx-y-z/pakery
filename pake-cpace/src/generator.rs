//! Generator calculation per draft-irtf-cfrg-cpace-18.
//!
//! ```text
//! generator_string(DSI, PRS, CI, sid, s_in_bytes):
//!     len_zpad = max(0, s_in_bytes - 1 - len(prepend_len(PRS)) - len(prepend_len(DSI)))
//!     return lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)
//!
//! calculate_generator(PRS, CI, sid):
//!     gen_str = generator_string(DSI, PRS, CI, sid, H.s_in_bytes)
//!     gen_str_hash = H.hash(gen_str, 2 * field_size_bytes)
//!     return element_derivation(gen_str_hash)
//! ```

use alloc::vec;
use alloc::vec::Vec;
use digest::Digest;
use pake_core::encoding::{lv_cat, prepend_len};

use crate::ciphersuite::CpaceCiphersuite;

/// Build the generator string per the CPace specification.
///
/// Returns the concatenation `lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)`.
pub fn generator_string<C: CpaceCiphersuite>(password: &[u8], ci: &[u8], sid: &[u8]) -> Vec<u8> {
    let s_in_bytes = C::HASH_BLOCK_SIZE;
    let prepend_len_dsi_len = prepend_len(C::DSI).len();
    let prepend_len_prs_len = prepend_len(password).len();

    let len_zpad = s_in_bytes
        .saturating_sub(1)
        .saturating_sub(prepend_len_prs_len)
        .saturating_sub(prepend_len_dsi_len);

    let zpad = vec![0u8; len_zpad];
    lv_cat(&[C::DSI, password, &zpad, ci, sid])
}

/// Calculate the CPace generator from password, channel identifier, and session ID.
///
/// Hashes the generator string and maps the result to a group element.
pub fn calculate_generator<C: CpaceCiphersuite>(
    password: &[u8],
    ci: &[u8],
    sid: &[u8],
) -> C::Group {
    let gen_str = generator_string::<C>(password, ci, sid);
    let hash_output = C::Hash::digest(&gen_str);
    C::element_derivation(hash_output.as_ref())
}
