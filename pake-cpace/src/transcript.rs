//! Transcript construction and ISK/session-ID derivation per draft-irtf-cfrg-cpace-18.

use alloc::vec::Vec;
use pake_core::crypto::Hash;
use pake_core::encoding::{lv_cat, o_cat};
use pake_core::SharedSecret;

use crate::ciphersuite::CpaceCiphersuite;

/// CPace protocol mode: determines transcript ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpaceMode {
    /// Initiator-responder mode: fixed ordering (Ya first, Yb second).
    InitiatorResponder,
    /// Symmetric mode: ordered concatenation (lexicographic ordering).
    Symmetric,
}

/// Transcript for initiator-responder mode.
///
/// `transcript_ir(Ya, ADa, Yb, ADb) = lv_cat(Ya, ADa) || lv_cat(Yb, ADb)`
pub fn transcript_ir(ya: &[u8], ad_a: &[u8], yb: &[u8], ad_b: &[u8]) -> Vec<u8> {
    let mut result = lv_cat(&[ya, ad_a]);
    result.extend_from_slice(&lv_cat(&[yb, ad_b]));
    result
}

/// Transcript for symmetric (ordered concatenation) mode.
///
/// `transcript_oc(Ya, ADa, Yb, ADb) = o_cat(lv_cat(Ya, ADa), lv_cat(Yb, ADb))`
pub fn transcript_oc(ya: &[u8], ad_a: &[u8], yb: &[u8], ad_b: &[u8]) -> Vec<u8> {
    let part_a = lv_cat(&[ya, ad_a]);
    let part_b = lv_cat(&[yb, ad_b]);
    o_cat(&part_a, &part_b)
}

/// Derive the intermediate session key (ISK).
///
/// ```text
/// DSI_ISK = DSI || "_ISK"
/// ISK = H.hash(lv_cat(DSI_ISK, sid, K) || transcript)
/// ```
pub fn derive_isk<C: CpaceCiphersuite>(
    sid: &[u8],
    k: &[u8],
    ya: &[u8],
    ad_a: &[u8],
    yb: &[u8],
    ad_b: &[u8],
    mode: CpaceMode,
) -> SharedSecret {
    let mut dsi_isk = Vec::from(C::DSI);
    dsi_isk.extend_from_slice(b"_ISK");

    let prefix = lv_cat(&[&dsi_isk, sid, k]);
    let transcript = match mode {
        CpaceMode::InitiatorResponder => transcript_ir(ya, ad_a, yb, ad_b),
        CpaceMode::Symmetric => transcript_oc(ya, ad_a, yb, ad_b),
    };

    let mut hasher = C::Hash::new();
    hasher.update(&prefix);
    hasher.update(&transcript);
    let hash = hasher.finalize();

    SharedSecret::new(hash)
}

/// Derive the optional session ID output.
///
/// ```text
/// sid_output = H.hash(b"CPaceSidOutput" || transcript)
/// ```
pub fn derive_session_id<C: CpaceCiphersuite>(
    ya: &[u8],
    ad_a: &[u8],
    yb: &[u8],
    ad_b: &[u8],
    mode: CpaceMode,
) -> Vec<u8> {
    let transcript = match mode {
        CpaceMode::InitiatorResponder => transcript_ir(ya, ad_a, yb, ad_b),
        CpaceMode::Symmetric => transcript_oc(ya, ad_a, yb, ad_b),
    };

    let mut hasher = C::Hash::new();
    hasher.update(b"CPaceSidOutput");
    hasher.update(&transcript);
    hasher.finalize()
}
