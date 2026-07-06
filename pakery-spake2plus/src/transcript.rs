//! Key schedule and output per RFC 9383 section 3.4.

use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use pakery_core::crypto::{Hash, Kdf, Mac};
use pakery_core::SharedSecret;

use crate::ciphersuite::Spake2PlusCiphersuite;
use crate::error::Spake2PlusError;

/// Output of a completed SPAKE2+ protocol run.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Spake2PlusOutput {
    /// The shared session key (K_shared).
    #[zeroize(skip)]
    pub session_key: SharedSecret,
}

impl Spake2PlusOutput {
    /// Consume the output and yield the session key.
    ///
    /// Because [`Spake2PlusOutput`] derives `ZeroizeOnDrop`, it cannot be
    /// pattern-destructured by the caller. This consumer extracts the
    /// session key cleanly without the boilerplate `mem::replace` shim.
    #[must_use]
    pub fn into_session_key(mut self) -> SharedSecret {
        core::mem::replace(&mut self.session_key, SharedSecret::new(Vec::new()))
    }
}

/// Key schedule derived from the SPAKE2+ transcript.
///
/// Contains confirmation keys, MACs, and the shared session key.
pub(crate) struct KeySchedule {
    pub confirm_p: Vec<u8>,
    pub confirm_v: Vec<u8>,
    pub session_key: SharedSecret,
}

impl Zeroize for KeySchedule {
    fn zeroize(&mut self) {
        self.confirm_p.zeroize();
        self.confirm_v.zeroize();
        // SharedSecret also zeroizes on its own drop; clearing it here keeps
        // `zeroize()` exhaustive over every secret field.
        self.session_key.zeroize();
    }
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Derive the key schedule from transcript TT.
///
/// Per RFC 9383 section 3.4:
/// 1. `K_main = Hash(TT)` (full NH-byte hash output)
/// 2. `PRK = KDF.extract(salt=[], ikm=K_main)`
/// 3. `K_confirmP || K_confirmV = KDF.expand(PRK, "ConfirmationKeys", 2*NH)`
/// 4. `K_shared = KDF.expand(PRK, "SharedKey", NH)`
/// 5. `confirmV = MAC(K_confirmV, shareP)`, `confirmP = MAC(K_confirmP, shareV)`
pub(crate) fn derive_key_schedule<C: Spake2PlusCiphersuite>(
    tt: &[u8],
    share_p: &[u8],
    share_v: &[u8],
) -> Result<KeySchedule, Spake2PlusError> {
    // Step 1: K_main = Hash(TT)
    const { assert!(<C::Hash as pakery_core::crypto::Hash>::OUTPUT_SIZE >= C::NH) };
    let k_main = Zeroizing::new(C::Hash::digest(tt));

    // Step 2: PRK = KDF.extract(salt=[], ikm=K_main)
    let prk = C::Kdf::extract(&[], &k_main[..C::NH]);

    // Step 3: K_confirmP || K_confirmV = KDF.expand(PRK, "ConfirmationKeys", 2*NH)
    let kc = C::Kdf::expand(&prk, b"ConfirmationKeys", 2 * C::NH)
        .map_err(|_| Spake2PlusError::InternalError("KDF expand failed for ConfirmationKeys"))?;
    let k_confirm_p = &kc[..C::NH];
    let k_confirm_v = &kc[C::NH..2 * C::NH];

    // Step 4: K_shared = KDF.expand(PRK, "SharedKey", NH)
    let mut k_shared = C::Kdf::expand(&prk, b"SharedKey", C::NH)
        .map_err(|_| Spake2PlusError::InternalError("KDF expand failed for SharedKey"))?;

    // Step 5: confirmV = MAC(K_confirmV, shareP), confirmP = MAC(K_confirmP, shareV)
    // Note: MACs are over the *peer's* share
    let confirm_v = C::Mac::mac(k_confirm_v, share_p)
        .map_err(|_| Spake2PlusError::InternalError("MAC computation failed"))?;
    let confirm_p = C::Mac::mac(k_confirm_p, share_v)
        .map_err(|_| Spake2PlusError::InternalError("MAC computation failed"))?;

    Ok(KeySchedule {
        confirm_p,
        confirm_v,
        session_key: SharedSecret::new(core::mem::take(&mut *k_shared)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Calling `.zeroize()` on a live value must clear every secret field
    /// (roadmap item 7: catches a future field added without zeroization).
    /// `session_key` is `#[zeroize(skip)]` by design: `SharedSecret` zeroizes
    /// itself on its own drop, so it must survive the struct-level call.
    #[test]
    fn output_zeroize_leaves_self_zeroizing_session_key() {
        let mut output = Spake2PlusOutput {
            session_key: SharedSecret::new(vec![0xAA; 32]),
        };
        output.zeroize();
        // Skipped field is untouched (self-zeroizing on its own drop).
        assert_eq!(output.session_key.as_bytes(), &[0xAA; 32]);
    }

    /// The manual `Zeroize` impl (called from `Drop`) must clear every
    /// secret field of the key schedule.
    #[test]
    fn key_schedule_zeroize_clears_all_secret_fields() {
        let mut ks = KeySchedule {
            confirm_p: vec![0xAA; 64],
            confirm_v: vec![0xBB; 64],
            session_key: SharedSecret::new(vec![0xCC; 32]),
        };
        ks.zeroize();
        assert!(ks.confirm_p.is_empty());
        assert!(ks.confirm_v.is_empty());
        assert!(ks.session_key.as_bytes().is_empty());
    }
}
