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

/// Key schedule derived from the SPAKE2+ transcript.
///
/// Contains confirmation keys, MACs, and the shared session key.
pub(crate) struct KeySchedule {
    pub confirm_p: Vec<u8>,
    pub confirm_v: Vec<u8>,
    pub session_key: SharedSecret,
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        self.confirm_p.zeroize();
        self.confirm_v.zeroize();
        // session_key has its own ZeroizeOnDrop via SharedSecret
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
