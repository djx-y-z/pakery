//! Key schedule and output per RFC 9382 §4.

use alloc::vec::Vec;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use pake_core::crypto::{Hash, Kdf, Mac};
use pake_core::SharedSecret;

use crate::ciphersuite::Spake2Ciphersuite;
use crate::error::Spake2Error;

/// Output of a completed SPAKE2 protocol run.
///
/// Contains the session key and confirmation MACs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Spake2Output {
    /// The session key (Ke, second half of the hash).
    #[zeroize(skip)]
    pub session_key: SharedSecret,
    /// This party's confirmation MAC to send to the peer.
    pub confirmation_mac: Vec<u8>,
    /// The expected MAC from the peer.
    expected_peer_mac: Vec<u8>,
}

impl Spake2Output {
    /// Verify the peer's confirmation MAC in constant time.
    pub fn verify_peer_confirmation(&self, peer_mac: &[u8]) -> Result<(), Spake2Error> {
        if self.expected_peer_mac.ct_eq(peer_mac).into() {
            Ok(())
        } else {
            Err(Spake2Error::ConfirmationFailed)
        }
    }
}

/// Derive the key schedule from transcript TT.
///
/// Per RFC 9382 §4:
/// 1. `Ka || Ke = Hash(TT)` (first NH/2 = Ka, second NH/2 = Ke)
/// 2. `PRK = KDF.extract(salt=[], ikm=Ka)`
/// 3. `KcA || KcB = KDF.expand(PRK, "ConfirmationKeys" || AAD, NH)`
/// 4. `cA = MAC(KcA, TT)`, `cB = MAC(KcB, TT)`
pub fn derive_key_schedule<C: Spake2Ciphersuite>(
    tt: &[u8],
    aad: &[u8],
    is_party_a: bool,
) -> Result<Spake2Output, Spake2Error> {
    // Step 1: Hash(TT) → Ka || Ke
    let hash_tt = C::Hash::digest(tt);
    let half = C::NH / 2;
    if hash_tt.len() < C::NH {
        return Err(Spake2Error::InternalError("hash output too short"));
    }
    let ka = &hash_tt[..half];
    let ke = &hash_tt[half..C::NH];

    // Step 2: PRK = KDF.extract(salt=[], ikm=Ka)
    let prk = C::Kdf::extract(&[], ka);

    // Step 3: KcA || KcB = KDF.expand(PRK, "ConfirmationKeys" || AAD, NH)
    let mut info = Vec::from(b"ConfirmationKeys" as &[u8]);
    info.extend_from_slice(aad);
    let kc = C::Kdf::expand(&prk, &info, C::NH)
        .map_err(|_| Spake2Error::InternalError("KDF expand failed"))?;
    let kc_a = &kc[..half];
    let kc_b = &kc[half..C::NH];

    // Step 4: cA = MAC(KcA, TT), cB = MAC(KcB, TT)
    let mac_a =
        C::Mac::mac(kc_a, tt).map_err(|_| Spake2Error::InternalError("MAC computation failed"))?;
    let mac_b =
        C::Mac::mac(kc_b, tt).map_err(|_| Spake2Error::InternalError("MAC computation failed"))?;

    let session_key = SharedSecret::new(ke.to_vec());

    if is_party_a {
        Ok(Spake2Output {
            session_key,
            confirmation_mac: mac_a,
            expected_peer_mac: mac_b,
        })
    } else {
        Ok(Spake2Output {
            session_key,
            confirmation_mac: mac_b,
            expected_peer_mac: mac_a,
        })
    }
}
