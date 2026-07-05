//! Fuzz the SPAKE2 protocol state machine with adversarial peer messages.
//!
//! Input layout: `[selector][peer bytes...]`. The peer bytes are split into
//! a peer share (first `share_len` bytes) and a claimed confirmation MAC
//! (the rest). Selector bits pick the ciphersuite and the honest role.
//!
//! Invariants:
//! - `finish` returns `Ok`/`Err`, never panics.
//! - If the fuzz share decodes, the fuzz confirmation MAC must still fail
//!   verification: without the password scalar `w`, forging an
//!   HMAC-over-transcript confirmation is computationally impossible, so a
//!   passing verification here is a real break.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pakery_core::crypto::{CpaceGroup, Hash};
use pakery_crypto::{Sha512Hash, Spake2P256, Spake2Ristretto255};
use pakery_spake2::{PartyA, PartyB, Spake2Ciphersuite};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

const ID_A: &[u8] = b"fuzz-alice";
const ID_B: &[u8] = b"fuzz-bob";
const AAD: &[u8] = b"fuzz-aad";

fn run<C: Spake2Ciphersuite>(peer: &[u8], role_a: bool) {
    let digest = Sha512Hash::digest(b"pakery-fuzz-password");
    let w = <C::Group as CpaceGroup>::scalar_from_wide_bytes(&digest).expect("64-byte digest");
    let mut rng = ChaCha8Rng::seed_from_u64(0x70616b65_72790003);

    if role_a {
        let (pa, state) = PartyA::<C>::start(&w, ID_A, ID_B, AAD, &mut rng).expect("start A");
        let (share, mac) = peer.split_at(pa.len().min(peer.len()));
        if let Ok(out) = state.finish(share) {
            assert!(
                out.verify_peer_confirmation(mac).is_err(),
                "fuzzer forged a party-B confirmation MAC"
            );
        }
    } else {
        let (pb, state) = PartyB::<C>::start(&w, ID_A, ID_B, AAD, &mut rng).expect("start B");
        let (share, mac) = peer.split_at(pb.len().min(peer.len()));
        if let Ok(out) = state.finish(share) {
            assert!(
                out.verify_peer_confirmation(mac).is_err(),
                "fuzzer forged a party-A confirmation MAC"
            );
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&sel, peer)) = input.split_first() else {
        return;
    };
    let role_a = sel & 0x02 != 0;
    if sel & 0x01 == 0 {
        run::<Spake2Ristretto255>(peer, role_a);
    } else {
        run::<Spake2P256>(peer, role_a);
    }
});
