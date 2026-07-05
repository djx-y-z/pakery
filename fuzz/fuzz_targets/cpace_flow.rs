//! Fuzz the CPace protocol state machine with adversarial peer messages.
//!
//! Input layout: `[selector][peer share bytes...]`. Selector bits pick the
//! ciphersuite, the CPace mode, and which honest role receives the fuzz
//! bytes as its peer's share.
//!
//! Invariant: the receiving step returns `Ok`/`Err`, never panics — invalid
//! encodings, identity points, and wrong lengths must all surface as `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pakery_cpace::{CpaceCiphersuite, CpaceInitiator, CpaceMode, CpaceResponder};
use pakery_crypto::{CpaceP256, CpaceRistretto255};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

const PASSWORD: &[u8] = b"pakery-fuzz-password";
const CI: &[u8] = b"pakery-fuzz-channel";
const SID: &[u8] = b"pakery-fuzz-sid";
const AD_A: &[u8] = b"ad-initiator";
const AD_B: &[u8] = b"ad-responder";

fn run<C: CpaceCiphersuite>(peer: &[u8], mode: CpaceMode, feed_responder: bool) {
    let mut rng = ChaCha8Rng::seed_from_u64(0x70616b65_72790002);
    if feed_responder {
        // Honest responder receives the fuzz bytes as the initiator's share.
        let _ = CpaceResponder::<C>::respond(peer, PASSWORD, CI, SID, AD_A, AD_B, mode, &mut rng);
    } else {
        // Honest initiator receives the fuzz bytes as the responder's share.
        let (_ya, state) =
            CpaceInitiator::<C>::start(PASSWORD, CI, SID, AD_A, &mut rng).expect("start");
        let _ = state.finish(peer, AD_B, mode);
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&sel, peer)) = input.split_first() else {
        return;
    };
    let mode = if sel & 0x02 == 0 {
        CpaceMode::InitiatorResponder
    } else {
        CpaceMode::Symmetric
    };
    let feed_responder = sel & 0x04 != 0;
    if sel & 0x01 == 0 {
        run::<CpaceRistretto255>(peer, mode, feed_responder);
    } else {
        run::<CpaceP256>(peer, mode, feed_responder);
    }
});
