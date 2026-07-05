//! Fuzz the SPAKE2+ protocol state machine with adversarial peer messages.
//!
//! Input layout: `[selector][cut][peer bytes...]`. Selector bits pick the
//! ciphersuite and which honest step receives the fuzz bytes:
//! - verifier receives a fuzz `shareP`;
//! - prover receives fuzz `shareV` + `confirmV` (split at `cut`);
//! - verifier receives a fuzz `confirmP`.
//!
//! Invariants:
//! - Every receiving step returns `Ok`/`Err`, never panics.
//! - Fuzz-supplied confirmation MACs must never verify: forging them
//!   requires breaking the MAC, so an `Ok` there is a real break.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pakery_core::crypto::{CpaceGroup, Hash};
use pakery_crypto::{Sha512Hash, Spake2PlusP256, Spake2PlusRistretto255};
use pakery_spake2plus::{compute_verifier, Prover, Spake2PlusCiphersuite, Verifier};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

const CONTEXT: &[u8] = b"fuzz-context";
const ID_P: &[u8] = b"fuzz-prover";
const ID_V: &[u8] = b"fuzz-verifier";

type Scalar<C> = <<C as Spake2PlusCiphersuite>::Group as CpaceGroup>::Scalar;

fn pw_scalars<C: Spake2PlusCiphersuite>() -> (Scalar<C>, Scalar<C>) {
    let mut h0 = Sha512Hash::new();
    h0.update(b"pakery-fuzz-password");
    h0.update(b"w0");
    let w0 = <C::Group as CpaceGroup>::scalar_from_wide_bytes(&h0.finalize()).expect("64 bytes");
    let mut h1 = Sha512Hash::new();
    h1.update(b"pakery-fuzz-password");
    h1.update(b"w1");
    let w1 = <C::Group as CpaceGroup>::scalar_from_wide_bytes(&h1.finalize()).expect("64 bytes");
    (w0, w1)
}

fn run<C: Spake2PlusCiphersuite>(which: u8, cut: u8, peer: &[u8]) {
    let (w0, w1) = pw_scalars::<C>();
    let l_bytes = compute_verifier::<C>(&w1);
    let mut rng = ChaCha8Rng::seed_from_u64(0x70616b65_72790004);

    match which {
        0 => {
            // Honest verifier receives the fuzz bytes as shareP.
            let _ = Verifier::<C>::start(peer, &w0, &l_bytes, CONTEXT, ID_P, ID_V, &mut rng);
        }
        1 => {
            // Honest prover receives fuzz shareV + confirmV.
            let (_share_p, state) =
                Prover::<C>::start(&w0, &w1, CONTEXT, ID_P, ID_V, &mut rng).expect("prover start");
            let (share_v, confirm_v) = peer.split_at(cut as usize % (peer.len() + 1));
            assert!(
                state.finish(share_v, confirm_v).is_err(),
                "fuzzer forged a confirmV MAC"
            );
        }
        _ => {
            // Honest verifier receives a fuzz confirmP.
            let (share_p, _state) =
                Prover::<C>::start(&w0, &w1, CONTEXT, ID_P, ID_V, &mut rng).expect("prover start");
            let (_share_v, _confirm_v, verifier_state) =
                Verifier::<C>::start(&share_p, &w0, &l_bytes, CONTEXT, ID_P, ID_V, &mut rng)
                    .expect("verifier start");
            assert!(
                verifier_state.finish(peer).is_err(),
                "fuzzer forged a confirmP MAC"
            );
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let [sel, cut, peer @ ..] = input else {
        return;
    };
    let which = (sel >> 1) % 3;
    if sel & 0x01 == 0 {
        run::<Spake2PlusRistretto255>(which, *cut, peer);
    } else {
        run::<Spake2PlusP256>(which, *cut, peer);
    }
});
