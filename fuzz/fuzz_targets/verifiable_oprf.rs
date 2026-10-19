//! Structure-aware fuzzing of the RFC 9497 VOPRF and POPRF (pakery-crypto
//! `verifiable_oprf`), both suites.
//!
//! `arbitrary` derives the scenario: suite and mode; a server key derived from
//! a seed or loaded from raw bytes; a batch of one to four inputs; for the
//! POPRF the `info` used at blind, at evaluation and at finalize; optionally a
//! deterministic blind (`hazmat`); optionally a different input at finalize;
//! and optionally one tamper (replace or XOR) of a wire value — the public
//! key, a blinded element, an evaluated element, or the proof.
//!
//! Invariants:
//! - No step ever panics or overflows.
//! - Raw key bytes either load, and then `secret_key()` returns them, or are
//!   rejected as `Deserialize`.
//! - A deterministic blind fails only as `InvalidInput`.
//! - A finalize input other than the blinded one, or a POPRF finalize `info`
//!   other than the one blinded with, fails as `InputMismatch`, whatever else
//!   was tampered — those checks come before anything the server sent is
//!   parsed.
//! - A flow whose wire bytes actually changed never finalizes.
//! - Otherwise, a POPRF whose server evaluated under another `info` fails as
//!   `Verify`, and every other flow finalizes to exactly the server's
//!   `evaluate` of each input.
//!
//! Proof bytes are never compared: the proof nonce is hedged, so only the
//! proof's validity is an oracle.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pakery_crypto::VoprfError;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

#[derive(Arbitrary, Debug)]
enum Key {
    Derive { seed: [u8; 32], info: Vec<u8> },
    Raw([u8; 32]),
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq)]
enum Stage {
    PublicKey,
    Blinded(u8),
    Evaluated(u8),
    Proof,
}

#[derive(Arbitrary, Debug)]
enum TamperMode {
    Replace(Vec<u8>),
    Xor(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct FlowInput {
    suite_p256: bool,
    poprf: bool,
    key: Key,
    seed: u64,
    inputs: Vec<Vec<u8>>,
    blind_info: Vec<u8>,
    server_info: Option<Vec<u8>>,
    finalize_info: Option<Vec<u8>>,
    deterministic_blind: Option<[u8; 64]>,
    finalize_input: Option<(u8, Vec<u8>)>,
    tamper: Option<(Stage, TamperMode)>,
}

fn cap(v: &[u8], n: usize) -> &[u8] {
    &v[..v.len().min(n)]
}

/// Apply the tamper if it targets `stage`; returns the bytes and whether they
/// actually differ from the honest ones.
fn mangle(honest: &[u8], stage: Stage, tamper: &Option<(Stage, TamperMode)>) -> (Vec<u8>, bool) {
    match tamper {
        Some((s, mode)) if *s == stage => {
            let out = match mode {
                TamperMode::Replace(bytes) => cap(bytes, 128).to_vec(),
                TamperMode::Xor(mask) => honest
                    .iter()
                    .zip(mask.iter().chain(core::iter::repeat(&0)))
                    .map(|(b, m)| b ^ m)
                    .collect(),
            };
            let changed = out != honest;
            (out, changed)
        }
        _ => (honest.to_vec(), false),
    }
}

/// Normalize a tamper's element index to the batch, so every tamper lands.
fn normalize(tamper: &Option<(Stage, TamperMode)>, n: usize) -> Option<(Stage, &TamperMode)> {
    tamper.as_ref().map(|(stage, mode)| {
        let stage = match *stage {
            Stage::Blinded(i) => Stage::Blinded((usize::from(i) % n) as u8),
            Stage::Evaluated(i) => Stage::Evaluated((usize::from(i) % n) as u8),
            other => other,
        };
        (stage, mode)
    })
}

macro_rules! flow {
    ($name:ident, server: $server:ty, client: $client:ty, info: [$($info:ident)?]) => {
        fn $name(inp: &FlowInput) {
            let mut inputs: Vec<&[u8]> = inp.inputs.iter().take(4).map(|i| cap(i, 64)).collect();
            if inputs.is_empty() {
                inputs.push(b"");
            }
            let n = inputs.len();
            let blind_info = cap(&inp.blind_info, 32);
            let server_info = inp.server_info.as_deref().map_or(blind_info, |i| cap(i, 32));
            let finalize_info = inp.finalize_info.as_deref().map_or(server_info, |i| cap(i, 32));
            // The three infos are used by the POPRF instantiations only.
            let _ = (blind_info, server_info, finalize_info);
            let tamper = normalize(&inp.tamper, n);
            let tamper = tamper.map(|(stage, mode)| (stage, match mode {
                TamperMode::Replace(b) => TamperMode::Replace(b.clone()),
                TamperMode::Xor(b) => TamperMode::Xor(b.clone()),
            }));
            let mut rng = ChaCha8Rng::seed_from_u64(inp.seed);
            $(let $info = ();)?

            let server = match &inp.key {
                Key::Derive { seed, info } => <$server>::derive(seed, cap(info, 32)).expect("derive"),
                Key::Raw(bytes) => match <$server>::from_secret_key(bytes) {
                    Ok(server) => {
                        assert_eq!(*server.secret_key(), *bytes, "secret key round trip");
                        server
                    }
                    Err(e) => {
                        assert_eq!(e, VoprfError::Deserialize);
                        return;
                    }
                },
            };

            let (pk, mut dirty) = mangle(&server.public_key(), Stage::PublicKey, &tamper);
            let client = match <$client>::new(&pk) {
                Ok(client) => client,
                Err(e) => {
                    assert!(dirty, "honest public key rejected: {e:?}");
                    return;
                }
            };

            let mut states = Vec::new();
            let mut blinded = Vec::new();
            for (i, input) in inputs.iter().enumerate() {
                let result = match &inp.deterministic_blind {
                    Some(bytes) => {
                        let result = client.deterministic_blind(input, $({ let _ = $info; blind_info },)? bytes);
                        if let Err(e) = &result {
                            assert_eq!(*e, VoprfError::InvalidInput, "deterministic blind error");
                            return;
                        }
                        result
                    }
                    None => client.blind(input, $({ let _ = $info; blind_info },)? &mut rng),
                };
                let (state, b) = match result {
                    Ok(v) => v,
                    // Only a tampered public key can make the POPRF tweaked
                    // key the identity; anything else is a bug.
                    Err(e) => {
                        assert!(dirty, "honest blind failed: {e:?}");
                        return;
                    }
                };
                states.push(state);
                let (b, changed) = mangle(&b, Stage::Blinded(i as u8), &tamper);
                dirty |= changed;
                blinded.push(b);
            }

            let (evaluated, proof) = match server.blind_evaluate_batch(
                &blinded,
                $({ let _ = $info; server_info },)?
                &mut rng,
            ) {
                Ok(v) => v,
                Err(e) => {
                    assert!(dirty, "honest evaluation failed: {e:?}");
                    return;
                }
            };
            let mut evaluated_wire = Vec::new();
            for (i, e) in evaluated.iter().enumerate() {
                let (e, changed) = mangle(e, Stage::Evaluated(i as u8), &tamper);
                dirty |= changed;
                evaluated_wire.push(e);
            }
            let (proof, changed) = mangle(&proof, Stage::Proof, &tamper);
            dirty |= changed;

            let mut finalize_inputs = inputs.clone();
            let mut input_changed = false;
            if let Some((i, replacement)) = &inp.finalize_input {
                let i = usize::from(*i) % n;
                let replacement = cap(replacement, 64);
                input_changed = replacement != finalize_inputs[i];
                finalize_inputs[i] = replacement;
            }

            let result = client.finalize_batch(
                &states,
                &finalize_inputs,
                $({ let _ = $info; finalize_info },)?
                &evaluated_wire,
                &proof,
            );
            let caller_mismatch = input_changed $(|| {
                let _ = $info;
                finalize_info != blind_info
            })?;
            if caller_mismatch {
                assert_eq!(result.unwrap_err(), VoprfError::InputMismatch);
                return;
            }
            if dirty {
                assert!(result.is_err(), "a tampered flow finalized");
                return;
            }
            $(
                let _ = $info;
                if finalize_info != server_info {
                    assert_eq!(result.unwrap_err(), VoprfError::Verify);
                    return;
                }
            )?
            let outputs = result.expect("honest finalize");
            for (input, output) in inputs.iter().zip(&outputs) {
                let expected = server
                    .evaluate(input, $({ let _ = $info; finalize_info })?)
                    .expect("evaluate");
                assert_eq!(**output, *expected, "finalize disagrees with evaluate");
            }
        }
    };
}

flow!(voprf_ristretto255, server: pakery_crypto::Ristretto255VoprfServer, client: pakery_crypto::Ristretto255VoprfClient, info: []);
flow!(poprf_ristretto255, server: pakery_crypto::Ristretto255PoprfServer, client: pakery_crypto::Ristretto255PoprfClient, info: [info]);
flow!(voprf_p256, server: pakery_crypto::P256VoprfServer, client: pakery_crypto::P256VoprfClient, info: []);
flow!(poprf_p256, server: pakery_crypto::P256PoprfServer, client: pakery_crypto::P256PoprfClient, info: [info]);

fuzz_target!(|inp: FlowInput| {
    match (inp.suite_p256, inp.poprf) {
        (false, false) => voprf_ristretto255(&inp),
        (false, true) => poprf_ristretto255(&inp),
        (true, false) => voprf_p256(&inp),
        (true, true) => poprf_p256(&inp),
    }
});
