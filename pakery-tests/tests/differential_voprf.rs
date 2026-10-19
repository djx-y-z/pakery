//! Differential testing of pakery-crypto's RFC 9497 VOPRF and POPRF against
//! `voprf` 0.5, the RFC 9497 implementation `opaque-ke` builds on.
//!
//! Both suites (ristretto255-SHA512, P256-SHA256) and both modes run on
//! identical inputs. Byte-compared, for every case:
//!
//! - `DeriveKeyPair`: the secret and the public key;
//! - the blinded elements, from identical RNG bytes;
//! - the evaluated elements, single and batched;
//! - the PRF output, four ways — each implementation's client finalizing each
//!   implementation's proof — against both servers' `Evaluate`.
//!
//! # How inputs are forced equal
//!
//! Both sides draw a blind with the same byte pattern: 64 bytes reduced modulo
//! the order for ristretto255, the first canonical nonzero 32-byte candidate
//! for P-256. A [`PlannedRng`] serves each call exactly the chunk planned for
//! it, panics on any other request, and checks on drop that nothing planned was
//! left over, so a change in either side's consumption fails loudly instead of
//! desynchronizing the comparison. Keys come from `derive` / `new_from_seed`
//! on both sides.
//!
//! # What is not compared, and why
//!
//! - **Proof bytes.** pakery hedges the proof nonce with the key and the
//!   statement (its `verifiable_oprf` documentation, after RFC 9591 §4.1), so
//!   its proofs differ from `voprf`'s even on equal RNG bytes. Each client
//!   verifying the other's proof is the comparison that matters: it fails
//!   unless both build the same composite and challenge transcripts. The
//!   proof bytes themselves are pinned by the RFC vectors in pakery-crypto.
//! - **`generate` against `VoprfServer::new`.** `voprf` derives a random key
//!   through `DeriveKeyPair` on an RNG seed; pakery's `generate` is
//!   `GenerateKeyPair` (§3.2). Both are conformant and not comparable.
//! - **Malformed input.** `voprf` is not an oracle for rejection: its
//!   deserializers ignore trailing bytes, and its P-256 path decompacts SEC1
//!   `0x05` encodings and zero-pads short keys in `new_with_key`. pakery's
//!   rejections are pinned by its own unit tests and the negative vectors.
//!
//! # Known divergences, pinned below
//!
//! - A proof with `c` or `s` zero: `voprf` rejects it while deserializing;
//!   pakery parses it (RFC 9497 §4: `DeserializeScalar` accepts `[0, p - 1]`)
//!   and fails verification.
//! - `voprf`'s POPRF `evaluate(input, None)` leaves the `info` framing out of
//!   the hash while its own `finalize(.., None)` puts it in. With `Some(info)`
//!   — `Some(b"")` included — both agree with pakery, so this suite always
//!   passes `Some`.

#![cfg(feature = "differential")]

use std::collections::VecDeque;
use std::convert::Infallible;

use opaque_ke::rand::{CryptoRng as KeCryptoRng, Error as KeRngError, RngCore as KeRngCore};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use voprf::{BlindedElement, EvaluationElement, Group as _, Proof};

type VoprfP256 = p256_013::NistP256;

/// An RNG that serves exactly the planned chunks, one per call. Each call must
/// ask for exactly the next chunk's length; word draws are refused. On drop it
/// checks that every planned chunk was consumed.
struct PlannedRng {
    chunks: VecDeque<Vec<u8>>,
}

impl PlannedRng {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks: chunks.into(),
        }
    }

    fn serve(&mut self, dest: &mut [u8]) {
        let chunk = self
            .chunks
            .pop_front()
            .expect("RNG drawn more often than planned");
        assert_eq!(chunk.len(), dest.len(), "RNG draw length differs from plan");
        dest.copy_from_slice(&chunk);
    }
}

impl Drop for PlannedRng {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(self.chunks.is_empty(), "planned RNG chunks left unconsumed");
        }
    }
}

// pakery-crypto side: rand_core 0.10.
impl rand_core::TryRng for PlannedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        panic!("word draw not planned")
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        panic!("word draw not planned")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.serve(dest);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for PlannedRng {}

// voprf side: rand_core 0.6, reached through opaque-ke's re-export — the same
// rand_core 0.6.4 that voprf bounds on, so a split would fail to compile.
impl KeRngCore for PlannedRng {
    fn next_u32(&mut self) -> u32 {
        panic!("word draw not planned")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("word draw not planned")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.serve(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), KeRngError> {
        self.serve(dest);
        Ok(())
    }
}

impl KeCryptoRng for PlannedRng {}

/// One differential case, drawn from a seed.
struct Case {
    key_seed: [u8; 32],
    key_info: Vec<u8>,
    inputs: Vec<Vec<u8>>,
    info: Vec<u8>,
    /// Per input, the bytes the blind is drawn from.
    blinds: Vec<Vec<u8>>,
    /// pakery's hedge randomness.
    hedge: Vec<u8>,
    /// voprf's proof nonce draw.
    their_nonce: Vec<u8>,
}

/// P-256 order, big-endian.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// A scalar draw both sides accept on the first try: 64 bytes for
/// ristretto255 (reduced; zero has probability 2^-252), and for P-256 a
/// 32-byte big-endian value in `[1, n)` so neither rejection loop redraws.
fn scalar_draw(rng: &mut ChaCha20Rng, p256: bool) -> Vec<u8> {
    if !p256 {
        let mut wide = vec![0u8; 64];
        rng.fill_bytes(&mut wide);
        return wide;
    }
    loop {
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        if bytes.as_slice() < P256_ORDER.as_slice() && bytes.iter().any(|&b| b != 0) {
            return bytes;
        }
    }
}

fn random_bytes(rng: &mut ChaCha20Rng, max_len: usize) -> Vec<u8> {
    let len = (rng.next_u32() as usize) % (max_len + 1);
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn case(seed: u64, batch: usize, p256: bool) -> Case {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut key_seed = [0u8; 32];
    rng.fill_bytes(&mut key_seed);
    let key_info = random_bytes(&mut rng, 16);
    let inputs = (0..batch).map(|_| random_bytes(&mut rng, 64)).collect();
    let info = random_bytes(&mut rng, 32);
    let blinds = (0..batch).map(|_| scalar_draw(&mut rng, p256)).collect();
    let mut hedge = vec![0u8; 32];
    rng.fill_bytes(&mut hedge);
    let their_nonce = scalar_draw(&mut rng, p256);
    Case {
        key_seed,
        key_info,
        inputs,
        info,
        blinds,
        hedge,
        their_nonce,
    }
}

/// The RFC 9497 Appendix A key material, with the vectors' inputs and info,
/// as a fixed case alongside the random ones.
fn rfc_like_case(p256: bool) -> Case {
    let mut rng = ChaCha20Rng::seed_from_u64(9497);
    Case {
        key_seed: [0xa3; 32],
        key_info: b"test key".to_vec(),
        inputs: vec![vec![0x00], vec![0x5a; 17]],
        info: b"test info".to_vec(),
        blinds: (0..2).map(|_| scalar_draw(&mut rng, p256)).collect(),
        hedge: vec![0x42; 32],
        their_nonce: scalar_draw(&mut rng, p256),
    }
}

/// The comparison for one suite and the VOPRF.
macro_rules! voprf_differential {
    ($name:ident, server: $server:ty, client: $client:ty, suite: $cs:ty, p256: $p256:expr) => {
        fn $name(case: &Case) {
            type Cs = $cs;
            let ours = <$server>::derive(&case.key_seed, &case.key_info).unwrap();
            let theirs =
                voprf::VoprfServer::<Cs>::new_from_seed(&case.key_seed, &case.key_info).unwrap();
            let theirs_serialized = theirs.serialize();
            assert_eq!(ours.secret_key().as_slice(), &theirs_serialized[..32]);
            let pk = ours.public_key();
            assert_eq!(
                pk.as_slice(),
                <Cs as voprf::CipherSuite>::Group::serialize_elem(theirs.get_public_key())
                    .as_slice()
            );
            let their_pk = <Cs as voprf::CipherSuite>::Group::deserialize_elem(&pk).unwrap();

            let client = <$client>::new(&pk).unwrap();
            let mut states = Vec::new();
            let mut their_states = Vec::new();
            let mut blinded = Vec::new();
            for (input, blind) in case.inputs.iter().zip(&case.blinds) {
                let (state, b) = client
                    .blind(input, &mut PlannedRng::new(vec![blind.clone()]))
                    .unwrap();
                let their = voprf::VoprfClient::<Cs>::blind(
                    input,
                    &mut PlannedRng::new(vec![blind.clone()]),
                )
                .unwrap();
                assert_eq!(
                    b.as_slice(),
                    their.message.serialize().as_slice(),
                    "blinded element"
                );
                states.push(state);
                their_states.push(their.state);
                blinded.push(b);
            }

            let (evaluated, proof) = ours
                .blind_evaluate_batch(&blinded, &mut PlannedRng::new(vec![case.hedge.clone()]))
                .unwrap();
            let their_blinded: Vec<BlindedElement<Cs>> = blinded
                .iter()
                .map(|b| BlindedElement::deserialize(b).unwrap())
                .collect();
            let their_result = theirs
                .batch_blind_evaluate(
                    &mut PlannedRng::new(vec![case.their_nonce.clone()]),
                    &their_blinded,
                )
                .unwrap();
            let their_evaluated: Vec<Vec<u8>> = their_result
                .messages
                .iter()
                .map(|m| m.serialize().to_vec())
                .collect();
            let our_evaluated: Vec<Vec<u8>> = evaluated.iter().map(|e| e.to_vec()).collect();
            assert_eq!(our_evaluated, their_evaluated, "evaluated elements");
            let their_proof: [u8; 64] = their_result
                .proof
                .serialize()
                .as_slice()
                .try_into()
                .unwrap();

            let expected: Vec<Vec<u8>> = case
                .inputs
                .iter()
                .map(|input| ours.evaluate(input).unwrap().to_vec())
                .collect();
            let their_expected: Vec<Vec<u8>> = case
                .inputs
                .iter()
                .map(|input| theirs.evaluate(input).unwrap().to_vec())
                .collect();
            assert_eq!(expected, their_expected, "Evaluate");

            // Our client, on our proof and on theirs.
            for p in [proof, their_proof] {
                let outputs = client
                    .finalize_batch(&states, &case.inputs, &evaluated, &p)
                    .unwrap();
                let outputs: Vec<Vec<u8>> = outputs.iter().map(|o| o.to_vec()).collect();
                assert_eq!(outputs, expected, "pakery finalize");
            }
            // Their client, on our proof and on theirs.
            let messages: Vec<EvaluationElement<Cs>> = evaluated
                .iter()
                .map(|e| EvaluationElement::deserialize(e).unwrap())
                .collect();
            for p in [
                Proof::<Cs>::deserialize(&proof).unwrap(),
                their_result.proof,
            ] {
                let outputs: Vec<Vec<u8>> = voprf::VoprfClient::<Cs>::batch_finalize(
                    &case.inputs,
                    &their_states,
                    &messages,
                    &p,
                    their_pk,
                )
                .unwrap()
                .map(|o| o.unwrap().to_vec())
                .collect();
                assert_eq!(outputs, expected, "voprf finalize");
            }

            // Single evaluation agrees with the batch.
            let (single, _) = ours
                .blind_evaluate(&blinded[0], &mut PlannedRng::new(vec![case.hedge.clone()]))
                .unwrap();
            assert_eq!(single, evaluated[0]);
            let _ = $p256;
        }
    };
}

/// The comparison for one suite and the POPRF.
macro_rules! poprf_differential {
    ($name:ident, server: $server:ty, client: $client:ty, suite: $cs:ty, p256: $p256:expr) => {
        fn $name(case: &Case) {
            type Cs = $cs;
            let info = case.info.as_slice();
            let ours = <$server>::derive(&case.key_seed, &case.key_info).unwrap();
            let theirs =
                voprf::PoprfServer::<Cs>::new_from_seed(&case.key_seed, &case.key_info).unwrap();
            let theirs_serialized = theirs.serialize();
            assert_eq!(ours.secret_key().as_slice(), &theirs_serialized[..32]);
            let pk = ours.public_key();
            assert_eq!(
                pk.as_slice(),
                <Cs as voprf::CipherSuite>::Group::serialize_elem(theirs.get_public_key())
                    .as_slice()
            );
            let their_pk = <Cs as voprf::CipherSuite>::Group::deserialize_elem(&pk).unwrap();

            let client = <$client>::new(&pk).unwrap();
            let mut states = Vec::new();
            let mut their_states = Vec::new();
            let mut blinded = Vec::new();
            for (input, blind) in case.inputs.iter().zip(&case.blinds) {
                let (state, b) = client
                    .blind(input, info, &mut PlannedRng::new(vec![blind.clone()]))
                    .unwrap();
                let their = voprf::PoprfClient::<Cs>::blind(
                    input,
                    &mut PlannedRng::new(vec![blind.clone()]),
                )
                .unwrap();
                assert_eq!(
                    b.as_slice(),
                    their.message.serialize().as_slice(),
                    "blinded element"
                );
                states.push(state);
                their_states.push(their.state);
                blinded.push(b);
            }

            let (evaluated, proof) = ours
                .blind_evaluate_batch(
                    &blinded,
                    info,
                    &mut PlannedRng::new(vec![case.hedge.clone()]),
                )
                .unwrap();
            let their_blinded: Vec<BlindedElement<Cs>> = blinded
                .iter()
                .map(|b| BlindedElement::deserialize(b).unwrap())
                .collect();
            let their_result = theirs
                .batch_blind_evaluate(
                    &mut PlannedRng::new(vec![case.their_nonce.clone()]),
                    &their_blinded,
                    Some(info),
                )
                .unwrap();
            let their_evaluated: Vec<Vec<u8>> = their_result
                .messages
                .iter()
                .map(|m| m.serialize().to_vec())
                .collect();
            let our_evaluated: Vec<Vec<u8>> = evaluated.iter().map(|e| e.to_vec()).collect();
            assert_eq!(our_evaluated, their_evaluated, "evaluated elements");
            let their_proof: [u8; 64] = their_result
                .proof
                .serialize()
                .as_slice()
                .try_into()
                .unwrap();

            let expected: Vec<Vec<u8>> = case
                .inputs
                .iter()
                .map(|input| ours.evaluate(input, info).unwrap().to_vec())
                .collect();
            let their_expected: Vec<Vec<u8>> = case
                .inputs
                .iter()
                .map(|input| theirs.evaluate(input, Some(info)).unwrap().to_vec())
                .collect();
            assert_eq!(expected, their_expected, "Evaluate");

            for p in [proof, their_proof] {
                let outputs = client
                    .finalize_batch(&states, &case.inputs, info, &evaluated, &p)
                    .unwrap();
                let outputs: Vec<Vec<u8>> = outputs.iter().map(|o| o.to_vec()).collect();
                assert_eq!(outputs, expected, "pakery finalize");
            }
            let messages: Vec<EvaluationElement<Cs>> = evaluated
                .iter()
                .map(|e| EvaluationElement::deserialize(e).unwrap())
                .collect();
            for p in [
                Proof::<Cs>::deserialize(&proof).unwrap(),
                their_result.proof,
            ] {
                let outputs: Vec<Vec<u8>> = voprf::PoprfClient::<Cs>::batch_finalize(
                    case.inputs.iter().map(Vec::as_slice),
                    &their_states,
                    &messages,
                    &p,
                    their_pk,
                    Some(info),
                )
                .unwrap()
                .map(|o| o.unwrap().to_vec())
                .collect();
                assert_eq!(outputs, expected, "voprf finalize");
            }

            let (single, _) = ours
                .blind_evaluate(
                    &blinded[0],
                    info,
                    &mut PlannedRng::new(vec![case.hedge.clone()]),
                )
                .unwrap();
            assert_eq!(single, evaluated[0]);
            let _ = $p256;
        }
    };
}

voprf_differential!(
    voprf_ristretto255,
    server: pakery_crypto::Ristretto255VoprfServer,
    client: pakery_crypto::Ristretto255VoprfClient,
    suite: voprf::Ristretto255,
    p256: false
);
voprf_differential!(
    voprf_p256,
    server: pakery_crypto::P256VoprfServer,
    client: pakery_crypto::P256VoprfClient,
    suite: VoprfP256,
    p256: true
);
poprf_differential!(
    poprf_ristretto255,
    server: pakery_crypto::Ristretto255PoprfServer,
    client: pakery_crypto::Ristretto255PoprfClient,
    suite: voprf::Ristretto255,
    p256: false
);
poprf_differential!(
    poprf_p256,
    server: pakery_crypto::P256PoprfServer,
    client: pakery_crypto::P256PoprfClient,
    suite: VoprfP256,
    p256: true
);

#[test]
fn differential_rfc_key_material() {
    voprf_ristretto255(&rfc_like_case(false));
    voprf_p256(&rfc_like_case(true));
    poprf_ristretto255(&rfc_like_case(false));
    poprf_p256(&rfc_like_case(true));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn differential_voprf_ristretto255(seed in any::<u64>(), batch in 1usize..=4) {
        voprf_ristretto255(&case(seed, batch, false));
    }

    #[test]
    fn differential_voprf_p256(seed in any::<u64>(), batch in 1usize..=4) {
        voprf_p256(&case(seed, batch, true));
    }

    #[test]
    fn differential_poprf_ristretto255(seed in any::<u64>(), batch in 1usize..=4) {
        poprf_ristretto255(&case(seed, batch, false));
    }

    #[test]
    fn differential_poprf_p256(seed in any::<u64>(), batch in 1usize..=4) {
        poprf_p256(&case(seed, batch, true));
    }
}

/// pakery parses a zero `c` or `s` — RFC 9497 §4 lets `DeserializeScalar`
/// return any value in `[0, p - 1]` — and then fails verification; `voprf`
/// rejects the same bytes while deserializing. Both refuse the proof; this
/// pins where.
#[test]
fn divergence_zero_proof_scalars() {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let server = pakery_crypto::Ristretto255VoprfServer::derive(&[1; 32], b"").unwrap();
    let client = pakery_crypto::Ristretto255VoprfClient::new(&server.public_key()).unwrap();
    let (state, blinded) = client.blind(b"in", &mut rng).unwrap();
    let (evaluated, proof) = server.blind_evaluate(&blinded, &mut rng).unwrap();
    for half in [0..32, 32..64] {
        let mut zero = proof;
        zero[half].fill(0);
        assert_eq!(
            client
                .finalize(&state, b"in", &evaluated, &zero)
                .unwrap_err(),
            pakery_crypto::VoprfError::Verify
        );
        assert!(Proof::<voprf::Ristretto255>::deserialize(&zero).is_err());
    }

    let server = pakery_crypto::P256VoprfServer::derive(&[1; 32], b"").unwrap();
    let client = pakery_crypto::P256VoprfClient::new(&server.public_key()).unwrap();
    let (state, blinded) = client.blind(b"in", &mut rng).unwrap();
    let (evaluated, proof) = server.blind_evaluate(&blinded, &mut rng).unwrap();
    for half in [0..32, 32..64] {
        let mut zero = proof;
        zero[half].fill(0);
        assert_eq!(
            client
                .finalize(&state, b"in", &evaluated, &zero)
                .unwrap_err(),
            pakery_crypto::VoprfError::Verify
        );
        assert!(Proof::<VoprfP256>::deserialize(&zero).is_err());
    }
}

/// `voprf`'s POPRF `evaluate(input, None)` disagrees with its own client,
/// which frames a `None` info as empty; `Some(b"")` agrees with pakery's empty
/// `info`. This is why every comparison above passes `Some`.
#[test]
fn divergence_voprf_poprf_none_info() {
    let ours = pakery_crypto::Ristretto255PoprfServer::derive(&[2; 32], b"").unwrap();
    let theirs = voprf::PoprfServer::<voprf::Ristretto255>::new_from_seed(&[2; 32], b"").unwrap();
    let with_empty = theirs.evaluate(b"in", Some(b"")).unwrap();
    let with_none = theirs.evaluate(b"in", None).unwrap();
    assert_eq!(
        with_empty.as_slice(),
        ours.evaluate(b"in", b"").unwrap().as_slice()
    );
    assert_ne!(with_none.as_slice(), with_empty.as_slice());
}
