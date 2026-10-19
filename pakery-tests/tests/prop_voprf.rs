//! Property-based tests for the RFC 9497 VOPRF and POPRF in pakery-crypto.
//!
//! Suites: ristretto255-SHA512 (always) and P256-SHA256 (feature `p256`), both
//! modes. All randomness is driven through a `ChaCha20Rng` seeded from a
//! proptest-generated `u64`.
//!
//! Properties (see SECURITY_TESTING.md, "Property-based tests"):
//! 1. Agreement: for a batch of 1..=4 inputs, `finalize_batch` and `finalize`
//!    equal the server's `evaluate` of each input.
//! 2. Tamper rejection: XOR-ing any byte of any evaluated element or of the
//!    proof makes `finalize` fail; a client holding another server's key fails
//!    with `Verify`.
//! 3. Input binding: replacing any one input of a batch at `finalize` fails
//!    with `InputMismatch`.
//! 4. Keys: `derive` is deterministic, `from_secret_key(secret_key())`
//!    round-trips, and the VOPRF and POPRF derive different keys from the same
//!    seed.
//! 5. POPRF `info`: `finalize` under an `info` other than the one blinded
//!    with fails as `InputMismatch`; otherwise it fails as `Verify` exactly
//!    when the server evaluated under another `info`, and succeeds — equal to
//!    `evaluate` — when all three agree. The blinded element does not depend
//!    on `info`.
//! 6. No panic: arbitrary bytes as a public key, blinded element, evaluated
//!    element or proof yield `Err`, never a panic, and every strict prefix or
//!    extension of a valid message is rejected.
//! 7. With `hazmat`: `deterministic_blind` agrees with `blind` fed the bytes
//!    the suite's `RandomScalar` reduces to the same scalar.

use pakery_crypto::VoprfError;
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max_len)
}

fn batch() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(bytes(64), 1..=4)
}

/// Replays fixed bytes, panicking when it runs out.
#[cfg(feature = "hazmat")]
struct ScriptedRng(std::collections::VecDeque<u8>);

#[cfg(feature = "hazmat")]
impl rand_core::TryRng for ScriptedRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("word draw not scripted")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("word draw not scripted")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest {
            *byte = self.0.pop_front().expect("ScriptedRng exhausted");
        }
        Ok(())
    }
}

#[cfg(feature = "hazmat")]
impl rand_core::TryCryptoRng for ScriptedRng {}

macro_rules! properties {
    (
        $module:ident,
        server: $server:ty,
        client: $client:ty,
        ne: $ne:literal,
        info: [$($info:ident)?] $(,)?
    ) => {
        mod $module {
            use super::*;

            #[allow(unused_variables)]
            fn run(
                seed: u64,
                inputs: &[Vec<u8>],
                $($info: &[u8],)?
            ) -> ($server, $client, Vec<Vec<u8>>, [u8; 64], Vec<Vec<u8>>) {
                let mut rng = ChaCha20Rng::seed_from_u64(seed);
                let server = <$server>::generate(&mut rng);
                let client = <$client>::new(&server.public_key()).unwrap();
                let mut states = Vec::new();
                let mut blinded = Vec::new();
                for input in inputs {
                    let (state, b) = client.blind(input, $($info,)? &mut rng).unwrap();
                    states.push(state);
                    blinded.push(b);
                }
                let (evaluated, proof) =
                    server.blind_evaluate_batch(&blinded, $($info,)? &mut rng).unwrap();
                let outputs = client
                    .finalize_batch(&states, inputs, $($info,)? &evaluated, &proof)
                    .unwrap();
                let evaluated = evaluated.iter().map(|e| e.to_vec()).collect();
                let outputs = outputs.iter().map(|o| o.to_vec()).collect();
                (server, client, evaluated, proof, outputs)
            }

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(32))]

                #[test]
                fn agreement_with_evaluate(seed in any::<u64>(), inputs in batch() $(, $info in bytes(32))?) {
                    let (server, client, _, _, outputs) = run(seed, &inputs, $(&$info)?);
                    for (input, output) in inputs.iter().zip(&outputs) {
                        prop_assert_eq!(output.clone(), server.evaluate(input, $(&$info)?).unwrap().to_vec());
                    }
                    // A single round trip agrees with the batch.
                    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 1);
                    let (state, blinded) = client.blind(&inputs[0], $(&$info,)? &mut rng).unwrap();
                    let (evaluated, proof) = server.blind_evaluate(&blinded, $(&$info,)? &mut rng).unwrap();
                    let single = client.finalize(&state, &inputs[0], $(&$info,)? &evaluated, &proof).unwrap();
                    prop_assert_eq!(single.to_vec(), outputs[0].clone());
                }

                #[test]
                fn any_flipped_byte_is_rejected(
                    seed in any::<u64>(),
                    inputs in batch(),
                    $($info in bytes(32),)?
                    target in any::<prop::sample::Index>(),
                    position in any::<prop::sample::Index>(),
                    mask in 1u8..=255,
                ) {
                    let mut rng = ChaCha20Rng::seed_from_u64(seed);
                    let server = <$server>::generate(&mut rng);
                    let client = <$client>::new(&server.public_key()).unwrap();
                    let mut states = Vec::new();
                    let mut blinded = Vec::new();
                    for input in &inputs {
                        let (state, b) = client.blind(input, $(&$info,)? &mut rng).unwrap();
                        states.push(state);
                        blinded.push(b);
                    }
                    let (mut evaluated, mut proof) =
                        server.blind_evaluate_batch(&blinded, $(&$info,)? &mut rng).unwrap();
                    // Targets 0..n are the evaluated elements, n the proof.
                    let target = target.index(evaluated.len() + 1);
                    if target < evaluated.len() {
                        evaluated[target][position.index($ne)] ^= mask;
                    } else {
                        proof[position.index(64)] ^= mask;
                    }
                    let result = client.finalize_batch(&states, &inputs, $(&$info,)? &evaluated, &proof);
                    prop_assert!(matches!(
                        result.unwrap_err(),
                        VoprfError::Deserialize | VoprfError::Verify
                    ));
                }

                #[test]
                fn another_servers_evaluation_fails_verification(
                    seed in any::<u64>(),
                    input in bytes(64),
                    $($info in bytes(32),)?
                ) {
                    let mut rng = ChaCha20Rng::seed_from_u64(seed);
                    let server = <$server>::generate(&mut rng);
                    let other = <$server>::generate(&mut rng);
                    let client = <$client>::new(&server.public_key()).unwrap();
                    let (state, blinded) = client.blind(&input, $(&$info,)? &mut rng).unwrap();
                    let (evaluated, proof) = other.blind_evaluate(&blinded, $(&$info,)? &mut rng).unwrap();
                    prop_assert_eq!(
                        client.finalize(&state, &input, $(&$info,)? &evaluated, &proof).unwrap_err(),
                        VoprfError::Verify
                    );
                }

                #[test]
                fn finalize_input_must_be_the_blinded_one(
                    seed in any::<u64>(),
                    inputs in batch(),
                    $($info in bytes(32),)?
                    which in any::<prop::sample::Index>(),
                    replacement in bytes(64),
                ) {
                    let which = which.index(inputs.len());
                    prop_assume!(replacement != inputs[which]);
                    let mut rng = ChaCha20Rng::seed_from_u64(seed);
                    let server = <$server>::generate(&mut rng);
                    let client = <$client>::new(&server.public_key()).unwrap();
                    let mut states = Vec::new();
                    let mut blinded = Vec::new();
                    for input in &inputs {
                        let (state, b) = client.blind(input, $(&$info,)? &mut rng).unwrap();
                        states.push(state);
                        blinded.push(b);
                    }
                    let (evaluated, proof) =
                        server.blind_evaluate_batch(&blinded, $(&$info,)? &mut rng).unwrap();
                    let mut wrong = inputs.clone();
                    wrong[which] = replacement;
                    prop_assert_eq!(
                        client.finalize_batch(&states, &wrong, $(&$info,)? &evaluated, &proof).unwrap_err(),
                        VoprfError::InputMismatch
                    );
                }

                #[test]
                fn keys_derive_deterministically_and_round_trip(seed in any::<[u8; 32]>(), key_info in bytes(32)) {
                    let a = <$server>::derive(&seed, &key_info).unwrap();
                    let b = <$server>::derive(&seed, &key_info).unwrap();
                    prop_assert_eq!(a.public_key(), b.public_key());
                    let reloaded = <$server>::from_secret_key(&*a.secret_key()).unwrap();
                    prop_assert_eq!(reloaded.public_key(), a.public_key());
                    prop_assert_eq!(*reloaded.secret_key(), *a.secret_key());
                }

                #[test]
                fn arbitrary_bytes_never_panic(
                    seed in any::<u64>(),
                    junk in bytes(80),
                    junk_proof in bytes(80),
                    $($info in bytes(32),)?
                ) {
                    let mut rng = ChaCha20Rng::seed_from_u64(seed);
                    let server = <$server>::generate(&mut rng);
                    let client = <$client>::new(&server.public_key()).unwrap();
                    let _ = <$client>::new(&junk);
                    let _ = <$server>::from_secret_key(&junk);
                    let _ = server.blind_evaluate(&junk, $(&$info,)? &mut rng);
                    let (state, _) = client.blind(b"in", $(&$info,)? &mut rng).unwrap();
                    let _ = client.finalize(&state, b"in", $(&$info,)? &junk, &junk_proof);
                }
            }

            /// Every strict prefix and every one-byte extension of each valid
            /// message is rejected: the public key, a blinded element, an
            /// evaluated element and a proof.
            #[test]
            fn truncations_and_extensions_are_rejected() {
                $(let $info: &[u8] = b"sweep";)?
                let mut rng = ChaCha20Rng::seed_from_u64(7);
                let server = <$server>::generate(&mut rng);
                let pk = server.public_key();
                let client = <$client>::new(&pk).unwrap();
                let (state, blinded) = client.blind(b"in", $($info,)? &mut rng).unwrap();
                let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng).unwrap();
                let variants = |message: &[u8]| {
                    let mut out: Vec<Vec<u8>> = (0..message.len()).map(|n| message[..n].to_vec()).collect();
                    out.push([message, &[0]].concat());
                    out.push([message, &[0xff]].concat());
                    out
                };
                for bad in variants(&pk) {
                    assert_eq!(<$client>::new(&bad).unwrap_err(), VoprfError::Deserialize);
                }
                for bad in variants(&blinded) {
                    assert_eq!(
                        server.blind_evaluate(&bad, $($info,)? &mut rng).unwrap_err(),
                        VoprfError::Deserialize
                    );
                }
                for bad in variants(&evaluated) {
                    assert_eq!(
                        client.finalize(&state, b"in", $($info,)? &bad, &proof).unwrap_err(),
                        VoprfError::Deserialize
                    );
                }
                for bad in variants(&proof) {
                    assert_eq!(
                        client.finalize(&state, b"in", $($info,)? &evaluated, &bad).unwrap_err(),
                        VoprfError::Deserialize
                    );
                }
            }
        }
    };
}

/// POPRF-only properties: the role of `info`.
macro_rules! poprf_info_properties {
    ($module:ident, server: $server:ty, client: $client:ty $(,)?) => {
        mod $module {
            use super::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(32))]

                /// The three `info`s are drawn from three values so that every
                /// combination of agreeing and disagreeing comes up.
                #[test]
                fn info_decides_between_mismatch_verify_and_success(
                    seed in any::<u64>(),
                    input in bytes(64),
                    blind_info in prop::sample::select(vec![Vec::new(), b"a".to_vec(), b"b".to_vec()]),
                    server_info in prop::sample::select(vec![Vec::new(), b"a".to_vec(), b"b".to_vec()]),
                    finalize_info in prop::sample::select(vec![Vec::new(), b"a".to_vec(), b"b".to_vec()]),
                ) {
                    let mut rng = ChaCha20Rng::seed_from_u64(seed);
                    let server = <$server>::generate(&mut rng);
                    let client = <$client>::new(&server.public_key()).unwrap();
                    let (state, blinded) = client.blind(&input, &blind_info, &mut rng).unwrap();
                    let (evaluated, proof) = server.blind_evaluate(&blinded, &server_info, &mut rng).unwrap();
                    let result = client.finalize(&state, &input, &finalize_info, &evaluated, &proof);
                    if finalize_info != blind_info {
                        prop_assert_eq!(result.unwrap_err(), VoprfError::InputMismatch);
                    } else if server_info != finalize_info {
                        prop_assert_eq!(result.unwrap_err(), VoprfError::Verify);
                    } else {
                        prop_assert_eq!(
                            result.unwrap().to_vec(),
                            server.evaluate(&input, &finalize_info).unwrap().to_vec()
                        );
                    }
                }
            }
        }
    };
}

properties!(
    ristretto255_voprf,
    server: pakery_crypto::Ristretto255VoprfServer,
    client: pakery_crypto::Ristretto255VoprfClient,
    ne: 32,
    info: [],
);
properties!(
    ristretto255_poprf,
    server: pakery_crypto::Ristretto255PoprfServer,
    client: pakery_crypto::Ristretto255PoprfClient,
    ne: 32,
    info: [info],
);
poprf_info_properties!(
    ristretto255_poprf_info,
    server: pakery_crypto::Ristretto255PoprfServer,
    client: pakery_crypto::Ristretto255PoprfClient,
);

#[cfg(feature = "p256")]
properties!(
    p256_voprf,
    server: pakery_crypto::P256VoprfServer,
    client: pakery_crypto::P256VoprfClient,
    ne: 33,
    info: [],
);
#[cfg(feature = "p256")]
properties!(
    p256_poprf,
    server: pakery_crypto::P256PoprfServer,
    client: pakery_crypto::P256PoprfClient,
    ne: 33,
    info: [info],
);
#[cfg(feature = "p256")]
poprf_info_properties!(
    p256_poprf_info,
    server: pakery_crypto::P256PoprfServer,
    client: pakery_crypto::P256PoprfClient,
);

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// The mode is part of every derivation tag, so one seed gives a VOPRF key
    /// and a different POPRF key (RFC 9497 §3.2.1, `contextString`).
    #[test]
    fn modes_derive_different_keys(seed in any::<[u8; 32]>(), key_info in bytes(32)) {
        let v = pakery_crypto::Ristretto255VoprfServer::derive(&seed, &key_info).unwrap();
        let p = pakery_crypto::Ristretto255PoprfServer::derive(&seed, &key_info).unwrap();
        prop_assert_ne!(v.public_key(), p.public_key());
    }

    /// The POPRF blinded element does not depend on `info`, and differs from
    /// the VOPRF one for the same RNG bytes (the hash-to-group tags differ).
    #[test]
    fn blinded_element_ignores_info_but_not_mode(
        seed in any::<u64>(),
        input in bytes(64),
        info_a in bytes(16),
        info_b in bytes(16),
    ) {
        let server = pakery_crypto::Ristretto255PoprfServer::generate(&mut ChaCha20Rng::seed_from_u64(seed));
        let client = pakery_crypto::Ristretto255PoprfClient::new(&server.public_key()).unwrap();
        let (_, a) = client.blind(&input, &info_a, &mut ChaCha20Rng::seed_from_u64(seed)).unwrap();
        let (_, b) = client.blind(&input, &info_b, &mut ChaCha20Rng::seed_from_u64(seed)).unwrap();
        prop_assert_eq!(a, b);
        let voprf = pakery_crypto::Ristretto255VoprfClient::new(&server.public_key()).unwrap();
        let (_, c) = voprf.blind(&input, &mut ChaCha20Rng::seed_from_u64(seed)).unwrap();
        prop_assert_ne!(a, c);
    }
}

#[cfg(feature = "hazmat")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// ristretto255 reads the 64 bytes little-endian and `RandomScalar` reduces
    /// a 64-byte draw: the same bytes give the same blinded element on both
    /// paths.
    #[test]
    fn hazmat_cross_path_ristretto255(wide in any::<[u8; 64]>(), input in bytes(64), info in bytes(16)) {
        let server = pakery_crypto::Ristretto255PoprfServer::derive(&[3; 32], b"").unwrap();
        let client = pakery_crypto::Ristretto255PoprfClient::new(&server.public_key()).unwrap();
        let (_, a) = client.deterministic_blind(&input, &info, &wide).unwrap();
        let (_, b) = client.blind(&input, &info, &mut ScriptedRng(wide.to_vec().into())).unwrap();
        prop_assert_eq!(a, b);
    }
}

#[cfg(all(feature = "hazmat", feature = "p256"))]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// P-256 reads the 64 bytes big-endian; `RandomScalar` accepts a canonical
    /// nonzero 32-byte draw. `0^32 || s` and the draw `s` give the same blinded
    /// element.
    #[test]
    fn hazmat_cross_path_p256(seed in any::<[u8; 32]>(), input in bytes(64)) {
        // Make `seed` a canonical nonzero scalar: clear the top bit (below
        // the order, which starts 0xffffffff00..) and set the lowest one.
        let mut scalar = seed;
        scalar[0] &= 0x7f;
        scalar[31] |= 1;
        let server = pakery_crypto::P256VoprfServer::derive(&[4; 32], b"").unwrap();
        let client = pakery_crypto::P256VoprfClient::new(&server.public_key()).unwrap();
        let mut wide = [0u8; 64];
        wide[32..].copy_from_slice(&scalar);
        let (_, a) = client.deterministic_blind(&input, &wide).unwrap();
        let (_, b) = client.blind(&input, &mut ScriptedRng(scalar.to_vec().into())).unwrap();
        prop_assert_eq!(a, b);
    }
}
