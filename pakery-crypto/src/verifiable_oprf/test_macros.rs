//! Test generators shared by both suites.
//!
//! The RFC 9497 vectors run through the *public* types, so a wrapper wired to
//! the wrong mode or the wrong list order fails them. The one value the public
//! path cannot reproduce is the RFC's proof: this crate hedges the proof nonce,
//! so the "Proof" bytes are checked through the core with the RFC's
//! "ProofRandomScalar" injected, and the public path is checked to produce the
//! same evaluated elements and outputs with a proof the client accepts.

/// The RFC 9497 Appendix A vectors of one (suite, mode).
///
/// `blind_rng` maps an RFC "Blind" to the RNG bytes the suite's
/// `RandomScalar` consumes to return it; `wide_blind` maps it to 64 bytes
/// that `deterministic_blind` reduces to it.
macro_rules! rfc_vector_tests {
    (
        voprf,
        server: $server:ident,
        client: $client:ident,
        group: $group:ty,
        key: $key:expr,
        vectors: $vectors:expr,
        blind_rng: $blind_rng:path,
        wide_blind: $wide_blind:path,
        hedged: $hedged:expr,
        deterministic: $deterministic:expr $(,)?
    ) => {
        use alloc::vec::Vec;
        use $crate::verifiable_oprf::protocol::test_support::{
            blind_evaluate_with_nonce, hex, ScriptedRng,
        };
        use $crate::verifiable_oprf::protocol::{Mode, VoprfGroup};

        fn rfc_server() -> $server {
            let seed: [u8; 32] = hex($key.seed).try_into().unwrap();
            $server::derive(&seed, &hex($key.key_info)).unwrap()
        }

        fn rfc_client() -> $client {
            $client::new(&hex($key.pk)).unwrap()
        }

        fn rfc_nonce(hex_scalar: &str) -> <$group as VoprfGroup>::Scalar {
            let bytes: [u8; 32] = hex(hex_scalar).try_into().unwrap();
            let (scalar, canonical) = <$group as VoprfGroup>::decode_scalar(&bytes);
            assert!(bool::from(canonical));
            scalar
        }

        #[test]
        fn derive_key_pair_matches_rfc() {
            let server = rfc_server();
            assert_eq!(server.secret_key().as_slice(), hex($key.sk).as_slice());
            assert_eq!(server.public_key().as_slice(), hex($key.pk).as_slice());
            let reloaded = $server::from_secret_key(&hex($key.sk)).unwrap();
            assert_eq!(reloaded.public_key().as_slice(), hex($key.pk).as_slice());
        }

        #[test]
        fn blind_matches_rfc() {
            let client = rfc_client();
            for tv in $vectors {
                for ((input, blind), blinded) in tv.inputs.iter().zip(tv.blinds).zip(tv.blinded) {
                    let mut rng = ScriptedRng::new(&$blind_rng(&hex(blind)));
                    let (_state, got) = client.blind(&hex(input), &mut rng).unwrap();
                    assert!(rng.is_exhausted(), "Blind must consume exactly one draw");
                    assert_eq!(got.as_slice(), hex(blinded).as_slice());
                }
            }
        }

        #[test]
        fn proof_with_rfc_nonce_matches_rfc() {
            let server = rfc_server();
            for tv in $vectors {
                let blinded: Vec<Vec<u8>> = tv.blinded.iter().map(|b| hex(b)).collect();
                let (evaluated, proof) = blind_evaluate_with_nonce::<$group, _>(
                    &server.0,
                    Mode::Voprf,
                    &blinded,
                    rfc_nonce(tv.proof_random_scalar),
                )
                .unwrap();
                let expected: Vec<Vec<u8>> = tv.evaluated.iter().map(|e| hex(e)).collect();
                let got: Vec<Vec<u8>> = evaluated.iter().map(|e| e.to_vec()).collect();
                assert_eq!(got, expected);
                assert_eq!(proof.as_slice(), hex(tv.proof).as_slice());
            }
        }

        #[test]
        fn finalize_of_rfc_response_matches_rfc() {
            let client = rfc_client();
            for tv in $vectors {
                let inputs: Vec<Vec<u8>> = tv.inputs.iter().map(|i| hex(i)).collect();
                let states: Vec<_> = inputs
                    .iter()
                    .zip(tv.blinds)
                    .map(|(input, blind)| {
                        let mut rng = ScriptedRng::new(&$blind_rng(&hex(blind)));
                        client.blind(input, &mut rng).unwrap().0
                    })
                    .collect();
                let evaluated: Vec<Vec<u8>> = tv.evaluated.iter().map(|e| hex(e)).collect();
                let outputs = client
                    .finalize_batch(&states, &inputs, &evaluated, &hex(tv.proof))
                    .unwrap();
                let got: Vec<Vec<u8>> = outputs.iter().map(|o| o.to_vec()).collect();
                let expected: Vec<Vec<u8>> = tv.outputs.iter().map(|o| hex(o)).collect();
                assert_eq!(got, expected);
                if states.len() == 1 {
                    let single = client
                        .finalize(&states[0], &inputs[0], &evaluated[0], &hex(tv.proof))
                        .unwrap();
                    assert_eq!(single.as_slice(), expected[0].as_slice());
                }
            }
        }

        #[test]
        fn evaluate_matches_rfc() {
            let server = rfc_server();
            for tv in $vectors {
                for (input, output) in tv.inputs.iter().zip(tv.outputs) {
                    let got = server.evaluate(&hex(input)).unwrap();
                    assert_eq!(got.as_slice(), hex(output).as_slice());
                }
            }
        }

        #[test]
        fn public_round_trip_matches_rfc_with_hedged_proof() {
            let server = rfc_server();
            let client = rfc_client();
            for tv in $vectors {
                let inputs: Vec<Vec<u8>> = tv.inputs.iter().map(|i| hex(i)).collect();
                let mut states = Vec::new();
                let mut blinded = Vec::new();
                for (input, blind) in inputs.iter().zip(tv.blinds) {
                    let mut rng = ScriptedRng::new(&$blind_rng(&hex(blind)));
                    let (state, b) = client.blind(input, &mut rng).unwrap();
                    states.push(state);
                    blinded.push(b);
                }
                let mut rng = ScriptedRng::new(&[0x42; 32]);
                let (evaluated, proof) = server.blind_evaluate_batch(&blinded, &mut rng).unwrap();
                assert!(rng.is_exhausted(), "the hedged nonce draws 32 bytes");
                let expected: Vec<Vec<u8>> = tv.evaluated.iter().map(|e| hex(e)).collect();
                let got: Vec<Vec<u8>> = evaluated.iter().map(|e| e.to_vec()).collect();
                assert_eq!(got, expected);
                assert_ne!(proof.as_slice(), hex(tv.proof).as_slice());
                let outputs = client
                    .finalize_batch(&states, &inputs, &evaluated, &proof)
                    .unwrap();
                let got: Vec<Vec<u8>> = outputs.iter().map(|o| o.to_vec()).collect();
                let expected: Vec<Vec<u8>> = tv.outputs.iter().map(|o| hex(o)).collect();
                assert_eq!(got, expected);
                if blinded.len() == 1 {
                    let mut rng = ScriptedRng::new(&[0x42; 32]);
                    let (single, single_proof) =
                        server.blind_evaluate(&blinded[0], &mut rng).unwrap();
                    assert_eq!(single, evaluated[0]);
                    assert_eq!(single_proof, proof);
                }
            }
        }

        #[cfg(feature = "hazmat")]
        #[test]
        fn deterministic_blind_matches_rfc() {
            let client = rfc_client();
            for tv in $vectors {
                for ((input, blind), blinded) in tv.inputs.iter().zip(tv.blinds).zip(tv.blinded) {
                    let (_state, got) = client
                        .deterministic_blind(&hex(input), &$wide_blind(&hex(blind)))
                        .unwrap();
                    assert_eq!(got.as_slice(), hex(blinded).as_slice());
                }
            }
        }

        /// The hedged nonce on the public path, against an independent model:
        /// the RFC key, inputs and blinds with hedge randomness `0x01..=0x20`
        /// must give exactly this proof. Pins every value the nonce hash
        /// covers.
        #[test]
        fn hedged_proof_matches_independent_model() {
            use $crate::verifiable_oprf::test_vectors::HEDGE_RAND;
            let server = rfc_server();
            let client = rfc_client();
            for (index, expected) in $hedged {
                let tv = &$vectors[*index];
                let blinded: Vec<_> = tv
                    .inputs
                    .iter()
                    .zip(tv.blinds)
                    .map(|(input, blind)| {
                        let mut rng = ScriptedRng::new(&$blind_rng(&hex(blind)));
                        client.blind(&hex(input), &mut rng).unwrap().1
                    })
                    .collect();
                let mut rng = ScriptedRng::new(&HEDGE_RAND);
                let (_, proof) = server.blind_evaluate_batch(&blinded, &mut rng).unwrap();
                assert!(rng.is_exhausted());
                assert_eq!(proof.as_slice(), hex(expected).as_slice());
            }
        }

        #[cfg(feature = "hazmat")]
        #[test]
        fn deterministic_blind_matches_independent_model() {
            let blind: [u8; 64] = core::array::from_fn(|i| i as u8 + 1);
            let (_, blinded) = rfc_client().deterministic_blind(&[0], &blind).unwrap();
            assert_eq!(blinded.as_slice(), hex($deterministic).as_slice());
        }
    };

    (
        poprf,
        server: $server:ident,
        client: $client:ident,
        group: $group:ty,
        key: $key:expr,
        vectors: $vectors:expr,
        blind_rng: $blind_rng:path,
        wide_blind: $wide_blind:path,
        hedged: $hedged:expr,
        deterministic: $deterministic:expr $(,)?
    ) => {
        use alloc::vec::Vec;
        use $crate::verifiable_oprf::protocol::test_support::{
            blind_evaluate_with_nonce, hex, ScriptedRng,
        };
        use $crate::verifiable_oprf::protocol::{Mode, VoprfGroup};

        fn rfc_server() -> $server {
            let seed: [u8; 32] = hex($key.seed).try_into().unwrap();
            $server::derive(&seed, &hex($key.key_info)).unwrap()
        }

        fn rfc_client() -> $client {
            $client::new(&hex($key.pk)).unwrap()
        }

        fn rfc_nonce(hex_scalar: &str) -> <$group as VoprfGroup>::Scalar {
            let bytes: [u8; 32] = hex(hex_scalar).try_into().unwrap();
            let (scalar, canonical) = <$group as VoprfGroup>::decode_scalar(&bytes);
            assert!(bool::from(canonical));
            scalar
        }

        #[test]
        fn derive_key_pair_matches_rfc() {
            let server = rfc_server();
            assert_eq!(server.secret_key().as_slice(), hex($key.sk).as_slice());
            assert_eq!(server.public_key().as_slice(), hex($key.pk).as_slice());
            let reloaded = $server::from_secret_key(&hex($key.sk)).unwrap();
            assert_eq!(reloaded.public_key().as_slice(), hex($key.pk).as_slice());
        }

        #[test]
        fn blind_matches_rfc() {
            let client = rfc_client();
            for tv in $vectors {
                let info = hex(tv.info);
                for ((input, blind), blinded) in tv.inputs.iter().zip(tv.blinds).zip(tv.blinded) {
                    let mut rng = ScriptedRng::new(&$blind_rng(&hex(blind)));
                    let (_state, got) = client.blind(&hex(input), &info, &mut rng).unwrap();
                    assert!(rng.is_exhausted(), "Blind must consume exactly one draw");
                    assert_eq!(got.as_slice(), hex(blinded).as_slice());
                }
            }
        }

        #[test]
        fn proof_with_rfc_nonce_matches_rfc() {
            let server = rfc_server();
            for tv in $vectors {
                let info = hex(tv.info);
                let blinded: Vec<Vec<u8>> = tv.blinded.iter().map(|b| hex(b)).collect();
                let (evaluated, proof) = blind_evaluate_with_nonce::<$group, _>(
                    &server.0,
                    Mode::Poprf(&info),
                    &blinded,
                    rfc_nonce(tv.proof_random_scalar),
                )
                .unwrap();
                let expected: Vec<Vec<u8>> = tv.evaluated.iter().map(|e| hex(e)).collect();
                let got: Vec<Vec<u8>> = evaluated.iter().map(|e| e.to_vec()).collect();
                assert_eq!(got, expected);
                assert_eq!(proof.as_slice(), hex(tv.proof).as_slice());
            }
        }

        #[test]
        fn finalize_of_rfc_response_matches_rfc() {
            let client = rfc_client();
            for tv in $vectors {
                let info = hex(tv.info);
                let inputs: Vec<Vec<u8>> = tv.inputs.iter().map(|i| hex(i)).collect();
                let states: Vec<_> = inputs
                    .iter()
                    .zip(tv.blinds)
                    .map(|(input, blind)| {
                        let mut rng = ScriptedRng::new(&$blind_rng(&hex(blind)));
                        client.blind(input, &info, &mut rng).unwrap().0
                    })
                    .collect();
                let evaluated: Vec<Vec<u8>> = tv.evaluated.iter().map(|e| hex(e)).collect();
                let outputs = client
                    .finalize_batch(&states, &inputs, &info, &evaluated, &hex(tv.proof))
                    .unwrap();
                let got: Vec<Vec<u8>> = outputs.iter().map(|o| o.to_vec()).collect();
                let expected: Vec<Vec<u8>> = tv.outputs.iter().map(|o| hex(o)).collect();
                assert_eq!(got, expected);
                if states.len() == 1 {
                    let single = client
                        .finalize(&states[0], &inputs[0], &info, &evaluated[0], &hex(tv.proof))
                        .unwrap();
                    assert_eq!(single.as_slice(), expected[0].as_slice());
                }
            }
        }

        #[test]
        fn evaluate_matches_rfc() {
            let server = rfc_server();
            for tv in $vectors {
                let info = hex(tv.info);
                for (input, output) in tv.inputs.iter().zip(tv.outputs) {
                    let got = server.evaluate(&hex(input), &info).unwrap();
                    assert_eq!(got.as_slice(), hex(output).as_slice());
                }
            }
        }

        #[test]
        fn public_round_trip_matches_rfc_with_hedged_proof() {
            let server = rfc_server();
            let client = rfc_client();
            for tv in $vectors {
                let info = hex(tv.info);
                let inputs: Vec<Vec<u8>> = tv.inputs.iter().map(|i| hex(i)).collect();
                let mut states = Vec::new();
                let mut blinded = Vec::new();
                for (input, blind) in inputs.iter().zip(tv.blinds) {
                    let mut rng = ScriptedRng::new(&$blind_rng(&hex(blind)));
                    let (state, b) = client.blind(input, &info, &mut rng).unwrap();
                    states.push(state);
                    blinded.push(b);
                }
                let mut rng = ScriptedRng::new(&[0x42; 32]);
                let (evaluated, proof) = server
                    .blind_evaluate_batch(&blinded, &info, &mut rng)
                    .unwrap();
                assert!(rng.is_exhausted(), "the hedged nonce draws 32 bytes");
                let expected: Vec<Vec<u8>> = tv.evaluated.iter().map(|e| hex(e)).collect();
                let got: Vec<Vec<u8>> = evaluated.iter().map(|e| e.to_vec()).collect();
                assert_eq!(got, expected);
                assert_ne!(proof.as_slice(), hex(tv.proof).as_slice());
                let outputs = client
                    .finalize_batch(&states, &inputs, &info, &evaluated, &proof)
                    .unwrap();
                let got: Vec<Vec<u8>> = outputs.iter().map(|o| o.to_vec()).collect();
                let expected: Vec<Vec<u8>> = tv.outputs.iter().map(|o| hex(o)).collect();
                assert_eq!(got, expected);
                if blinded.len() == 1 {
                    let mut rng = ScriptedRng::new(&[0x42; 32]);
                    let (single, single_proof) =
                        server.blind_evaluate(&blinded[0], &info, &mut rng).unwrap();
                    assert_eq!(single, evaluated[0]);
                    assert_eq!(single_proof, proof);
                }
            }
        }

        #[cfg(feature = "hazmat")]
        #[test]
        fn deterministic_blind_matches_rfc() {
            let client = rfc_client();
            for tv in $vectors {
                let info = hex(tv.info);
                for ((input, blind), blinded) in tv.inputs.iter().zip(tv.blinds).zip(tv.blinded) {
                    let (_state, got) = client
                        .deterministic_blind(&hex(input), &info, &$wide_blind(&hex(blind)))
                        .unwrap();
                    assert_eq!(got.as_slice(), hex(blinded).as_slice());
                }
            }
        }

        /// The hedged nonce on the public path, against an independent model:
        /// the RFC key, inputs, info and blinds with hedge randomness
        /// `0x01..=0x20` must give exactly this proof. Pins every value the
        /// nonce hash covers.
        #[test]
        fn hedged_proof_matches_independent_model() {
            use $crate::verifiable_oprf::test_vectors::HEDGE_RAND;
            let server = rfc_server();
            let client = rfc_client();
            for (index, expected) in $hedged {
                let tv = &$vectors[*index];
                let info = hex(tv.info);
                let blinded: Vec<_> = tv
                    .inputs
                    .iter()
                    .zip(tv.blinds)
                    .map(|(input, blind)| {
                        let mut rng = ScriptedRng::new(&$blind_rng(&hex(blind)));
                        client.blind(&hex(input), &info, &mut rng).unwrap().1
                    })
                    .collect();
                let mut rng = ScriptedRng::new(&HEDGE_RAND);
                let (_, proof) = server
                    .blind_evaluate_batch(&blinded, &info, &mut rng)
                    .unwrap();
                assert!(rng.is_exhausted());
                assert_eq!(proof.as_slice(), hex(expected).as_slice());
            }
        }

        #[cfg(feature = "hazmat")]
        #[test]
        fn deterministic_blind_matches_independent_model() {
            let blind: [u8; 64] = core::array::from_fn(|i| i as u8 + 1);
            let info = hex($vectors[0].info);
            let (_, blinded) = rfc_client()
                .deterministic_blind(&[0], &info, &blind)
                .unwrap();
            assert_eq!(blinded.as_slice(), hex($deterministic).as_slice());
        }
    };
}

pub(crate) use rfc_vector_tests;

/// Behaviour and rejection tests of one (suite, mode), through the public
/// types. Every decision the module documents as deliberate has a test here
/// that fails if it is reverted.
///
/// `invalid_elements` are encodings `DeserializeElement` must reject (the
/// identity among them); `scalar_order` encodes the group order, the smallest
/// non-canonical scalar; `wide_order` is 64 bytes that reduce to zero.
macro_rules! behaviour_tests {
    (
        common,
        server: $server:ident,
        client: $client:ident,
        group: $group:ty,
        ne: $ne:literal,
        invalid_elements: $invalid:expr,
        scalar_order: $order:expr,
        wide_order: $wide_order:expr,
        wide_zero_high: $wide_zero_high:expr,
        mode: $mode:expr,
        info: [$($info:expr)?] $(,)?
    ) => {
        use $crate::verifiable_oprf::protocol::test_support::{
            degenerate_proof, server_key_is_zero, state_is_wiped, ScriptedRng,
        };
        use $crate::verifiable_oprf::VoprfError;
        use alloc::vec;
        use alloc::vec::Vec;
        use zeroize::Zeroize;

        fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
            rand_core::UnwrapErr(getrandom::SysRng)
        }

        fn setup() -> ($server, $client) {
            let server = $server::generate(&mut rng());
            let client = $client::new(&server.public_key()).unwrap();
            (server, client)
        }

        #[test]
        fn round_trip_matches_evaluate() {
            let (server, client) = setup();
            for input in [&b""[..], b"x", &[0xa5; 300]] {
                let (state, blinded) = client.blind(input, $($info,)? &mut rng()).unwrap();
                let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
                let output = client.finalize(&state, input, $($info,)? &evaluated, &proof).unwrap();
                assert_eq!(*output, *server.evaluate(input, $($info)?).unwrap());
            }
        }

        #[test]
        fn client_rejects_invalid_public_keys() {
            for bad in $invalid {
                assert_eq!($client::new(bad).unwrap_err(), VoprfError::Deserialize);
            }
        }

        #[test]
        fn from_secret_key_rejects_invalid_keys() {
            let order: [u8; 32] = $order;
            for bad in [&[0u8; 32][..], &order, &[0xff; 32], &[1u8; 31], &[1u8; 33], &[]] {
                assert_eq!($server::from_secret_key(bad).unwrap_err(), VoprfError::Deserialize);
            }
            let (server, _) = setup();
            let reloaded = $server::from_secret_key(&*server.secret_key()).unwrap();
            assert_eq!(reloaded.public_key(), server.public_key());
        }

        #[test]
        fn blind_evaluate_rejects_invalid_blinded_elements() {
            let (server, _) = setup();
            for bad in $invalid {
                assert_eq!(
                    server.blind_evaluate(bad, $($info,)? &mut rng()).unwrap_err(),
                    VoprfError::Deserialize
                );
            }
        }

        #[test]
        fn finalize_rejects_invalid_evaluated_elements() {
            let (server, client) = setup();
            let (state, blinded) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            let (_, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            for bad in $invalid {
                assert_eq!(
                    client.finalize(&state, b"in", $($info,)? bad, &proof).unwrap_err(),
                    VoprfError::Deserialize
                );
            }
        }

        #[test]
        fn finalize_rejects_another_servers_evaluation() {
            let (_, client) = setup();
            let (other, _) = setup();
            let (state, blinded) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            let (evaluated, proof) = other.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            assert_eq!(
                client.finalize(&state, b"in", $($info,)? &evaluated, &proof).unwrap_err(),
                VoprfError::Verify
            );
        }

        #[test]
        fn finalize_rejects_any_single_bit_flip() {
            let (server, client) = setup();
            let (state, blinded) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            for i in 0..64 {
                let mut tampered = proof;
                tampered[i] ^= 1;
                assert!(client.finalize(&state, b"in", $($info,)? &evaluated, &tampered).is_err());
            }
            for i in 0..$ne {
                let mut tampered = evaluated;
                tampered[i] ^= 1;
                assert!(client.finalize(&state, b"in", $($info,)? &tampered, &proof).is_err());
            }
        }

        #[test]
        fn finalize_rejects_malformed_proofs() {
            let (server, client) = setup();
            let (state, blinded) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            let order: [u8; 32] = $order;
            let mut bad_c = proof;
            bad_c[..32].copy_from_slice(&order);
            let mut bad_s = proof;
            bad_s[32..].copy_from_slice(&order);
            let extended = [proof.as_slice(), &[0]].concat();
            for bad in [&bad_c[..], &bad_s, &proof[..63], extended.as_slice(), &[]] {
                assert_eq!(
                    client.finalize(&state, b"in", $($info,)? &evaluated, bad).unwrap_err(),
                    VoprfError::Deserialize
                );
            }
        }

        /// RFC 9497 §4: `DeserializeScalar` accepts `[0, p - 1]`, so a zero
        /// `c` or `s` is a well-formed proof that then fails to verify — not a
        /// deserialization error.
        #[test]
        fn zero_proof_scalars_parse_and_fail_verification() {
            let (server, client) = setup();
            let (state, blinded) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            let mut zero_c = proof;
            zero_c[..32].fill(0);
            let mut zero_s = proof;
            zero_s[32..].fill(0);
            for bad in [zero_c, zero_s, [0u8; 64]] {
                assert_eq!(
                    client.finalize(&state, b"in", $($info,)? &evaluated, &bad).unwrap_err(),
                    VoprfError::Verify
                );
            }
        }

        /// A canonical, nonzero `c` or `s` other than the server's parses and
        /// then fails verification: `Verify`, not `Deserialize`.
        #[test]
        fn altered_proof_scalars_parse_and_fail_verification() {
            use $crate::verifiable_oprf::protocol::test_support::bump_proof_scalar;
            let (server, client) = setup();
            let (state, blinded) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            for offset in [0, 32] {
                let altered = bump_proof_scalar::<$group>(&proof, offset);
                assert_ne!(altered, proof);
                assert_eq!(
                    client.finalize(&state, b"in", $($info,)? &evaluated, &altered).unwrap_err(),
                    VoprfError::Verify
                );
            }
        }

        /// `s = -c * k` makes `t2` and `t3` the identity. The statement is true,
        /// but no RFC-conformant prover produces it (its nonce is never zero,
        /// erratum 8392), P-256 cannot encode it, and this crate rejects it on
        /// both suites instead of hashing the identity.
        #[test]
        fn finalize_rejects_degenerate_proof() {
            let (server, client) = setup();
            let (state, blinded) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            let (evaluated, _) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            let proof = degenerate_proof::<$group>(&server.0, $mode, &blinded, &evaluated);
            assert_eq!(
                client.finalize(&state, b"in", $($info,)? &evaluated, &proof).unwrap_err(),
                VoprfError::Verify
            );
        }

        #[test]
        fn finalize_rejects_an_input_other_than_the_blinded_one() {
            let (server, client) = setup();
            let (state, blinded) = client.blind(b"right", $($info,)? &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            assert_eq!(
                client.finalize(&state, b"wrong", $($info,)? &evaluated, &proof).unwrap_err(),
                VoprfError::InputMismatch
            );
            assert!(client.finalize(&state, b"right", $($info,)? &evaluated, &proof).is_ok());
        }

        #[test]
        fn wiped_state_is_refused() {
            let (server, client) = setup();
            let (mut state, blinded) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            state.zeroize();
            assert!(state_is_wiped(&state.0));
            assert_eq!(
                client.finalize(&state, b"in", $($info,)? &evaluated, &proof).unwrap_err(),
                VoprfError::InvalidInput
            );
        }

        #[test]
        fn wiped_server_refuses_to_evaluate() {
            let (mut server, client) = setup();
            let (_, blinded) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            server.zeroize();
            assert!(server_key_is_zero(&server.0));
            assert_eq!(
                server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap_err(),
                VoprfError::Deserialize
            );
            assert_eq!(server.evaluate(b"in", $($info)?).unwrap_err(), VoprfError::Deserialize);
        }

        #[test]
        fn batch_shape_is_checked() {
            let (server, client) = setup();
            let empty: [[u8; $ne]; 0] = [];
            assert_eq!(
                server.blind_evaluate_batch(&empty, $($info,)? &mut rng()).unwrap_err(),
                VoprfError::Batch
            );
            let oversized = vec![[0u8; $ne]; 65536];
            assert_eq!(
                server.blind_evaluate_batch(&oversized, $($info,)? &mut rng()).unwrap_err(),
                VoprfError::Batch
            );
            let (state, blinded) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            let states = [state];
            let no_inputs: [&[u8]; 0] = [];
            assert_eq!(
                client
                    .finalize_batch(&states, &no_inputs, $($info,)? &[evaluated], &proof)
                    .unwrap_err(),
                VoprfError::Batch
            );
            assert_eq!(
                client
                    .finalize_batch(&states, &[b"in", b"in"], $($info,)? &[evaluated], &proof)
                    .unwrap_err(),
                VoprfError::Batch
            );
            assert_eq!(
                client
                    .finalize_batch(&states, &[b"in"], $($info,)? &[evaluated, evaluated], &proof)
                    .unwrap_err(),
                VoprfError::Batch
            );
            let no_states: [_; 0] = [];
            assert_eq!(
                client
                    .finalize_batch(&no_states, &no_inputs, $($info,)? &empty, &proof)
                    .unwrap_err(),
                VoprfError::Batch
            );
        }

        /// A batch of the maximum size is accepted by the shape check and then
        /// rejected on its first element; one more is rejected by shape alone.
        #[test]
        fn batch_size_limit_is_65535() {
            let (server, _) = setup();
            let zeros = vec![[0u8; $ne]; 65535];
            assert_eq!(
                server.blind_evaluate_batch(&zeros, $($info,)? &mut rng()).unwrap_err(),
                VoprfError::Deserialize
            );
        }

        /// The input check of every element of a batch, in every position, and
        /// before the evaluated elements are even parsed.
        #[test]
        fn batch_input_check_covers_every_position() {
            let (server, client) = setup();
            let inputs: [&[u8]; 3] = [b"first", b"second", b"third"];
            let mut states = Vec::new();
            let mut blinded = Vec::new();
            for input in inputs {
                let (state, b) = client.blind(input, $($info,)? &mut rng()).unwrap();
                states.push(state);
                blinded.push(b);
            }
            let (evaluated, proof) =
                server.blind_evaluate_batch(&blinded, $($info,)? &mut rng()).unwrap();
            for position in 0..3 {
                let mut wrong = inputs;
                wrong[position] = b"other";
                assert_eq!(
                    client
                        .finalize_batch(&states, &wrong, $($info,)? &evaluated, &proof)
                        .unwrap_err(),
                    VoprfError::InputMismatch
                );
            }
            let swapped: [&[u8]; 3] = [inputs[1], inputs[0], inputs[2]];
            assert_eq!(
                client
                    .finalize_batch(&states, &swapped, $($info,)? &evaluated, &proof)
                    .unwrap_err(),
                VoprfError::InputMismatch
            );
            // A wrong input is reported even when the evaluated elements are
            // garbage too: caller errors come before server errors.
            let garbage = vec![[0xffu8; $ne]; 3];
            let mut wrong = inputs;
            wrong[2] = b"other";
            assert_eq!(
                client
                    .finalize_batch(&states, &wrong, $($info,)? &garbage, &proof)
                    .unwrap_err(),
                VoprfError::InputMismatch
            );
        }

        #[test]
        fn input_check_catches_any_change() {
            let (server, client) = setup();
            let input = b"exactly this input";
            let (state, blinded) = client.blind(input, $($info,)? &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            let mut flipped = *input;
            flipped[0] ^= 1;
            let extended = [input.as_slice(), b"!"].concat();
            for wrong in [&flipped[..], &input[..input.len() - 1], &extended, &[]] {
                assert_eq!(
                    client.finalize(&state, wrong, $($info,)? &evaluated, &proof).unwrap_err(),
                    VoprfError::InputMismatch
                );
            }
        }

        #[test]
        fn batch_matches_singles_and_detects_reordering() {
            let (server, client) = setup();
            let inputs: [&[u8]; 3] = [b"a", b"b", b"c"];
            let mut states = Vec::new();
            let mut blinded = Vec::new();
            for input in inputs {
                let (state, b) = client.blind(input, $($info,)? &mut rng()).unwrap();
                states.push(state);
                blinded.push(b);
            }
            let (evaluated, proof) =
                server.blind_evaluate_batch(&blinded, $($info,)? &mut rng()).unwrap();
            let outputs = client
                .finalize_batch(&states, &inputs, $($info,)? &evaluated, &proof)
                .unwrap();
            for (input, output) in inputs.iter().zip(&outputs) {
                assert_eq!(**output, *server.evaluate(input, $($info)?).unwrap());
            }
            let mut swapped = evaluated.clone();
            swapped.swap(0, 1);
            assert_eq!(
                client
                    .finalize_batch(&states, &inputs, $($info,)? &swapped, &proof)
                    .unwrap_err(),
                VoprfError::Verify
            );
        }

        #[test]
        fn input_length_bound_is_65535_bytes() {
            let (server, client) = setup();
            let longest = vec![7u8; 65535];
            let too_long = vec![7u8; 65536];
            let (state, blinded) = client.blind(&longest, $($info,)? &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            let output = client.finalize(&state, &longest, $($info,)? &evaluated, &proof).unwrap();
            assert_eq!(*output, *server.evaluate(&longest, $($info)?).unwrap());
            assert_eq!(
                client.blind(&too_long, $($info,)? &mut rng()).unwrap_err(),
                VoprfError::InputTooLong
            );
            assert_eq!(
                server.evaluate(&too_long, $($info)?).unwrap_err(),
                VoprfError::InputTooLong
            );
            assert_eq!(
                client.finalize(&state, &too_long, $($info,)? &evaluated, &proof).unwrap_err(),
                VoprfError::InputTooLong
            );
        }

        #[test]
        fn debug_output_is_redacted() {
            let (server, client) = setup();
            let (state, _) = client.blind(b"in", $($info,)? &mut rng()).unwrap();
            assert_eq!(alloc::format!("{server:?}"), concat!(stringify!($server), " { .. }"));
            assert_eq!(alloc::format!("{client:?}"), concat!(stringify!($client), " { .. }"));
            assert!(alloc::format!("{state:?}").ends_with("ClientState { .. }"));
        }

        /// The hedged nonce, recovered from each proof as `r = s + c * k`: the
        /// same RNG bytes give the same nonce for the same key and statement,
        /// and a different nonce for other RNG bytes, another blinded element
        /// or another key — the last two are what the hedge is for. Nonces, not
        /// proofs, are compared: `c` hashes the statement, so two proofs of
        /// different statements differ whatever their nonces. Another key also
        /// changes the statement (`Bm` and `Z` depend on it), so this cannot
        /// tell the key's own term in the nonce hash from the statement's; the
        /// known-answer test pins that term. Every proof from `server`
        /// verifies.
        #[test]
        fn hedged_nonce_depends_on_randomness_key_and_statement() {
            use $crate::verifiable_oprf::protocol::test_support::proof_nonce;
            let (server, client) = setup();
            let (state_a, blinded_a) = client.blind(b"a", $($info,)? &mut rng()).unwrap();
            let (state_b, blinded_b) = client.blind(b"b", $($info,)? &mut rng()).unwrap();
            let prove = |server: &$server, blinded: &[u8], rand: u8| {
                let mut rng = ScriptedRng::new(&[rand; 32]);
                let (evaluated, proof) = server.blind_evaluate(blinded, $($info,)? &mut rng).unwrap();
                (evaluated, proof, proof_nonce::<$group>(&server.0, $mode, &proof))
            };
            let (eval_a, proof_a1, r_a1) = prove(&server, &blinded_a, 1);
            let (_, proof_a1_again, r_a1_again) = prove(&server, &blinded_a, 1);
            let (_, proof_a2, r_a2) = prove(&server, &blinded_a, 2);
            let (eval_b, proof_b1, r_b1) = prove(&server, &blinded_b, 1);
            assert_eq!(proof_a1, proof_a1_again);
            assert_eq!(r_a1, r_a1_again);
            assert_ne!(r_a1, r_a2);
            // The same RNG bytes and another statement: another nonce.
            assert_ne!(r_a1, r_b1);
            for proof in [proof_a1, proof_a2] {
                assert!(client.finalize(&state_a, b"a", $($info,)? &eval_a, &proof).is_ok());
            }
            assert!(client.finalize(&state_b, b"b", $($info,)? &eval_b, &proof_b1).is_ok());
            // The same RNG bytes and blinded element, another key: another nonce.
            let other = $server::generate(&mut rng());
            let (_, _, r_other) = prove(&other, &blinded_a, 1);
            assert_ne!(r_other, r_a1);
        }

        #[cfg(feature = "hazmat")]
        #[test]
        fn deterministic_blind_rejects_bytes_reducing_to_zero() {
            let (_, client) = setup();
            let wide_order: [u8; 64] = $wide_order;
            let wide_zero_high: [u8; 64] = $wide_zero_high;
            // 0, the order itself, and a value whose high half is nonzero —
            // all reduce to zero.
            for zero in [[0u8; 64], wide_order, wide_zero_high] {
                assert_eq!(
                    client.deterministic_blind(b"in", $($info,)? &zero).unwrap_err(),
                    VoprfError::InvalidInput
                );
            }
        }

        #[cfg(feature = "hazmat")]
        #[test]
        fn deterministic_blind_is_deterministic_and_round_trips() {
            let (server, client) = setup();
            let bytes = [0x5c; 64];
            let (state, blinded) = client.deterministic_blind(b"in", $($info,)? &bytes).unwrap();
            let (_, again) = client.deterministic_blind(b"in", $($info,)? &bytes).unwrap();
            assert_eq!(blinded, again, "equal (input, blind) give equal blinded elements");
            let (_, other_input) = client.deterministic_blind(b"other", $($info,)? &bytes).unwrap();
            assert_ne!(blinded, other_input);
            let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng()).unwrap();
            let output = client.finalize(&state, b"in", $($info,)? &evaluated, &proof).unwrap();
            assert_eq!(*output, *server.evaluate(b"in", $($info)?).unwrap());
        }
    };
}

pub(crate) use behaviour_tests;

/// POPRF-only behaviour: the role of `info`.
macro_rules! poprf_info_tests {
    (server: $server:ident, client: $client:ident, group: $group:ty $(,)?) => {
        /// The `info` is fixed at `blind`: the state stores the tweaked key it
        /// gives (RFC 9497 §3.3.3), and `finalize` requires the same one. A
        /// different `info` at `finalize` is the caller's error; a server that
        /// evaluated under another `info` fails verification. A state blinded
        /// by a client holding another public key is the caller's error too.
        #[test]
        fn info_is_fixed_at_blind_and_checked_against_the_server() {
            let (server, client) = setup();
            let (state, blinded) = client.blind(b"in", b"agreed", &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, b"agreed", &mut rng()).unwrap();
            let output = client.finalize(&state, b"in", b"agreed", &evaluated, &proof).unwrap();
            assert_eq!(*output, *server.evaluate(b"in", b"agreed").unwrap());
            for other in [&b"other"[..], b"", b"agreed "] {
                assert_eq!(
                    client.finalize(&state, b"in", other, &evaluated, &proof).unwrap_err(),
                    VoprfError::InputMismatch
                );
            }
            // The server evaluated under another info than the client agreed.
            let (evaluated, proof) = server.blind_evaluate(&blinded, b"other", &mut rng()).unwrap();
            assert_eq!(
                client.finalize(&state, b"in", b"agreed", &evaluated, &proof).unwrap_err(),
                VoprfError::Verify
            );
            // The state was blinded by a client holding another key.
            let (other_server, other_client) = setup();
            let (foreign, blinded) = other_client.blind(b"in", b"agreed", &mut rng()).unwrap();
            let (evaluated, proof) = other_server.blind_evaluate(&blinded, b"agreed", &mut rng()).unwrap();
            assert_eq!(
                client.finalize(&foreign, b"in", b"agreed", &evaluated, &proof).unwrap_err(),
                VoprfError::InputMismatch
            );
        }

        /// Two POPRF proofs that share a nonce under two `info`s reveal the key:
        /// their tweaked keys differ by a known amount. The same RNG bytes and
        /// the same blinded element under another `info` give another nonce.
        #[test]
        fn hedged_nonce_differs_across_info() {
            use $crate::verifiable_oprf::protocol::{test_support::proof_nonce, Mode};
            let (server, client) = setup();
            let (_, blinded) = client.blind(b"in", b"one", &mut rng()).unwrap();
            let nonce = |info: &[u8]| {
                let mut rng = ScriptedRng::new(&[1; 32]);
                let (_, proof) = server.blind_evaluate(&blinded, info, &mut rng).unwrap();
                proof_nonce::<$group>(&server.0, Mode::Poprf(info), &proof)
            };
            assert_eq!(nonce(b"one"), nonce(b"one"));
            assert_ne!(nonce(b"one"), nonce(b"two"));
        }

        #[test]
        fn blinded_element_does_not_depend_on_info() {
            let (_, client) = setup();
            let script = [0x11u8; 64];
            let (_, a) = client.blind(b"in", b"one", &mut ScriptedRng::new(&script)).unwrap();
            let (_, b) = client.blind(b"in", b"two", &mut ScriptedRng::new(&script)).unwrap();
            assert_eq!(a, b);
        }

        /// RFC 9497 §3.3.3: if `skS = -HashToScalar(framedInfo)`, the tweaked
        /// key `t` is zero. The server raises `InverseError`; a client sees the
        /// identity as the tweaked key and raises `InvalidInputError` in
        /// `blind`, before any request is sent.
        #[test]
        fn zero_tweak_is_rejected_on_both_sides() {
            let info = b"aimed at this key";
            let key = $crate::verifiable_oprf::protocol::test_support::key_with_zero_tweak::<$group>(info);
            let server = $server::from_secret_key(&key).unwrap();
            let client = $client::new(&server.public_key()).unwrap();
            let (_, honest_client) = setup();
            let (_, blinded) = honest_client.blind(b"in", info, &mut rng()).unwrap();
            assert_eq!(
                server.blind_evaluate(&blinded, info, &mut rng()).unwrap_err(),
                VoprfError::Inverse
            );
            assert_eq!(server.evaluate(b"in", info).unwrap_err(), VoprfError::Inverse);
            assert_eq!(
                client.blind(b"in", info, &mut rng()).unwrap_err(),
                VoprfError::InvalidInput
            );
            // Any other info works with the same key.
            let (state, blinded) = client.blind(b"in", b"other", &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, b"other", &mut rng()).unwrap();
            assert!(client.finalize(&state, b"in", b"other", &evaluated, &proof).is_ok());
        }

        #[test]
        fn info_length_bound_is_65535_bytes() {
            let (server, client) = setup();
            let longest = alloc::vec![9u8; 65535];
            let too_long = alloc::vec![9u8; 65536];
            let (state, blinded) = client.blind(b"in", &longest, &mut rng()).unwrap();
            let (evaluated, proof) = server.blind_evaluate(&blinded, &longest, &mut rng()).unwrap();
            assert!(client.finalize(&state, b"in", &longest, &evaluated, &proof).is_ok());
            assert_eq!(
                client.blind(b"in", &too_long, &mut rng()).unwrap_err(),
                VoprfError::InputTooLong
            );
            assert_eq!(
                server.blind_evaluate(&blinded, &too_long, &mut rng()).unwrap_err(),
                VoprfError::InputTooLong
            );
            assert_eq!(server.evaluate(b"in", &too_long).unwrap_err(), VoprfError::InputTooLong);
            assert_eq!(
                client.finalize(&state, b"in", &too_long, &evaluated, &proof).unwrap_err(),
                VoprfError::InputTooLong
            );
            assert_eq!(
                $server::derive(&[7; 32], &too_long).unwrap_err(),
                VoprfError::InputTooLong
            );
        }
    };
}

pub(crate) use poprf_info_tests;
