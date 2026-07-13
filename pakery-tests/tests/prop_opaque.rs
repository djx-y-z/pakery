//! Property-based self-play tests for OPAQUE (RFC 9807).
//!
//! Suites: `OpaqueRistretto255` (always) and `OpaqueP256` (feature `p256`).
//! Both use the identity KSF, so property runs stay fast (no Argon2). All
//! randomness is driven through a `ChaCha20Rng` seeded from a
//! proptest-generated `u64`.
//!
//! Properties (see SECURITY_TESTING.md, "Property-based tests"):
//! 1. Agreement: registration + login with the same password derives equal
//!    session keys on both sides and the same export key at registration
//!    and login.
//! 2. Mismatch: a wrong login password fails envelope recovery on the
//!    client; a differing context or identity fails the client's KE2 check;
//!    a `start_fake` KE2 always fails on the client. No mismatch ever
//!    yields agreeing keys.
//! 3. Tamper rejection: flipping any single byte of any wire message
//!    (registration request/response/record, KE1, KE2, KE3) makes some
//!    receiving step return `Err` — for registration-time tampering this is
//!    observed at the latest when a subsequent honest login fails.
//! 4. Serialization roundtrip: for all 8 message types,
//!    `deserialize(m.serialize())` re-serializes byte-identically.
//! 5. Truncation sweep: `deserialize` rejects every strict prefix and
//!    length extension of every valid message.

use pakery_opaque::{
    ClientLogin, ClientRegistration, CredentialResponse, Envelope, OpaqueCiphersuite, OpaqueError,
    RegistrationRecord, RegistrationRequest, RegistrationResponse, ServerLogin, ServerRegistration,
    ServerSetup, KE1, KE2, KE3,
};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[derive(Debug, Clone)]
struct Inputs {
    password: Vec<u8>,
    cred_id: Vec<u8>,
    context: Vec<u8>,
    server_id: Vec<u8>,
    client_id: Vec<u8>,
}

fn bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max_len)
}

fn inputs() -> impl Strategy<Value = Inputs> {
    (bytes(32), bytes(16), bytes(16), bytes(16), bytes(16)).prop_map(
        |(password, cred_id, context, server_id, client_id)| Inputs {
            password,
            cred_id,
            context,
            server_id,
            client_id,
        },
    )
}

/// Honest registration; returns the server setup, the stored record, and a
/// copy of the client's export key.
fn register<C: OpaqueCiphersuite>(
    inp: &Inputs,
    rng: &mut ChaCha20Rng,
) -> (ServerSetup<C>, RegistrationRecord, Vec<u8>) {
    let setup = ServerSetup::<C>::new(rng).unwrap();
    let (request, state) = ClientRegistration::<C>::start(&inp.password, rng).unwrap();
    let response = ServerRegistration::<C>::start(&setup, &request, &inp.cred_id).unwrap();
    let (record, export_key) = state
        .finish(&response, &inp.server_id, &inp.client_id, rng)
        .unwrap();
    (setup, record, export_key.to_vec())
}

/// Property 1: honest registration + login agree on session and export keys.
fn agreement<C: OpaqueCiphersuite>(inp: &Inputs, seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (setup, record, reg_export_key) = register::<C>(inp, &mut rng);

    let (ke1, client_state) = ClientLogin::<C>::start(&inp.password, &mut rng).unwrap();
    let (ke2, server_state) = ServerLogin::<C>::start(
        &setup,
        &record,
        &ke1,
        &inp.cred_id,
        &inp.context,
        &inp.server_id,
        &inp.client_id,
        &mut rng,
    )
    .unwrap();
    let (ke3, client_session_key, login_export_key) = client_state
        .finish(&ke2, &inp.context, &inp.server_id, &inp.client_id)
        .unwrap();
    let server_session_key = server_state.finish(&ke3).unwrap();

    assert_eq!(client_session_key.as_bytes(), server_session_key.as_bytes());
    assert_eq!(reg_export_key, login_export_key.to_vec());
}

/// Property 2a: a wrong password fails envelope recovery on the client.
fn wrong_password<C: OpaqueCiphersuite>(inp: &Inputs, wrong: &[u8], seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (setup, record, _) = register::<C>(inp, &mut rng);

    let (ke1, client_state) = ClientLogin::<C>::start(wrong, &mut rng).unwrap();
    let (ke2, _) = ServerLogin::<C>::start(
        &setup,
        &record,
        &ke1,
        &inp.cred_id,
        &inp.context,
        &inp.server_id,
        &inp.client_id,
        &mut rng,
    )
    .unwrap();
    let err = client_state
        .finish(&ke2, &inp.context, &inp.server_id, &inp.client_id)
        .unwrap_err();
    assert!(matches!(err, OpaqueError::EnvelopeRecoveryError));
}

/// Property 2b: a differing context or identity fails the client's KE2 check.
fn auth_input_mismatch<C: OpaqueCiphersuite>(inp: &Inputs, field: usize, seed: u64) {
    let mut client = inp.clone();
    match field {
        0 => client.context.push(0x5a),
        1 => client.server_id.push(0x5a),
        _ => client.client_id.push(0x5a),
    }

    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (setup, record, _) = register::<C>(inp, &mut rng);

    let (ke1, client_state) = ClientLogin::<C>::start(&inp.password, &mut rng).unwrap();
    let (ke2, _) = ServerLogin::<C>::start(
        &setup,
        &record,
        &ke1,
        &inp.cred_id,
        &inp.context,
        &inp.server_id,
        &inp.client_id,
        &mut rng,
    )
    .unwrap();
    assert!(client_state
        .finish(&ke2, &client.context, &client.server_id, &client.client_id)
        .is_err());
}

/// Property 2c: a `start_fake` KE2 always fails envelope recovery.
fn fake_login<C: OpaqueCiphersuite>(inp: &Inputs, seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let setup = ServerSetup::<C>::new(&mut rng).unwrap();

    let (ke1, client_state) = ClientLogin::<C>::start(&inp.password, &mut rng).unwrap();
    let ke2 = ServerLogin::<C>::start_fake(
        &setup,
        &ke1,
        &inp.cred_id,
        &inp.context,
        &inp.server_id,
        &inp.client_id,
        &mut rng,
    )
    .unwrap();
    let err = client_state
        .finish(&ke2, &inp.context, &inp.server_id, &inp.client_id)
        .unwrap_err();
    assert!(matches!(err, OpaqueError::EnvelopeRecoveryError));
}

fn flip_byte(msg: &[u8], idx: prop::sample::Index, flip: u8) -> Vec<u8> {
    let mut bad = msg.to_vec();
    let i = idx.index(bad.len());
    bad[i] ^= flip;
    bad
}

/// Property 3: tampered registration messages are either rejected outright
/// or poison the record so that a subsequent honest login fails.
///
/// `which`: 0 = RegistrationRequest, 1 = RegistrationResponse, 2 = record.
fn tamper_registration<C: OpaqueCiphersuite>(
    inp: &Inputs,
    which: usize,
    seed: u64,
    idx: prop::sample::Index,
    flip: u8,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let setup = ServerSetup::<C>::new(&mut rng).unwrap();
    let (request, state) = ClientRegistration::<C>::start(&inp.password, &mut rng).unwrap();

    let record = match which {
        0 => {
            let Ok(bad_request) =
                RegistrationRequest::deserialize::<C>(&flip_byte(&request.serialize(), idx, flip))
            else {
                return;
            };
            let Ok(response) = ServerRegistration::<C>::start(&setup, &bad_request, &inp.cred_id)
            else {
                return;
            };
            let Ok((record, _)) = state.finish(&response, &inp.server_id, &inp.client_id, &mut rng)
            else {
                return;
            };
            record
        }
        1 => {
            let response = ServerRegistration::<C>::start(&setup, &request, &inp.cred_id).unwrap();
            let Ok(bad_response) = RegistrationResponse::deserialize::<C>(&flip_byte(
                &response.serialize(),
                idx,
                flip,
            )) else {
                return;
            };
            let Ok((record, _)) =
                state.finish(&bad_response, &inp.server_id, &inp.client_id, &mut rng)
            else {
                return;
            };
            record
        }
        _ => {
            let response = ServerRegistration::<C>::start(&setup, &request, &inp.cred_id).unwrap();
            let (record, _) = state
                .finish(&response, &inp.server_id, &inp.client_id, &mut rng)
                .unwrap();
            let Ok(bad_record) =
                RegistrationRecord::deserialize::<C>(&flip_byte(&record.serialize(), idx, flip))
            else {
                return;
            };
            bad_record
        }
    };

    // Registration did not detect the tampering; an honest login against the
    // poisoned record must fail on the client (envelope/MAC mismatch).
    let (ke1, client_state) = ClientLogin::<C>::start(&inp.password, &mut rng).unwrap();
    let Ok((ke2, _)) = ServerLogin::<C>::start(
        &setup,
        &record,
        &ke1,
        &inp.cred_id,
        &inp.context,
        &inp.server_id,
        &inp.client_id,
        &mut rng,
    ) else {
        return;
    };
    assert!(client_state
        .finish(&ke2, &inp.context, &inp.server_id, &inp.client_id)
        .is_err());
}

/// Property 3: tampered KE1/KE2/KE3 make some login step fail.
///
/// `which`: 0 = KE1, 1 = KE2, 2 = KE3.
fn tamper_login<C: OpaqueCiphersuite>(
    inp: &Inputs,
    which: usize,
    seed: u64,
    idx: prop::sample::Index,
    flip: u8,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (setup, record, _) = register::<C>(inp, &mut rng);
    let (ke1, client_state) = ClientLogin::<C>::start(&inp.password, &mut rng).unwrap();

    if which == 0 {
        let Ok(bad_ke1) = KE1::deserialize::<C>(&flip_byte(&ke1.serialize(), idx, flip)) else {
            return;
        };
        let Ok((ke2, _)) = ServerLogin::<C>::start(
            &setup,
            &record,
            &bad_ke1,
            &inp.cred_id,
            &inp.context,
            &inp.server_id,
            &inp.client_id,
            &mut rng,
        ) else {
            return;
        };
        // The client's transcript contains its own KE1, not the tampered one.
        assert!(client_state
            .finish(&ke2, &inp.context, &inp.server_id, &inp.client_id)
            .is_err());
        return;
    }

    let (ke2, server_state) = ServerLogin::<C>::start(
        &setup,
        &record,
        &ke1,
        &inp.cred_id,
        &inp.context,
        &inp.server_id,
        &inp.client_id,
        &mut rng,
    )
    .unwrap();

    if which == 1 {
        let Ok(bad_ke2) = KE2::deserialize::<C>(&flip_byte(&ke2.serialize(), idx, flip)) else {
            return;
        };
        assert!(client_state
            .finish(&bad_ke2, &inp.context, &inp.server_id, &inp.client_id)
            .is_err());
        return;
    }

    let (ke3, _, _) = client_state
        .finish(&ke2, &inp.context, &inp.server_id, &inp.client_id)
        .unwrap();
    let Ok(bad_ke3) = KE3::deserialize::<C>(&flip_byte(&ke3.serialize(), idx, flip)) else {
        return;
    };
    assert!(server_state.finish(&bad_ke3).is_err());
}

/// Property 4: all 8 message types roundtrip byte-identically.
fn roundtrip<C: OpaqueCiphersuite>(inp: &Inputs, seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let setup = ServerSetup::<C>::new(&mut rng).unwrap();
    let (request, state) = ClientRegistration::<C>::start(&inp.password, &mut rng).unwrap();
    let response = ServerRegistration::<C>::start(&setup, &request, &inp.cred_id).unwrap();
    let (record, _) = state
        .finish(&response, &inp.server_id, &inp.client_id, &mut rng)
        .unwrap();
    let (ke1, client_state) = ClientLogin::<C>::start(&inp.password, &mut rng).unwrap();
    let (ke2, _) = ServerLogin::<C>::start(
        &setup,
        &record,
        &ke1,
        &inp.cred_id,
        &inp.context,
        &inp.server_id,
        &inp.client_id,
        &mut rng,
    )
    .unwrap();
    let (ke3, _, _) = client_state
        .finish(&ke2, &inp.context, &inp.server_id, &inp.client_id)
        .unwrap();
    // Envelope comes from the record; a CredentialResponse is assembled from
    // its parts (it never travels alone in the AKE flow).
    let envelope = Envelope {
        nonce: record.envelope.nonce.clone(),
        auth_tag: record.envelope.auth_tag.clone(),
    };
    let credential_response = CredentialResponse {
        server_public_key: response.server_public_key.clone(),
        envelope: Envelope {
            nonce: record.envelope.nonce.clone(),
            auth_tag: record.envelope.auth_tag.clone(),
        },
    };

    macro_rules! check_roundtrip {
        ($ty:ident, $msg:expr) => {{
            let bytes = $msg.serialize();
            let reparsed = $ty::deserialize::<C>(&bytes).unwrap();
            assert_eq!(reparsed.serialize(), bytes);
        }};
    }

    check_roundtrip!(RegistrationRequest, request);
    check_roundtrip!(RegistrationResponse, response);
    check_roundtrip!(RegistrationRecord, record);
    check_roundtrip!(Envelope, envelope);
    check_roundtrip!(CredentialResponse, credential_response);
    check_roundtrip!(KE1, ke1);
    check_roundtrip!(KE2, ke2);
    check_roundtrip!(KE3, ke3);
}

/// Property 5: every strict prefix and extension of every message is
/// rejected by `deserialize`.
fn wrong_length<C: OpaqueCiphersuite>() {
    let inp = Inputs {
        password: b"truncation-password".to_vec(),
        cred_id: b"credential-id".to_vec(),
        context: b"context".to_vec(),
        server_id: b"server".to_vec(),
        client_id: b"client".to_vec(),
    };
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let setup = ServerSetup::<C>::new(&mut rng).unwrap();
    let (request, state) = ClientRegistration::<C>::start(&inp.password, &mut rng).unwrap();
    let response = ServerRegistration::<C>::start(&setup, &request, &inp.cred_id).unwrap();
    let (record, _) = state
        .finish(&response, &inp.server_id, &inp.client_id, &mut rng)
        .unwrap();
    let (ke1, client_state) = ClientLogin::<C>::start(&inp.password, &mut rng).unwrap();
    let (ke2, _) = ServerLogin::<C>::start(
        &setup,
        &record,
        &ke1,
        &inp.cred_id,
        &inp.context,
        &inp.server_id,
        &inp.client_id,
        &mut rng,
    )
    .unwrap();
    let (ke3, _, _) = client_state
        .finish(&ke2, &inp.context, &inp.server_id, &inp.client_id)
        .unwrap();
    let credential_response = CredentialResponse {
        server_public_key: response.server_public_key.clone(),
        envelope: Envelope {
            nonce: record.envelope.nonce.clone(),
            auth_tag: record.envelope.auth_tag.clone(),
        },
    };

    macro_rules! check_wrong_length {
        ($ty:ident, $msg:expr) => {{
            let bytes = $msg.serialize();
            for len in 0..bytes.len() {
                assert!(
                    $ty::deserialize::<C>(&bytes[..len]).is_err(),
                    "{} accepted length {} (expected {})",
                    stringify!($ty),
                    len,
                    bytes.len()
                );
            }
            for extra in [1usize, 8] {
                let mut extended = bytes.clone();
                extended.resize(extended.len() + extra, 0);
                assert!(
                    $ty::deserialize::<C>(&extended).is_err(),
                    "{} accepted length {} (expected {})",
                    stringify!($ty),
                    extended.len(),
                    bytes.len()
                );
            }
        }};
    }

    check_wrong_length!(RegistrationRequest, request);
    check_wrong_length!(RegistrationResponse, response);
    check_wrong_length!(RegistrationRecord, record);
    check_wrong_length!(Envelope, record.envelope);
    check_wrong_length!(CredentialResponse, credential_response);
    check_wrong_length!(KE1, ke1);
    check_wrong_length!(KE2, ke2);
    check_wrong_length!(KE3, ke3);
}

macro_rules! opaque_props {
    ($name:ident, $suite:ty) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(32))]

                #[test]
                fn agreement(inp in inputs(), seed in any::<u64>()) {
                    super::agreement::<$suite>(&inp, seed);
                }

                #[test]
                fn wrong_password(
                    inp in inputs(),
                    wrong in bytes(32),
                    seed in any::<u64>(),
                ) {
                    prop_assume!(wrong != inp.password);
                    super::wrong_password::<$suite>(&inp, &wrong, seed);
                }

                #[test]
                fn auth_input_mismatch(inp in inputs(), field in 0usize..3, seed in any::<u64>()) {
                    super::auth_input_mismatch::<$suite>(&inp, field, seed);
                }

                #[test]
                fn fake_login(inp in inputs(), seed in any::<u64>()) {
                    super::fake_login::<$suite>(&inp, seed);
                }

                #[test]
                fn tamper_registration(
                    inp in inputs(),
                    which in 0usize..3,
                    seed in any::<u64>(),
                    idx in any::<prop::sample::Index>(),
                    flip in 1u8..,
                ) {
                    super::tamper_registration::<$suite>(&inp, which, seed, idx, flip);
                }

                #[test]
                fn tamper_login(
                    inp in inputs(),
                    which in 0usize..3,
                    seed in any::<u64>(),
                    idx in any::<prop::sample::Index>(),
                    flip in 1u8..,
                ) {
                    super::tamper_login::<$suite>(&inp, which, seed, idx, flip);
                }

                #[test]
                fn roundtrip(inp in inputs(), seed in any::<u64>()) {
                    super::roundtrip::<$suite>(&inp, seed);
                }
            }

            #[test]
            fn wrong_length_sweep() {
                super::wrong_length::<$suite>();
            }
        }
    };
}

opaque_props!(ristretto255, pakery_crypto::OpaqueRistretto255);
#[cfg(feature = "p256")]
opaque_props!(p256, pakery_crypto::OpaqueP256);
