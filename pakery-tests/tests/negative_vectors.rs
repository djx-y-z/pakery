//! Negative-vector sweep for OPAQUE, SPAKE2, SPAKE2+ and the RFC 9497
//! VOPRF / POPRF (see SECURITY_TESTING.md, "Negative test vectors").
//!
//! RFC 9807 (OPAQUE), RFC 9382 (SPAKE2) and RFC 9383 (SPAKE2+) ship no
//! negative test vectors, so `vectors/negative_vectors.json` carries
//! home-grown known-bad inputs constructed from the group specifications:
//!
//! - ristretto255 invalid point encodings: RFC 9496 appendix A.2 (the
//!   complete list of encodings that MUST be rejected);
//! - P-256 invalid point encodings: SEC1 violations, including Y_i1 from
//!   draft-irtf-cfrg-cpace-21 appendix B.5.11 (testvectors.json at
//!   https://github.com/cfrg/draft-irtf-cfrg-cpace, commit
//!   8fb4056e1b9201927d9f651b9970d9d5660c7892);
//! - scalars: zero and non-canonical (>= group order) encodings.
//!
//! Every invalid encoding must be rejected by every entry point that
//! consumes attacker-controlled bytes:
//!
//! - `CpaceGroup::from_bytes` (both groups);
//! - `DhGroup::diffie_hellman` (bad peer public key, bad/zero secret
//!   scalar);
//! - `Oprf::server_evaluate` (bad blinded element, bad/zero OPRF key) and
//!   `OprfClientState::finalize` (bad evaluated element);
//! - the VOPRF / POPRF types of both suites: the client's public key, the
//!   server's secret key, blinded elements (single and in a batch), evaluated
//!   elements (single and in a batch), and the proof's two scalars — where a
//!   non-canonical scalar is a deserialization error and a zero one a
//!   verification failure, RFC 9497 §4 allowing `[0, p - 1]`;
//! - SPAKE2 `finish` on both parties (bad peer share);
//! - SPAKE2+ `Verifier::start` (bad prover share) and `Prover::finish`
//!   (bad verifier share);
//! - OPAQUE registration and login step functions (bad blinded/evaluated
//!   elements and bad key shares inside otherwise-valid messages, plus a
//!   bad client public key inside a stored registration record).
//!
//! Identity ("neutral element") encodings are *valid* encodings, so
//! `from_bytes` may accept them — but every protocol entry point must
//! still abort on them (small-subgroup/identity defense).

use pakery_core::crypto::{CpaceGroup, DhGroup, Oprf, OprfClientState};
use serde::Deserialize;

#[derive(Deserialize)]
struct Entry {
    name: String,
    hex: String,
    reason: String,
}

#[derive(Deserialize)]
struct GroupVectors {
    identity_point: Entry,
    invalid_points: Vec<Entry>,
    non_canonical_scalars: Vec<Entry>,
    zero_scalar: Entry,
}

#[derive(Deserialize)]
struct VectorFile {
    ristretto255: GroupVectors,
    #[cfg(feature = "p256")]
    p256: GroupVectors,
}

fn vectors() -> VectorFile {
    serde_json::from_str(include_str!("../vectors/negative_vectors.json"))
        .expect("negative_vectors.json must parse")
}

fn h(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("valid hex")
}

/// All bad point encodings: the invalid ones plus the identity encoding.
/// Both classes must be rejected by protocol-level entry points.
fn bad_points(v: &GroupVectors) -> impl Iterator<Item = &Entry> {
    v.invalid_points
        .iter()
        .chain(core::iter::once(&v.identity_point))
}

/// All bad scalar encodings: non-canonical ones plus zero.
fn bad_scalars(v: &GroupVectors) -> impl Iterator<Item = &Entry> {
    v.non_canonical_scalars
        .iter()
        .chain(core::iter::once(&v.zero_scalar))
}

// --- Group decoding ---

fn sweep_group_decode<G: CpaceGroup>(v: &GroupVectors) {
    for e in &v.invalid_points {
        assert!(
            G::from_bytes(&h(&e.hex)).is_err(),
            "from_bytes must reject {}: {}",
            e.name,
            e.reason
        );
    }
    // The identity encoding may decode, but never to a non-identity point.
    if let Ok(p) = G::from_bytes(&h(&v.identity_point.hex)) {
        assert!(
            p.is_identity(),
            "{} must decode to the identity if it decodes at all",
            v.identity_point.name
        );
    }
}

// --- Diffie-Hellman ---

fn sweep_dh<D: DhGroup>(v: &GroupVectors) {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let (sk, pk) = D::generate_keypair(&mut rng).expect("keypair");

    for e in bad_points(v) {
        assert!(
            D::diffie_hellman(&sk, &h(&e.hex)).is_err(),
            "diffie_hellman must reject peer public key {}: {}",
            e.name,
            e.reason
        );
    }
    for e in bad_scalars(v) {
        // Zero is a canonical scalar, but DH with it yields the identity,
        // which the identity check after the multiplication must catch.
        assert!(
            D::diffie_hellman(&h(&e.hex), &pk).is_err(),
            "diffie_hellman must reject secret scalar {}: {}",
            e.name,
            e.reason
        );
    }
}

// --- OPRF ---

fn sweep_oprf<O: Oprf>(v: &GroupVectors) {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let oprf_key = O::derive_key(&[0x07; 32], b"negative-vector-sweep").expect("OPRF key");
    let (state, blinded) = O::client_blind(b"password", &mut rng).expect("blind");

    for e in bad_points(v) {
        assert!(
            O::server_evaluate(&oprf_key, &h(&e.hex)).is_err(),
            "server_evaluate must reject blinded element {}: {}",
            e.name,
            e.reason
        );
        assert!(
            state.finalize(b"password", &h(&e.hex)).is_err(),
            "client finalize must reject evaluated element {}: {}",
            e.name,
            e.reason
        );
    }
    for e in bad_scalars(v) {
        assert!(
            O::server_evaluate(&h(&e.hex), &blinded).is_err(),
            "server_evaluate must reject OPRF key {}: {}",
            e.name,
            e.reason
        );
    }
}

// --- RFC 9497 VOPRF / POPRF ---

macro_rules! sweep_verifiable {
    ($name:ident, server: $server:ty, client: $client:ty, info: [$($info:expr)?] $(,)?) => {
        fn $name(v: &GroupVectors) {
            use pakery_crypto::VoprfError;
            let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
            let server = <$server>::derive(&[0x07; 32], b"negative-vector-sweep").expect("key");
            let client = <$client>::new(&server.public_key()).expect("public key");
            let (state, blinded) = client.blind(b"password", $($info,)? &mut rng).expect("blind");
            let (evaluated, proof) = server
                .blind_evaluate(&blinded, $($info,)? &mut rng)
                .expect("evaluate");
            // A batch of two, whose second evaluated element is replaced below;
            // the untouched batch finalizes, so a rejection is the bad element's.
            let batch_inputs = [b"password".as_slice(), b"second input".as_slice()];
            let mut batch_states = Vec::new();
            let mut batch_blinded = Vec::new();
            for input in batch_inputs {
                let (state, blinded) = client.blind(input, $($info,)? &mut rng).expect("blind");
                batch_states.push(state);
                batch_blinded.push(blinded);
            }
            let (batch_evaluated, batch_proof) = server
                .blind_evaluate_batch(&batch_blinded, $($info,)? &mut rng)
                .expect("evaluate batch");
            client
                .finalize_batch(
                    &batch_states,
                    &batch_inputs,
                    $($info,)?
                    &batch_evaluated,
                    &batch_proof,
                )
                .expect("the untouched batch finalizes");

            for e in bad_points(v) {
                let bad = h(&e.hex);
                let ctx = |what: &str| format!("{what} must reject {}: {}", e.name, e.reason);
                assert_eq!(<$client>::new(&bad).unwrap_err(), VoprfError::Deserialize, "{}", ctx("Client::new"));
                assert_eq!(
                    server.blind_evaluate(&bad, $($info,)? &mut rng).unwrap_err(),
                    VoprfError::Deserialize,
                    "{}",
                    ctx("blind_evaluate")
                );
                assert_eq!(
                    server
                        .blind_evaluate_batch(&[blinded.as_slice(), &bad], $($info,)? &mut rng)
                        .unwrap_err(),
                    VoprfError::Deserialize,
                    "{}",
                    ctx("blind_evaluate_batch")
                );
                assert_eq!(
                    client.finalize(&state, b"password", $($info,)? &bad, &proof).unwrap_err(),
                    VoprfError::Deserialize,
                    "{}",
                    ctx("finalize")
                );
                assert_eq!(
                    client
                        .finalize_batch(
                            &batch_states,
                            &batch_inputs,
                            $($info,)?
                            &[batch_evaluated[0].as_slice(), bad.as_slice()],
                            &batch_proof,
                        )
                        .unwrap_err(),
                    VoprfError::Deserialize,
                    "{}",
                    ctx("finalize_batch")
                );
            }
            for e in bad_scalars(v) {
                assert_eq!(
                    <$server>::from_secret_key(&h(&e.hex)).unwrap_err(),
                    VoprfError::Deserialize,
                    "from_secret_key must reject {}: {}",
                    e.name,
                    e.reason
                );
            }
            for e in &v.non_canonical_scalars {
                let bad = h(&e.hex);
                for half in [0..32, 32..64] {
                    let mut tampered = proof;
                    tampered[half].copy_from_slice(&bad);
                    assert_eq!(
                        client.finalize(&state, b"password", $($info,)? &evaluated, &tampered).unwrap_err(),
                        VoprfError::Deserialize,
                        "a proof scalar {} must not deserialize: {}",
                        e.name,
                        e.reason
                    );
                }
            }
            let zero = h(&v.zero_scalar.hex);
            for half in [0..32, 32..64] {
                let mut tampered = proof;
                tampered[half].copy_from_slice(&zero);
                assert_eq!(
                    client.finalize(&state, b"password", $($info,)? &evaluated, &tampered).unwrap_err(),
                    VoprfError::Verify,
                    "a zero proof scalar deserializes (RFC 9497 §4) and must fail verification"
                );
            }
        }
    };
}

sweep_verifiable!(
    sweep_ristretto255_voprf,
    server: pakery_crypto::Ristretto255VoprfServer,
    client: pakery_crypto::Ristretto255VoprfClient,
    info: [],
);
sweep_verifiable!(
    sweep_ristretto255_poprf,
    server: pakery_crypto::Ristretto255PoprfServer,
    client: pakery_crypto::Ristretto255PoprfClient,
    info: [b"negative-vector-sweep info"],
);
#[cfg(feature = "p256")]
sweep_verifiable!(
    sweep_p256_voprf,
    server: pakery_crypto::P256VoprfServer,
    client: pakery_crypto::P256VoprfClient,
    info: [],
);
#[cfg(feature = "p256")]
sweep_verifiable!(
    sweep_p256_poprf,
    server: pakery_crypto::P256PoprfServer,
    client: pakery_crypto::P256PoprfClient,
    info: [b"negative-vector-sweep info"],
);

// --- SPAKE2 (RFC 9382) ---

fn sweep_spake2<C: pakery_spake2::Spake2Ciphersuite>(v: &GroupVectors) {
    use pakery_spake2::{PartyA, PartyB};

    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let w = C::Group::scalar_from_wide_bytes(&[0x2a; 64]).expect("w scalar");

    for e in bad_points(v) {
        let bad = h(&e.hex);

        let (_, state_a) = PartyA::<C>::start(&w, b"alice", b"bob", b"aad", &mut rng).unwrap();
        assert!(
            state_a.finish(&bad).is_err(),
            "SPAKE2 party A must reject share {}: {}",
            e.name,
            e.reason
        );

        let (_, state_b) = PartyB::<C>::start(&w, b"alice", b"bob", b"aad", &mut rng).unwrap();
        assert!(
            state_b.finish(&bad).is_err(),
            "SPAKE2 party B must reject share {}: {}",
            e.name,
            e.reason
        );
    }
}

// --- SPAKE2+ (RFC 9383) ---

fn sweep_spake2plus<C: pakery_spake2plus::Spake2PlusCiphersuite>(v: &GroupVectors) {
    use pakery_spake2plus::registration::compute_verifier;
    use pakery_spake2plus::{Prover, Verifier};

    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let w0 = C::Group::scalar_from_wide_bytes(&[0x2a; 64]).expect("w0 scalar");
    let w1 = C::Group::scalar_from_wide_bytes(&[0x2b; 64]).expect("w1 scalar");
    let l_bytes = compute_verifier::<C>(&w1);
    let context = b"negative-vector-sweep";

    for e in bad_points(v) {
        let bad = h(&e.hex);

        // Verifier receives the bad point as the prover's share.
        assert!(
            Verifier::<C>::start(&bad, &w0, &l_bytes, context, b"client", b"server", &mut rng)
                .is_err(),
            "SPAKE2+ verifier must reject shareP {}: {}",
            e.name,
            e.reason
        );

        // Prover receives the bad point as the verifier's share. The share
        // must be rejected before any MAC comparison, so a dummy confirmV
        // of the right length is sufficient.
        let (_, prover_state) =
            Prover::<C>::start(&w0, &w1, context, b"client", b"server", &mut rng).unwrap();
        assert!(
            prover_state.finish(&bad, &vec![0u8; C::NH]).is_err(),
            "SPAKE2+ prover must reject shareV {}: {}",
            e.name,
            e.reason
        );
    }
}

// --- OPAQUE (RFC 9807) ---

fn sweep_opaque<C: pakery_opaque::OpaqueCiphersuite>(v: &GroupVectors) {
    use pakery_opaque::{
        ClientLogin, ClientRegistration, ServerLogin, ServerRegistration, ServerSetup,
    };

    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let password = b"password";
    let cred_id = b"credential-id";
    let context = b"negative-vector-sweep";
    let server_id = b"server";
    let client_id = b"client";

    // Honest registration to obtain a valid record for the login sweeps.
    let setup = ServerSetup::<C>::new(&mut rng).unwrap();
    let (request, reg_state) = ClientRegistration::<C>::start(password, &mut rng).unwrap();
    let response = ServerRegistration::<C>::start(&setup, &request, cred_id).unwrap();
    let (record, _) = reg_state
        .finish(&response, server_id, client_id, &mut rng)
        .unwrap();

    for e in bad_points(v) {
        let bad = h(&e.hex);

        // Registration request with a bad blinded element.
        let (mut req, _) = ClientRegistration::<C>::start(password, &mut rng).unwrap();
        req.blinded_message = bad.clone();
        assert!(
            ServerRegistration::<C>::start(&setup, &req, cred_id).is_err(),
            "OPAQUE server registration must reject blinded element {}: {}",
            e.name,
            e.reason
        );

        // Registration response with a bad evaluated element.
        let (req, state) = ClientRegistration::<C>::start(password, &mut rng).unwrap();
        let mut resp = ServerRegistration::<C>::start(&setup, &req, cred_id).unwrap();
        resp.evaluated_message = bad.clone();
        assert!(
            state.finish(&resp, server_id, client_id, &mut rng).is_err(),
            "OPAQUE client registration must reject evaluated element {}: {}",
            e.name,
            e.reason
        );

        // KE1 with a bad blinded element.
        let (mut ke1, _) = ClientLogin::<C>::start(password, &mut rng).unwrap();
        ke1.blinded_message = bad.clone();
        assert!(
            ServerLogin::<C>::start(
                &setup, &record, &ke1, cred_id, context, server_id, client_id, &mut rng,
            )
            .is_err(),
            "OPAQUE server must reject KE1 blinded element {}: {}",
            e.name,
            e.reason
        );

        // KE1 with a bad client key share.
        let (mut ke1, _) = ClientLogin::<C>::start(password, &mut rng).unwrap();
        ke1.client_keyshare = bad.clone();
        assert!(
            ServerLogin::<C>::start(
                &setup, &record, &ke1, cred_id, context, server_id, client_id, &mut rng,
            )
            .is_err(),
            "OPAQUE server must reject KE1 client key share {}: {}",
            e.name,
            e.reason
        );

        // KE2 with a bad evaluated element.
        let (ke1, client_state) = ClientLogin::<C>::start(password, &mut rng).unwrap();
        let (mut ke2, _) = ServerLogin::<C>::start(
            &setup, &record, &ke1, cred_id, context, server_id, client_id, &mut rng,
        )
        .unwrap();
        ke2.evaluated_message = bad.clone();
        assert!(
            client_state
                .finish(&ke2, context, server_id, client_id)
                .is_err(),
            "OPAQUE client must reject KE2 evaluated element {}: {}",
            e.name,
            e.reason
        );

        // KE2 with a bad server key share.
        let (ke1, client_state) = ClientLogin::<C>::start(password, &mut rng).unwrap();
        let (mut ke2, _) = ServerLogin::<C>::start(
            &setup, &record, &ke1, cred_id, context, server_id, client_id, &mut rng,
        )
        .unwrap();
        ke2.server_keyshare = bad.clone();
        assert!(
            client_state
                .finish(&ke2, context, server_id, client_id)
                .is_err(),
            "OPAQUE client must reject KE2 server key share {}: {}",
            e.name,
            e.reason
        );

        // Stored record with a bad client public key. The record is server
        // state rather than a wire message, but its public key feeds the
        // server's 3DH, so a non-canonical encoding must still be rejected
        // (the opaque_flow fuzzer hit this via the SEC1 compact tag: a
        // decompactable 0x05-tag copy of the stored key let a tampered
        // record complete a login with agreeing keys — issue #13).
        let (ke1, _) = ClientLogin::<C>::start(password, &mut rng).unwrap();
        let mut bad_record = record.clone();
        bad_record.client_public_key = bad.clone();
        assert!(
            ServerLogin::<C>::start(
                &setup,
                &bad_record,
                &ke1,
                cred_id,
                context,
                server_id,
                client_id,
                &mut rng,
            )
            .is_err(),
            "OPAQUE server must reject record client public key {}: {}",
            e.name,
            e.reason
        );
    }
}

// --- Ristretto255 suite ---

#[test]
fn ristretto255_group_decode() {
    sweep_group_decode::<pakery_crypto::Ristretto255Group>(&vectors().ristretto255);
}

#[test]
fn ristretto255_dh() {
    sweep_dh::<pakery_crypto::Ristretto255Dh>(&vectors().ristretto255);
}

#[test]
fn ristretto255_oprf() {
    sweep_oprf::<pakery_crypto::Ristretto255Oprf>(&vectors().ristretto255);
}

#[test]
fn ristretto255_verifiable_oprf() {
    sweep_ristretto255_voprf(&vectors().ristretto255);
    sweep_ristretto255_poprf(&vectors().ristretto255);
}

#[test]
fn ristretto255_spake2() {
    sweep_spake2::<pakery_crypto::Spake2Ristretto255>(&vectors().ristretto255);
}

#[test]
fn ristretto255_spake2plus() {
    sweep_spake2plus::<pakery_crypto::Spake2PlusRistretto255>(&vectors().ristretto255);
}

#[test]
fn ristretto255_opaque() {
    sweep_opaque::<pakery_crypto::OpaqueRistretto255>(&vectors().ristretto255);
}

// --- P-256 suite ---

#[cfg(feature = "p256")]
mod p256_suite {
    use super::*;

    #[test]
    fn p256_group_decode() {
        sweep_group_decode::<pakery_crypto::P256Group>(&vectors().p256);
    }

    #[test]
    fn p256_dh() {
        sweep_dh::<pakery_crypto::P256Dh>(&vectors().p256);
    }

    #[test]
    fn p256_oprf() {
        sweep_oprf::<pakery_crypto::P256Oprf>(&vectors().p256);
    }

    #[test]
    fn p256_verifiable_oprf() {
        sweep_p256_voprf(&vectors().p256);
        sweep_p256_poprf(&vectors().p256);
    }

    #[test]
    fn p256_spake2() {
        sweep_spake2::<pakery_crypto::Spake2P256>(&vectors().p256);
    }

    #[test]
    fn p256_spake2plus() {
        sweep_spake2plus::<pakery_crypto::Spake2PlusP256>(&vectors().p256);
    }

    #[test]
    fn p256_opaque() {
        sweep_opaque::<pakery_crypto::OpaqueP256>(&vectors().p256);
    }
}
