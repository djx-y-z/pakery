//! Constant-time verification harness (ctgrind pattern, roadmap item 6).
//!
//! Runs full protocol flows for all four PAKEs and for the RFC 9497 VOPRF /
//! POPRF, on both groups, with secret material marked *undefined* for
//! Valgrind memcheck (via `pakery_core::ct`,
//! wired up by the `__ctgrind` feature). Under
//! `valgrind --track-origins=yes --error-exitcode=99` any secret-dependent
//! branch or memory index in the compiled artifact — including what LLVM
//! makes of `subtle` in release mode — surfaces as a memcheck error.
//!
//! ct.yml runs this test binary under Valgrind in debug **and** release on
//! every PR and daily. Outside Valgrind (e.g. ordinary `--all-features` test
//! runs) the marks are runtime no-ops and these tests are plain happy-path
//! flow checks.
//!
//! Scope notes:
//! - OPAQUE uses the identity-KSF suites: Argon2id is data-dependent by
//!   design in its second half (RFC 9106 accepts this hybrid trade-off), so
//!   running it tainted would only flag Argon2's documented design choice.
//! - Everything intentionally declassified (wire messages, MAC tags before
//!   sending, accept/reject decisions, and the secret-scalar canonicity checks
//!   of the base-mode ristretto255 OPRF and Diffie-Hellman parses, laundered
//!   because their `.into_option()` branches; the P-256 parses since 0.6.1,
//!   like the RFC 9497 modes' parses on both suites, keep the scalar tainted)
//!   is documented at the `ct` call sites in the library crates and summarized
//!   in `pakery_core::ct`'s module docs.
//! - All randomness is a seeded `ChaCha20Rng`, so runs are deterministic.

#![cfg(feature = "__ctgrind")]

use pakery_core::crypto::{CpaceGroup, Hash};
use pakery_core::ct;
use pakery_cpace::{CpaceInitiator, CpaceMode, CpaceResponder};
use pakery_crypto::Sha512Hash;
use pakery_opaque::{
    ClientLogin, ClientRegistration, ServerLogin, ServerRegistration, ServerSetup,
};
use pakery_spake2::{PartyA, PartyB};
use pakery_spake2plus::{compute_verifier, Prover, Verifier};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const PASSWORD: &[u8] = b"correct horse battery staple";
const WRONG_PASSWORD: &[u8] = b"correct horse battery stable";

/// Guard against a silently disarmed run: the ct helpers downgrade to no-ops
/// when crabgrind was built without real Valgrind headers (see
/// `pakery_core::ct::is_active`). ct.yml sets `PAKERY_CT_EXPECT_ARMED=1`, so
/// a CI image that lost its Valgrind headers fails loudly instead of going
/// green without checking anything.
#[test]
fn ct_harness_is_armed() {
    if std::env::var_os("PAKERY_CT_EXPECT_ARMED").is_some() {
        assert!(
            ct::is_active(),
            "PAKERY_CT_EXPECT_ARMED is set but the ct helpers are no-ops \
             (crabgrind built without Valgrind headers?)"
        );
    }
}

/// Guard against flows that silently vanish: the P-256 and `hazmat` flows
/// below are compiled only with their features, so a CT run built without
/// either would go green while checking less. ct.yml sets
/// `PAKERY_CT_EXPECT_ARMED=1` and builds with both.
#[test]
fn ct_harness_covers_every_flow() {
    if std::env::var_os("PAKERY_CT_EXPECT_ARMED").is_some() {
        #[cfg(not(all(feature = "p256", feature = "hazmat")))]
        panic!("the CT run must enable `p256` and `hazmat`, or their flows are compiled out");
    }
}

/// Compare two secret byte strings inside the harness. The pass/fail outcome
/// of a test assertion is public, so both sides are declassified first —
/// otherwise the comparison itself would (correctly) be flagged.
fn assert_secret_eq(a: &[u8], b: &[u8]) {
    ct::declassify(a);
    ct::declassify(b);
    assert_eq!(a, b);
}

/// A password buffer marked secret. The library entry points mark their
/// password arguments too; marking here as well keeps the harness honest
/// even for inputs that reach the protocol via caller-side derivation
/// (e.g. the SPAKE2 `w` scalars).
fn secret_password(pw: &[u8]) -> Vec<u8> {
    let buf = pw.to_vec();
    ct::mark_secret(&buf);
    buf
}

// ---------------------------------------------------------------------------
// CPace
// ---------------------------------------------------------------------------

fn cpace_flow<C: pakery_cpace::CpaceCiphersuite>(mode: CpaceMode, seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let password = secret_password(PASSWORD);

    let (ya, state) = CpaceInitiator::<C>::start(
        &password,
        b"channel-id",
        b"session-id-0123",
        b"adi",
        &mut rng,
    )
    .unwrap();
    let (yb, out_b) = CpaceResponder::<C>::respond(
        &ya,
        &password,
        b"channel-id",
        b"session-id-0123",
        b"adi",
        b"adr",
        mode,
        &mut rng,
    )
    .unwrap();
    let out_a = state.finish(&yb, b"adr", mode).unwrap();

    assert_secret_eq(out_a.isk.as_bytes(), out_b.isk.as_bytes());
    // The session id is public output; no declassification required.
    assert_eq!(out_a.session_id, out_b.session_id);
}

#[test]
fn ct_cpace_ristretto255() {
    cpace_flow::<pakery_crypto::CpaceRistretto255>(CpaceMode::InitiatorResponder, 1);
    cpace_flow::<pakery_crypto::CpaceRistretto255>(CpaceMode::Symmetric, 2);
}

#[cfg(feature = "p256")]
#[test]
fn ct_cpace_p256() {
    cpace_flow::<pakery_crypto::CpaceP256>(CpaceMode::InitiatorResponder, 3);
    cpace_flow::<pakery_crypto::CpaceP256>(CpaceMode::Symmetric, 4);
}

// ---------------------------------------------------------------------------
// SPAKE2
// ---------------------------------------------------------------------------

/// Password scalar as in the property tests: `scalar_from_wide_bytes` of a
/// SHA-512 digest. The digest of a marked password is tainted, and the wide
/// reduction is branch-free, so `w` carries taint into the protocol.
fn pw_scalar<G: CpaceGroup>(password: &[u8]) -> G::Scalar {
    let digest = Sha512Hash::digest(password);
    G::scalar_from_wide_bytes(&digest).expect("SHA-512 output is 64 bytes")
}

fn spake2_flow<C: pakery_spake2::Spake2Ciphersuite>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let password = secret_password(PASSWORD);
    let w = pw_scalar::<C::Group>(&password);

    let (pa, state_a) = PartyA::<C>::start(&w, b"client", b"server", b"aad", &mut rng).unwrap();
    let (pb, state_b) = PartyB::<C>::start(&w, b"client", b"server", b"aad", &mut rng).unwrap();

    let out_a = state_a.finish(&pb).unwrap();
    let out_b = state_b.finish(&pa).unwrap();

    out_a
        .verify_peer_confirmation(&out_b.confirmation_mac)
        .unwrap();
    out_b
        .verify_peer_confirmation(&out_a.confirmation_mac)
        .unwrap();
    assert_secret_eq(out_a.session_key.as_bytes(), out_b.session_key.as_bytes());
}

#[test]
fn ct_spake2_ristretto255() {
    spake2_flow::<pakery_crypto::Spake2Ristretto255>(5);
}

#[cfg(feature = "p256")]
#[test]
fn ct_spake2_p256() {
    spake2_flow::<pakery_crypto::Spake2P256>(6);
}

// ---------------------------------------------------------------------------
// SPAKE2+
// ---------------------------------------------------------------------------

fn spake2plus_flow<C: pakery_spake2plus::Spake2PlusCiphersuite>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let password = secret_password(PASSWORD);

    let mut h0 = Sha512Hash::new();
    h0.update(&password);
    h0.update(b"pakery-ct-w0");
    let w0 = <C::Group as CpaceGroup>::scalar_from_wide_bytes(&h0.finalize())
        .expect("SHA-512 output is 64 bytes");
    let mut h1 = Sha512Hash::new();
    h1.update(&password);
    h1.update(b"pakery-ct-w1");
    let w1 = <C::Group as CpaceGroup>::scalar_from_wide_bytes(&h1.finalize())
        .expect("SHA-512 output is 64 bytes");

    let l_bytes = compute_verifier::<C>(&w1);

    let (share_p, prover_state) =
        Prover::<C>::start(&w0, &w1, b"ct-context", b"prover", b"verifier", &mut rng).unwrap();
    let (share_v, confirm_v, verifier_state) = Verifier::<C>::start(
        &share_p,
        &w0,
        &l_bytes,
        b"ct-context",
        b"prover",
        b"verifier",
        &mut rng,
    )
    .unwrap();
    let prover_out = prover_state.finish(&share_v, &confirm_v).unwrap();
    let verifier_out = verifier_state.finish(&prover_out.confirm_p).unwrap();

    assert_secret_eq(
        prover_out.session_key.as_bytes(),
        verifier_out.session_key.as_bytes(),
    );
}

#[test]
fn ct_spake2plus_ristretto255() {
    spake2plus_flow::<pakery_crypto::Spake2PlusRistretto255>(7);
}

#[cfg(feature = "p256")]
#[test]
fn ct_spake2plus_p256() {
    spake2plus_flow::<pakery_crypto::Spake2PlusP256>(8);
}

// ---------------------------------------------------------------------------
// OPAQUE (identity-KSF suites — see the module docs for the Argon2 note)
// ---------------------------------------------------------------------------

fn opaque_flow<C: pakery_opaque::OpaqueCiphersuite>(seed: u64) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let password = secret_password(PASSWORD);

    // Registration.
    let setup = ServerSetup::<C>::new(&mut rng).unwrap();
    let (request, reg_state) = ClientRegistration::<C>::start(&password, &mut rng).unwrap();
    let response = ServerRegistration::<C>::start(&setup, &request, b"credential-id").unwrap();
    let (record, reg_export_key) = reg_state
        .finish(&response, b"server", b"client", &mut rng)
        .unwrap();

    // Login (happy path).
    let (ke1, client_state) = ClientLogin::<C>::start(&password, &mut rng).unwrap();
    let (ke2, server_state) = ServerLogin::<C>::start(
        &setup,
        &record,
        &ke1,
        b"credential-id",
        b"ct-context",
        b"server",
        b"client",
        &mut rng,
    )
    .unwrap();
    let (ke3, client_session_key, login_export_key) = client_state
        .finish(&ke2, b"ct-context", b"server", b"client")
        .unwrap();
    let server_session_key = server_state.finish(&ke3).unwrap();

    assert_secret_eq(client_session_key.as_bytes(), server_session_key.as_bytes());
    assert_secret_eq(&reg_export_key, &login_export_key);

    // Login with the wrong password: envelope recovery must fail (the
    // rejection path also runs under the same taint).
    let wrong = secret_password(WRONG_PASSWORD);
    let (ke1_w, client_state_w) = ClientLogin::<C>::start(&wrong, &mut rng).unwrap();
    let (ke2_w, _server_state_w) = ServerLogin::<C>::start(
        &setup,
        &record,
        &ke1_w,
        b"credential-id",
        b"ct-context",
        b"server",
        b"client",
        &mut rng,
    )
    .unwrap();
    assert!(client_state_w
        .finish(&ke2_w, b"ct-context", b"server", b"client")
        .is_err());

    // Fake credentials path (user enumeration defense): the client must
    // fail at envelope recovery.
    let (ke1_f, client_state_f) = ClientLogin::<C>::start(&password, &mut rng).unwrap();
    let ke2_f = ServerLogin::<C>::start_fake(
        &setup,
        &ke1_f,
        b"unknown-credential",
        b"ct-context",
        b"server",
        b"client",
        &mut rng,
    )
    .unwrap();
    assert!(client_state_f
        .finish(&ke2_f, b"ct-context", b"server", b"client")
        .is_err());
}

#[test]
fn ct_opaque_ristretto255() {
    opaque_flow::<pakery_crypto::OpaqueRistretto255>(9);
}

#[cfg(feature = "p256")]
#[test]
fn ct_opaque_p256() {
    opaque_flow::<pakery_crypto::OpaqueP256>(10);
}

// ---------------------------------------------------------------------------
// RFC 9497 VOPRF / POPRF
// ---------------------------------------------------------------------------

/// A copy of `bytes` marked secret (keys, seeds, deterministic blinds).
fn secret_array<const N: usize>(bytes: [u8; N]) -> [u8; N] {
    ct::mark_secret(&bytes);
    bytes
}

/// One suite and mode. The server key comes three ways — `derive` from a
/// marked seed, `from_secret_key` of a marked key, `generate` — and each runs a
/// single request, a batch of three, the deterministic blind (with `hazmat`),
/// and the rejection paths, all with the input marked secret. Wire values
/// (public key, blinded and evaluated elements, proof) are compared with plain
/// `assert_eq!`: memcheck would flag that comparison if the library had not
/// declassified them, so it doubles as a check that it did.
macro_rules! verifiable_flow {
    ($name:ident, server: $server:ty, client: $client:ty, info: [$($info:expr)?] $(,)?) => {
        fn $name(seed: u64) {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let derived = <$server>::derive(&secret_array([0x5a; 32]), b"ct-key-info").unwrap();
            let imported = <$server>::from_secret_key(&secret_array(*derived.secret_key())).unwrap();
            assert_eq!(derived.public_key(), imported.public_key());
            let generated = <$server>::generate(&mut rng);

            for server in [&derived, &imported, &generated] {
                let client = <$client>::new(&server.public_key()).unwrap();
                let input = secret_password(PASSWORD);

                // A single request.
                let (state, blinded) = client.blind(&input, $($info,)? &mut rng).unwrap();
                let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng).unwrap();
                let output = client.finalize(&state, &input, $($info,)? &evaluated, &proof).unwrap();
                assert_secret_eq(&*output, &*server.evaluate(&input, $($info)?).unwrap());

                // Rejections under taint: another input, a flipped proof byte.
                let wrong = secret_password(WRONG_PASSWORD);
                assert!(client.finalize(&state, &wrong, $($info,)? &evaluated, &proof).is_err());
                let mut tampered = proof;
                tampered[40] ^= 1;
                assert!(client.finalize(&state, &input, $($info,)? &evaluated, &tampered).is_err());

                // A batch of three.
                let inputs = [secret_password(b"one"), secret_password(b"two"), input.clone()];
                let mut states = Vec::new();
                let mut batch = Vec::new();
                for i in &inputs {
                    let (state, b) = client.blind(i, $($info,)? &mut rng).unwrap();
                    states.push(state);
                    batch.push(b);
                }
                let (evaluated, proof) =
                    server.blind_evaluate_batch(&batch, $($info,)? &mut rng).unwrap();
                let outputs = client
                    .finalize_batch(&states, &inputs, $($info,)? &evaluated, &proof)
                    .unwrap();
                assert_secret_eq(&*outputs[2], &*output);

                // The deterministic blind: the bytes are secret, the blinded
                // element is not.
                #[cfg(feature = "hazmat")]
                {
                    let blind = secret_array([0x33; 64]);
                    let (state, blinded) = client.deterministic_blind(&input, $($info,)? &blind).unwrap();
                    let (_, again) = client.deterministic_blind(&input, $($info,)? &blind).unwrap();
                    assert_eq!(blinded, again);
                    let (evaluated, proof) = server.blind_evaluate(&blinded, $($info,)? &mut rng).unwrap();
                    let det = client.finalize(&state, &input, $($info,)? &evaluated, &proof).unwrap();
                    assert_secret_eq(&*det, &*output);
                }
            }
        }
    };
}

verifiable_flow!(
    voprf_flow_ristretto255,
    server: pakery_crypto::Ristretto255VoprfServer,
    client: pakery_crypto::Ristretto255VoprfClient,
    info: [],
);
verifiable_flow!(
    poprf_flow_ristretto255,
    server: pakery_crypto::Ristretto255PoprfServer,
    client: pakery_crypto::Ristretto255PoprfClient,
    info: [b"ct-info"],
);
#[cfg(feature = "p256")]
verifiable_flow!(
    voprf_flow_p256,
    server: pakery_crypto::P256VoprfServer,
    client: pakery_crypto::P256VoprfClient,
    info: [],
);
#[cfg(feature = "p256")]
verifiable_flow!(
    poprf_flow_p256,
    server: pakery_crypto::P256PoprfServer,
    client: pakery_crypto::P256PoprfClient,
    info: [b"ct-info"],
);

#[test]
fn ct_voprf_ristretto255() {
    voprf_flow_ristretto255(11);
}

#[test]
fn ct_poprf_ristretto255() {
    poprf_flow_ristretto255(12);
    // A finalize info other than the blinded one is refused under taint too.
    let server =
        pakery_crypto::Ristretto255PoprfServer::generate(&mut ChaCha20Rng::seed_from_u64(13));
    let client = pakery_crypto::Ristretto255PoprfClient::new(&server.public_key()).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(14);
    let input = secret_password(PASSWORD);
    let (state, blinded) = client.blind(&input, b"one", &mut rng).unwrap();
    let (evaluated, proof) = server.blind_evaluate(&blinded, b"one", &mut rng).unwrap();
    assert!(client
        .finalize(&state, &input, b"two", &evaluated, &proof)
        .is_err());
}

#[cfg(feature = "p256")]
#[test]
fn ct_voprf_p256() {
    voprf_flow_p256(15);
}

#[cfg(feature = "p256")]
#[test]
fn ct_poprf_p256() {
    poprf_flow_p256(16);
}
