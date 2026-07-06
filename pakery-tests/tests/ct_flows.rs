//! Constant-time verification harness (ctgrind pattern, roadmap item 6).
//!
//! Runs full protocol flows for all four PAKEs on both groups with secret
//! material marked *undefined* for Valgrind memcheck (via `pakery_core::ct`,
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
//!   sending, accept/reject decisions, secret-scalar canonicity checks at
//!   the dalek/p256 parse boundary) is documented at the `ct` call sites in
//!   the library crates and summarized in `pakery_core::ct`'s module docs.
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
