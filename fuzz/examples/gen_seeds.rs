//! Regenerate the checked-in seed corpus under `fuzz/seeds/`.
//!
//! Run from the `fuzz/` directory:
//!
//! ```text
//! cargo run --example gen_seeds
//! ```
//!
//! Seeds are valid protocol messages: the RFC 9807 test-vector messages
//! (D.1.1, the same hex as `pakery-tests/tests/opaque_vectors.rs`) plus
//! messages from deterministic honest flows for both ciphersuites.
//!
//! Deliberately NOT seeded: valid confirmation-MAC pairs for the
//! `spake2_flow` / `spake2plus_flow` targets. Those targets assert that a
//! fuzz-supplied MAC never verifies (forging one requires the password);
//! a seed constructed here *with* the password would trip that assert.
//! Shares are therefore paired with all-zero MACs.

use pakery_core::crypto::{CpaceGroup, DhGroup, Hash, Oprf};
use pakery_cpace::{CpaceCiphersuite, CpaceInitiator, CpaceMode, CpaceResponder};
use pakery_crypto::{
    CpaceP256, CpaceRistretto255, OpaqueP256, OpaqueRistretto255, P256Dh, P256Group, P256Oprf,
    Ristretto255Dh, Ristretto255Group, Ristretto255Oprf, Sha512Hash, Spake2P256, Spake2PlusP256,
    Spake2PlusRistretto255, Spake2Ristretto255,
};
use pakery_opaque::{
    ClientLogin, ClientRegistration, CredentialResponse, Envelope, OpaqueCiphersuite, ServerLogin,
    ServerRegistration, ServerSetup,
};
use pakery_spake2::{PartyA, PartyB, Spake2Ciphersuite};
use pakery_spake2plus::{compute_verifier, Prover, Spake2PlusCiphersuite, Verifier};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use std::fs;
use std::path::PathBuf;

fn seed_dir(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("seeds")
        .join(target)
}

fn write_seed(target: &str, name: &str, bytes: &[u8]) {
    let dir = seed_dir(target);
    fs::create_dir_all(&dir).expect("create seed dir");
    fs::write(dir.join(name), bytes).expect("write seed");
}

fn with_sel(sel: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![sel];
    out.extend_from_slice(bytes);
    out
}

fn with_sel_cut(sel: u8, cut: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![sel, cut];
    out.extend_from_slice(bytes);
    out
}

// RFC 9807 test vector D.1.1 (real ristretto255 suite messages, identical to
// the constants in pakery-tests/tests/opaque_vectors.rs).
const RFC9807_REGISTRATION_REQUEST: &str =
    "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71";
const RFC9807_REGISTRATION_RESPONSE: &str = "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78";
const RFC9807_REGISTRATION_UPLOAD: &str = "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5";
const RFC9807_ENVELOPE: &str = "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5";
const RFC9807_KE1: &str = "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326";
const RFC9807_KE2: &str = "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90";
const RFC9807_KE3: &str = "4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442";

/// One deterministic honest OPAQUE flow; returns all 8 serialized messages.
#[allow(clippy::type_complexity)]
fn opaque_messages<C: OpaqueCiphersuite>() -> [Vec<u8>; 8] {
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let setup = ServerSetup::<C>::new(&mut rng).unwrap();
    let (request, state) = ClientRegistration::<C>::start(b"password", &mut rng).unwrap();
    let response = ServerRegistration::<C>::start(&setup, &request, b"cred-id").unwrap();
    let (record, _) = state
        .finish(&response, b"server", b"client", &mut rng)
        .unwrap();
    let (ke1, client_state) = ClientLogin::<C>::start(b"password", &mut rng).unwrap();
    let (ke2, _) = ServerLogin::<C>::start(
        &setup, &record, &ke1, b"cred-id", b"context", b"server", b"client", &mut rng,
    )
    .unwrap();
    let (ke3, _, _) = client_state
        .finish(&ke2, b"context", b"server", b"client")
        .unwrap();
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
    [
        request.serialize(),
        response.serialize(),
        record.serialize(),
        envelope.serialize(),
        credential_response.serialize(),
        ke1.serialize(),
        ke2.serialize(),
        ke3.serialize(),
    ]
}

fn opaque_deserialize_seeds() {
    // Selector: low 3 bits = message type, bit 3 = suite (0 = ristretto255).
    let rfc = [
        (0u8, RFC9807_REGISTRATION_REQUEST),
        (1, RFC9807_REGISTRATION_RESPONSE),
        (2, RFC9807_REGISTRATION_UPLOAD),
        (3, RFC9807_ENVELOPE),
        (5, RFC9807_KE1),
        (6, RFC9807_KE2),
        (7, RFC9807_KE3),
    ];
    for (kind, hex_str) in rfc {
        let bytes = hex::decode(hex_str).unwrap();
        write_seed(
            "opaque_deserialize",
            &format!("rfc9807-r255-{kind}"),
            &with_sel(kind, &bytes),
        );
    }
    for (suite_bit, msgs) in [
        (0u8, opaque_messages::<OpaqueRistretto255>()),
        (8, opaque_messages::<OpaqueP256>()),
    ] {
        for (kind, msg) in msgs.iter().enumerate() {
            write_seed(
                "opaque_deserialize",
                &format!(
                    "honest-{}-{kind}",
                    if suite_bit == 0 { "r255" } else { "p256" }
                ),
                &with_sel(suite_bit | kind as u8, msg),
            );
        }
    }
}

fn group_decode_seeds_for<G: CpaceGroup, D: DhGroup, O: Oprf>(base: u8, tag: &str) {
    let point = G::from_uniform_bytes(&[0x42; 64]).unwrap().to_bytes();
    write_seed(
        "group_decode",
        &format!("{tag}-point"),
        &with_sel_cut(base, 0, &point),
    );
    write_seed(
        "group_decode",
        &format!("{tag}-uniform"),
        &with_sel_cut(base + 1, 0, &[0x42; 64]),
    );
    write_seed(
        "group_decode",
        &format!("{tag}-wide-scalar"),
        &with_sel_cut(base + 2, 0, &[0x5a; 64]),
    );
    let (sk, pk) = D::derive_keypair(b"gen-seeds-dh").unwrap();
    let mut dh = sk.to_vec();
    let cut = dh.len() as u8;
    dh.extend_from_slice(&pk);
    write_seed(
        "group_decode",
        &format!("{tag}-dh"),
        &with_sel_cut(base + 3, cut, &dh),
    );
    write_seed(
        "group_decode",
        &format!("{tag}-dh-pk"),
        &with_sel_cut(base + 4, 0, &pk),
    );
    let key = O::derive_key(b"gen-seeds-oprf", b"fuzz").unwrap();
    let mut rng = ChaCha8Rng::seed_from_u64(2);
    let (_state, blinded) = O::client_blind(b"password", &mut rng).unwrap();
    let mut eval = key.to_vec();
    let cut = eval.len() as u8;
    eval.extend_from_slice(&blinded);
    write_seed(
        "group_decode",
        &format!("{tag}-oprf-eval"),
        &with_sel_cut(base + 7, cut, &eval),
    );
    let evaluated = O::server_evaluate(&key, &blinded).unwrap();
    write_seed(
        "group_decode",
        &format!("{tag}-oprf-finalize"),
        &with_sel_cut(base + 9, 0, &evaluated),
    );
}

fn cpace_seeds_for<C: CpaceCiphersuite>(suite_bit: u8, tag: &str) {
    // Must mirror the constants in fuzz_targets/cpace_flow.rs.
    let (password, ci, sid, ad_a, ad_b) = (
        b"pakery-fuzz-password".as_slice(),
        b"pakery-fuzz-channel".as_slice(),
        b"pakery-fuzz-sid".as_slice(),
        b"ad-initiator".as_slice(),
        b"ad-responder".as_slice(),
    );
    let mut rng = ChaCha8Rng::seed_from_u64(3);
    let (ya, _state) = CpaceInitiator::<C>::start(password, ci, sid, ad_a, &mut rng).unwrap();
    let (yb, _out) = CpaceResponder::<C>::respond(
        &ya,
        password,
        ci,
        sid,
        ad_a,
        ad_b,
        CpaceMode::InitiatorResponder,
        &mut rng,
    )
    .unwrap();
    for mode_bit in [0u8, 2] {
        // Initiator receives yb (bit 2 clear), responder receives ya (bit 2 set).
        write_seed(
            "cpace_flow",
            &format!("{tag}-mode{mode_bit}-to-initiator"),
            &with_sel(suite_bit | mode_bit, &yb),
        );
        write_seed(
            "cpace_flow",
            &format!("{tag}-mode{mode_bit}-to-responder"),
            &with_sel(suite_bit | mode_bit | 4, &ya),
        );
    }
}

fn spake2_seeds_for<C: Spake2Ciphersuite>(suite_bit: u8, tag: &str) {
    let digest = Sha512Hash::digest(b"pakery-fuzz-password");
    let w = <C::Group as CpaceGroup>::scalar_from_wide_bytes(&digest).unwrap();
    let mut rng = ChaCha8Rng::seed_from_u64(4);
    let (pa, _) =
        PartyA::<C>::start(&w, b"fuzz-alice", b"fuzz-bob", b"fuzz-aad", &mut rng).unwrap();
    let (pb, _) =
        PartyB::<C>::start(&w, b"fuzz-alice", b"fuzz-bob", b"fuzz-aad", &mut rng).unwrap();
    // Valid share + all-zero MAC (see module comment: never seed a real MAC).
    let mut to_a = pb;
    to_a.extend_from_slice(&[0u8; 64]);
    write_seed(
        "spake2_flow",
        &format!("{tag}-share-to-a"),
        &with_sel(suite_bit | 2, &to_a),
    );
    let mut to_b = pa;
    to_b.extend_from_slice(&[0u8; 64]);
    write_seed(
        "spake2_flow",
        &format!("{tag}-share-to-b"),
        &with_sel(suite_bit, &to_b),
    );
}

fn spake2plus_seeds_for<C: Spake2PlusCiphersuite>(suite_bit: u8, tag: &str) {
    let mut h0 = Sha512Hash::new();
    h0.update(b"pakery-fuzz-password");
    h0.update(b"w0");
    let w0 = <C::Group as CpaceGroup>::scalar_from_wide_bytes(&h0.finalize()).unwrap();
    let mut h1 = Sha512Hash::new();
    h1.update(b"pakery-fuzz-password");
    h1.update(b"w1");
    let w1 = <C::Group as CpaceGroup>::scalar_from_wide_bytes(&h1.finalize()).unwrap();
    let l_bytes = compute_verifier::<C>(&w1);
    let mut rng = ChaCha8Rng::seed_from_u64(5);
    let (share_p, _state) = Prover::<C>::start(
        &w0,
        &w1,
        b"fuzz-context",
        b"fuzz-prover",
        b"fuzz-verifier",
        &mut rng,
    )
    .unwrap();
    let (share_v, _confirm_v, _vstate) = Verifier::<C>::start(
        &share_p,
        &w0,
        &l_bytes,
        b"fuzz-context",
        b"fuzz-prover",
        b"fuzz-verifier",
        &mut rng,
    )
    .unwrap();
    // which = (sel >> 1) % 3; suite is bit 0.
    write_seed(
        "spake2plus_flow",
        &format!("{tag}-share-p"),
        &with_sel_cut(suite_bit, 0, &share_p),
    );
    // Valid shareV + all-zero confirmV (see module comment).
    let mut to_prover = share_v.clone();
    let cut = to_prover.len() as u8;
    to_prover.extend_from_slice(&vec![0u8; C::NH]);
    write_seed(
        "spake2plus_flow",
        &format!("{tag}-share-v"),
        &with_sel_cut(suite_bit | 2, cut, &to_prover),
    );
    write_seed(
        "spake2plus_flow",
        &format!("{tag}-confirm-p"),
        &with_sel_cut(suite_bit | 4, 0, &vec![0u8; C::NH]),
    );
}

fn opaque_flow_seeds() {
    // Structure-aware target: `arbitrary` decodes these blobs into a
    // FlowInput. A run of zeros is the minimal honest ristretto255 flow;
    // the patterned blob exercises longer inputs and the tamper arm.
    write_seed("opaque_flow", "zeros", &[0u8; 64]);
    let patterned: Vec<u8> = (0..256u16).map(|i| (i % 251) as u8).collect();
    write_seed("opaque_flow", "patterned", &patterned);
}

fn main() {
    opaque_deserialize_seeds();
    group_decode_seeds_for::<Ristretto255Group, Ristretto255Dh, Ristretto255Oprf>(0, "r255");
    group_decode_seeds_for::<P256Group, P256Dh, P256Oprf>(10, "p256");
    cpace_seeds_for::<CpaceRistretto255>(0, "r255");
    cpace_seeds_for::<CpaceP256>(1, "p256");
    spake2_seeds_for::<Spake2Ristretto255>(0, "r255");
    spake2_seeds_for::<Spake2P256>(1, "p256");
    spake2plus_seeds_for::<Spake2PlusRistretto255>(0, "r255");
    spake2plus_seeds_for::<Spake2PlusP256>(1, "p256");
    opaque_flow_seeds();
    println!("seeds written to {}", seed_dir("").display());
}
