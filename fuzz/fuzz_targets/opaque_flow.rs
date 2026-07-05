//! Structure-aware fuzzing of the full OPAQUE registration + login flow.
//!
//! `arbitrary` derives the whole scenario: ciphersuite, all client/server
//! inputs, an optional `start_fake` login, and an optional tamper operation
//! (replace or XOR) applied to one wire message. Every message crosses the
//! wire through `serialize` / `deserialize`, like a real deployment.
//!
//! Invariants:
//! - No step ever panics or overflows.
//! - An untampered flow completes with equal session keys on both sides and
//!   the same export key at registration and login.
//! - A flow whose wire bytes were actually altered never ends in a
//!   completed mutual login (some step must return `Err`).
//! - A client talking to `ServerLogin::start_fake` never completes.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pakery_crypto::{OpaqueP256, OpaqueRistretto255};
use pakery_opaque::{
    ClientLogin, ClientRegistration, OpaqueCiphersuite, RegistrationRecord, RegistrationRequest,
    RegistrationResponse, ServerLogin, ServerRegistration, ServerSetup, KE1, KE2, KE3,
};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq)]
enum Stage {
    RegRequest,
    RegResponse,
    Record,
    Ke1,
    Ke2,
    Ke3,
}

#[derive(Arbitrary, Debug)]
enum TamperMode {
    Replace(Vec<u8>),
    Xor(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct FlowInput {
    suite_p256: bool,
    fake: bool,
    seed: u64,
    password: Vec<u8>,
    cred_id: Vec<u8>,
    context: Vec<u8>,
    server_id: Vec<u8>,
    client_id: Vec<u8>,
    tamper: Option<(Stage, TamperMode)>,
}

fn cap(v: &[u8], n: usize) -> &[u8] {
    &v[..v.len().min(n)]
}

/// Apply the tamper operation if it targets `stage`. Returns the wire bytes
/// and whether they actually differ from the honest serialization.
fn mangle(honest: Vec<u8>, stage: Stage, tamper: &Option<(Stage, TamperMode)>) -> (Vec<u8>, bool) {
    match tamper {
        Some((s, mode)) if *s == stage => match mode {
            TamperMode::Replace(bytes) => {
                let bytes = cap(bytes, 2048).to_vec();
                let changed = bytes != honest;
                (bytes, changed)
            }
            TamperMode::Xor(mask) => {
                let mut out = honest.clone();
                for (byte, m) in out.iter_mut().zip(mask.iter()) {
                    *byte ^= m;
                }
                let changed = out != honest;
                (out, changed)
            }
        },
        _ => (honest, false),
    }
}

/// Deserialize a wire message, panicking if an *untampered* message fails.
macro_rules! recv {
    ($ty:ident, $bytes:expr, $dirty:expr) => {
        match $ty::deserialize::<C>(&$bytes) {
            Ok(msg) => msg,
            Err(_) if $dirty => return,
            Err(e) => panic!(concat!("honest ", stringify!($ty), " rejected: {:?}"), e),
        }
    };
}

/// A protocol step that may only fail on a dirty (tampered) flow.
macro_rules! step {
    ($res:expr, $dirty:expr, $what:literal) => {
        match $res {
            Ok(v) => v,
            Err(_) if $dirty => return,
            Err(e) => panic!(concat!("honest ", $what, " failed: {:?}"), e),
        }
    };
}

fn run<C: OpaqueCiphersuite>(inp: &FlowInput) {
    let mut rng = ChaCha8Rng::seed_from_u64(inp.seed);
    let password = cap(&inp.password, 64);
    let cred_id = cap(&inp.cred_id, 32);
    let context = cap(&inp.context, 32);
    let server_id = cap(&inp.server_id, 32);
    let client_id = cap(&inp.client_id, 32);

    let setup = ServerSetup::<C>::new(&mut rng).expect("server setup");

    if inp.fake {
        // Client login against a server that fakes an unknown credential.
        let (ke1, client_state) =
            ClientLogin::<C>::start(password, &mut rng).expect("client login start");
        let (ke1_bytes, mut dirty) = mangle(ke1.serialize(), Stage::Ke1, &inp.tamper);
        let ke1 = recv!(KE1, ke1_bytes, dirty);
        // A tampered KE1 can decode fine yet carry e.g. an identity blinded
        // element, which the server rightly rejects — only an honest KE1
        // must always be accepted.
        let ke2 = step!(
            ServerLogin::<C>::start_fake(
                &setup, &ke1, cred_id, context, server_id, client_id, &mut rng,
            ),
            dirty,
            "ServerLogin::start_fake"
        );
        let (ke2_bytes, changed) = mangle(ke2.serialize(), Stage::Ke2, &inp.tamper);
        dirty |= changed;
        let ke2 = recv!(KE2, ke2_bytes, dirty);
        assert!(
            client_state
                .finish(&ke2, context, server_id, client_id)
                .is_err(),
            "client completed a login against start_fake"
        );
        return;
    }

    // Registration.
    let mut dirty = false;
    let (request, reg_state) =
        ClientRegistration::<C>::start(password, &mut rng).expect("registration start");
    let (req_bytes, changed) = mangle(request.serialize(), Stage::RegRequest, &inp.tamper);
    dirty |= changed;
    let request = recv!(RegistrationRequest, req_bytes, dirty);

    let response = step!(
        ServerRegistration::<C>::start(&setup, &request, cred_id),
        dirty,
        "ServerRegistration::start"
    );
    let (resp_bytes, changed) = mangle(response.serialize(), Stage::RegResponse, &inp.tamper);
    dirty |= changed;
    let response = recv!(RegistrationResponse, resp_bytes, dirty);

    let (record, reg_export_key) = step!(
        reg_state.finish(&response, server_id, client_id, &mut rng),
        dirty,
        "ClientRegistration::finish"
    );
    let (record_bytes, changed) = mangle(record.serialize(), Stage::Record, &inp.tamper);
    dirty |= changed;
    let record = recv!(RegistrationRecord, record_bytes, dirty);

    // Login.
    let (ke1, client_state) =
        ClientLogin::<C>::start(password, &mut rng).expect("client login start");
    let (ke1_bytes, changed) = mangle(ke1.serialize(), Stage::Ke1, &inp.tamper);
    dirty |= changed;
    let ke1 = recv!(KE1, ke1_bytes, dirty);

    let (ke2, server_state) = step!(
        ServerLogin::<C>::start(
            &setup, &record, &ke1, cred_id, context, server_id, client_id, &mut rng,
        ),
        dirty,
        "ServerLogin::start"
    );
    let (ke2_bytes, changed) = mangle(ke2.serialize(), Stage::Ke2, &inp.tamper);
    dirty |= changed;
    let ke2 = recv!(KE2, ke2_bytes, dirty);

    let (ke3, client_session_key, login_export_key) = step!(
        client_state.finish(&ke2, context, server_id, client_id),
        dirty,
        "ClientLogin::finish"
    );
    let (ke3_bytes, changed) = mangle(ke3.serialize(), Stage::Ke3, &inp.tamper);
    dirty |= changed;
    let ke3 = recv!(KE3, ke3_bytes, dirty);

    let server_session_key = step!(server_state.finish(&ke3), dirty, "ServerLogin::finish");

    // Both sides completed: only legitimate for an untampered flow.
    assert!(
        !dirty,
        "flow completed although a wire message was tampered with"
    );
    assert_eq!(
        client_session_key.as_bytes(),
        server_session_key.as_bytes(),
        "session keys disagree on an honest flow"
    );
    assert_eq!(
        reg_export_key.as_slice(),
        login_export_key.as_slice(),
        "export keys differ between registration and login"
    );
}

fuzz_target!(|inp: FlowInput| {
    if inp.suite_p256 {
        run::<OpaqueP256>(&inp);
    } else {
        run::<OpaqueRistretto255>(&inp);
    }
});
