//! Fuzz all 8 OPAQUE wire-message deserializers over both ciphersuites.
//!
//! Input layout: `[selector][message bytes...]`. The selector's low 3 bits
//! pick the message type, bit 3 picks the ciphersuite.
//!
//! Invariants:
//! - `deserialize` returns `Ok` or `Err`, never panics or overflows.
//! - On `Ok`, re-serialization is byte-identical to the input (strict,
//!   canonical wire format — no malleability).

#![no_main]

use libfuzzer_sys::fuzz_target;
use pakery_crypto::{OpaqueP256, OpaqueRistretto255};
use pakery_opaque::{
    CredentialResponse, Envelope, OpaqueCiphersuite, RegistrationRecord, RegistrationRequest,
    RegistrationResponse, KE1, KE2, KE3,
};

fn dispatch<C: OpaqueCiphersuite>(kind: u8, data: &[u8]) {
    macro_rules! case {
        ($ty:ident) => {{
            if let Ok(msg) = $ty::deserialize::<C>(data) {
                assert_eq!(
                    msg.serialize(),
                    data,
                    concat!(
                        stringify!($ty),
                        " deserialize/serialize roundtrip not byte-identical"
                    )
                );
            }
        }};
    }

    match kind & 0x07 {
        0 => case!(RegistrationRequest),
        1 => case!(RegistrationResponse),
        2 => case!(RegistrationRecord),
        3 => case!(Envelope),
        4 => case!(CredentialResponse),
        5 => case!(KE1),
        6 => case!(KE2),
        _ => case!(KE3),
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&sel, data)) = input.split_first() else {
        return;
    };
    if sel & 0x08 == 0 {
        dispatch::<OpaqueRistretto255>(sel, data);
    } else {
        dispatch::<OpaqueP256>(sel, data);
    }
});
