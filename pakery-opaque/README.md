# pakery-opaque

[![crates.io](https://img.shields.io/crates/v/pakery-opaque.svg)](https://crates.io/crates/pakery-opaque)
[![docs.rs](https://docs.rs/pakery-opaque/badge.svg)](https://docs.rs/pakery-opaque)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

OPAQUE augmented PAKE protocol implementation ([RFC 9807](https://www.rfc-editor.org/rfc/rfc9807)).

Part of the [`pakery`](https://github.com/djx-y-z/pakery) workspace.

OPAQUE is an augmented (asymmetric) PAKE: the server stores a password verifier instead of the plaintext password. Even if the server is compromised, the attacker must perform an offline dictionary attack per user to recover passwords.

## Usage

```toml
[dependencies]
pakery-opaque = "0.3"
pakery-core = "0.3"
pakery-crypto = { version = "0.3", features = ["ristretto255"] }
# `OsRng` lives in rand_core, so it must be a direct dependency with its
# `os_rng` feature on. Enabling `os_rng` on any pakery crate turns the
# same rand_core feature on transitively; naming it here keeps the
# requirement explicit and independent of feature unification.
rand_core = { version = "0.9", features = ["os_rng"] }
```

## Example

The suite below uses `IdentityKsf`, which applies **no password hardening** —
it keeps the example short and matches the RFC 9807 test vectors. That choice
removes exactly the protection the paragraph above describes: with an identity
KSF, an attacker who steals the registration record can test password guesses
at the cost of one OPRF evaluation each. For production, use a real key
stretching function (`pakery_crypto::Argon2idKsf`, behind the `argon2`
feature) or the pre-built `pakery_crypto::OpaqueRistretto255Argon2` /
`OpaqueP256Argon2` suites.


```rust
use pakery_opaque::*;
use pakery_crypto::*;
use pakery_core::crypto::IdentityKsf;

struct MyOpaqueSuite;

impl OpaqueCiphersuite for MyOpaqueSuite {
    type Hash = Sha512Hash;
    type Kdf = HkdfSha512;
    type Mac = HmacSha512;
    type Dh = Ristretto255Dh;
    type Oprf = Ristretto255Oprf;
    type Ksf = IdentityKsf;

    const NN: usize = 32;
    const NSEED: usize = 32;
    const NOE: usize = 32;
    const NOK: usize = 32;
    const NM: usize = 64;
    const NH: usize = 64;
    const NPK: usize = 32;
    const NSK: usize = 32;
    const NX: usize = 64;
}

// In rand_core 0.9 `OsRng` only implements `TryRngCore`; `UnwrapErr`
// adapts it to the `CryptoRng` bound used by pakery's API (panics on
// RNG failure, which never happens on a real OS).
let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

// === Registration ===
let setup = ServerSetup::<MyOpaqueSuite>::new(&mut rng).unwrap();

let (reg_request, reg_state) =
    ClientRegistration::<MyOpaqueSuite>::start(b"password", &mut rng).unwrap();

let reg_response =
    ServerRegistration::<MyOpaqueSuite>::start(&setup, &reg_request, b"user@example.com")
        .unwrap();

let (record, _export_key) = reg_state.finish(&reg_response, b"", b"", &mut rng).unwrap();

// === Login ===
let (ke1, client_state) =
    ClientLogin::<MyOpaqueSuite>::start(b"password", &mut rng).unwrap();

let (ke2, server_state) = ServerLogin::<MyOpaqueSuite>::start(
    &setup, &record, &ke1, b"user@example.com",
    b"my-context", b"", b"", &mut rng,
).unwrap();

let (ke3, client_session_key, _export_key) = client_state
    .finish(&ke2, b"my-context", b"", b"").unwrap();

let server_session_key = server_state.finish(&ke3).unwrap();

assert_eq!(client_session_key, server_session_key);
```

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Enable `std` support |
| `os_rng` | Enable OS-backed RNG via `rand_core/os_rng` |
| `test-utils` | Expose deterministic constructors for testing |

## Security

- `#![forbid(unsafe_code)]`
- Constant-time comparisons via [`subtle`](https://crates.io/crates/subtle)
- Secret values zeroized on drop via [`zeroize`](https://crates.io/crates/zeroize)
- Validated against RFC 9807 test vectors

## MSRV

The minimum supported Rust version is **1.85**.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
