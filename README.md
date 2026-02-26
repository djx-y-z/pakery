# pakery

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![CI](https://github.com/djx-y-z/pakery/actions/workflows/ci.yml/badge.svg)](https://github.com/djx-y-z/pakery/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/djx-y-z/COVERAGE_GIST_ID/raw/coverage.json)](https://github.com/djx-y-z/pakery/actions/workflows/ci.yml)

Modular, `no_std`-compatible Password-Authenticated Key Exchange (PAKE) implementations in Rust.

All protocol crates are generic over cryptographic primitives via traits defined in `pakery-core`, with concrete implementations provided by `pakery-crypto`. This lets you swap cipher suites without changing protocol logic.

## Protocols

| Crate | Protocol | Type | Spec | crates.io |
|-------|----------|------|------|-----------|
| [`pakery-cpace`](pakery-cpace/) | CPace | Balanced | [draft-irtf-cfrg-cpace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/) | [![crates.io](https://img.shields.io/crates/v/pakery-cpace.svg)](https://crates.io/crates/pakery-cpace) |
| [`pakery-opaque`](pakery-opaque/) | OPAQUE | Augmented | [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807) | [![crates.io](https://img.shields.io/crates/v/pakery-opaque.svg)](https://crates.io/crates/pakery-opaque) |
| [`pakery-spake2`](pakery-spake2/) | SPAKE2 | Balanced | [RFC 9382](https://www.rfc-editor.org/rfc/rfc9382) | [![crates.io](https://img.shields.io/crates/v/pakery-spake2.svg)](https://crates.io/crates/pakery-spake2) |
| [`pakery-spake2plus`](pakery-spake2plus/) | SPAKE2+ | Augmented | [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383) | [![crates.io](https://img.shields.io/crates/v/pakery-spake2plus.svg)](https://crates.io/crates/pakery-spake2plus) |

## Supporting crates

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [`pakery-core`](pakery-core/) | Shared traits and types | [![crates.io](https://img.shields.io/crates/v/pakery-core.svg)](https://crates.io/crates/pakery-core) |
| [`pakery-crypto`](pakery-crypto/) | Concrete crypto implementations | [![crates.io](https://img.shields.io/crates/v/pakery-crypto.svg)](https://crates.io/crates/pakery-crypto) |

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                 Protocol Crates                      │
│  pakery-cpace  pakery-opaque  pakery-spake2  spake2+ │
└───────────────────────┬──────────────────────────────┘
                        │ depends on traits
┌───────────────────────▼──────────────────────────────┐
│                   pakery-core                        │
│  Hash · Kdf · Mac · CpaceGroup · DhGroup · Oprf     │
└───────────────────────▲──────────────────────────────┘
                        │ implements traits
┌───────────────────────┴──────────────────────────────┐
│                  pakery-crypto                       │
│  Ristretto255 · P-256 · SHA-2 · HKDF · HMAC         │
└──────────────────────────────────────────────────────┘
```

## Supported cipher suites

| Feature | Group | Hash | KDF | MAC | OPRF |
|---------|-------|------|-----|-----|------|
| `ristretto255` | Ristretto255 | SHA-512 | HKDF-SHA-512 | HMAC-SHA-512 | Ristretto255 VOPRF |
| `p256` | P-256 | SHA-256 / SHA-512 | HKDF-SHA-256 | HMAC-SHA-256 | P-256 VOPRF |

Optional: `argon2` feature enables Argon2id as a key-stretching function for OPAQUE.

## Quick example

CPace key exchange using Ristretto255:

```rust
use pakery_cpace::{CpaceCiphersuite, CpaceInitiator, CpaceResponder, CpaceMode};
use pakery_crypto::{Ristretto255Group, Sha512Hash};

struct MyCpaceSuite;

impl CpaceCiphersuite for MyCpaceSuite {
    type Group = Ristretto255Group;
    type Hash = Sha512Hash;
    const DSI: &'static [u8] = b"CPaceRistretto255";
    const HASH_BLOCK_SIZE: usize = 128;
    const FIELD_SIZE_BYTES: usize = 32;
}

let mut rng = rand_core::OsRng;

// Initiator starts the exchange
let (ya, state) = CpaceInitiator::<MyCpaceSuite>::start(
    b"password", b"channel", b"session", b"ad_a", &mut rng,
).unwrap();

// Responder processes and responds
let (yb, resp_out) = CpaceResponder::<MyCpaceSuite>::respond(
    &ya, b"password", b"channel", b"session",
    b"ad_a", b"ad_b", CpaceMode::InitiatorResponder, &mut rng,
).unwrap();

// Initiator finishes
let init_out = state.finish(&yb, b"ad_b", CpaceMode::InitiatorResponder).unwrap();

// Both sides derive the same session key
assert_eq!(init_out.isk.as_bytes(), resp_out.isk.as_bytes());
```

## Features

All protocol crates support:

| Feature | Description |
|---------|-------------|
| `std` (default) | Enable `std` support |
| `getrandom` | Enable OS-backed RNG via `rand_core/getrandom` |

## Security

- All crates use `#![forbid(unsafe_code)]`
- Constant-time comparisons via the [`subtle`](https://crates.io/crates/subtle) crate
- Secret values zeroized on drop via [`zeroize`](https://crates.io/crates/zeroize)
- Validated against RFC test vectors where available

**Disclaimer:** This library has not been independently audited. Use at your own risk in production systems.

## MSRV

The minimum supported Rust version is **1.79**.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
