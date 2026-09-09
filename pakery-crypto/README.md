# pakery-crypto

[![crates.io](https://img.shields.io/crates/v/pakery-crypto.svg)](https://crates.io/crates/pakery-crypto)
[![docs.rs](https://docs.rs/pakery-crypto/badge.svg)](https://docs.rs/pakery-crypto)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Concrete cryptographic implementations for the [`pakery`](https://github.com/djx-y-z/pakery) PAKE workspace.

This crate provides implementations of the traits defined in [`pakery-core`](https://crates.io/crates/pakery-core), backed by well-known cryptographic libraries. Select the primitives you need via feature flags.

## Usage

```toml
[dependencies]
pakery-cpace = "0.3"
pakery-crypto = { version = "0.3", features = ["ristretto255"] }
```

## Available types

### Ristretto255 (`ristretto255` feature)

| Type | Implements |
|------|-----------|
| `Ristretto255Group` | `CpaceGroup` |
| `Ristretto255Dh` | `DhGroup` |
| `Ristretto255Oprf` | `Oprf` |
| `Sha512Hash` | `Hash` |
| `HkdfSha512` | `Kdf` |
| `HmacSha512` | `Mac` |
| `SPAKE2_M_COMPRESSED` | SPAKE2 M constant |
| `SPAKE2_N_COMPRESSED` | SPAKE2 N constant |
| `SPAKE2_S_COMPRESSED` | SPAKE2 S constant (symmetric mode) |

### P-256 (`p256` feature)

| Type | Implements |
|------|-----------|
| `P256Group` | `CpaceGroup` |
| `P256Dh` | `DhGroup` |
| `P256Oprf` | `Oprf` |
| `Sha256Hash` | `Hash` |
| `HkdfSha256` | `Kdf` |
| `HmacSha256` | `Mac` |
| `SPAKE2_P256_M_COMPRESSED` | SPAKE2 M constant (P-256) |
| `SPAKE2_P256_N_COMPRESSED` | SPAKE2 N constant (P-256) |

### Argon2 (`argon2` feature)

| Type | Implements |
|------|-----------|
| `Argon2idKsf` | `Ksf` |

### Pre-built ciphersuites

Ready-made ciphersuite types, so you do not have to spell out the associated
types and length constants yourself. Each needs its protocol feature plus the
group feature.

| Type | Features | Suite |
|------|----------|-------|
| `CpaceRistretto255` | `cpace` + `ristretto255` | CPace, Ristretto255 + SHA-512 |
| `CpaceP256` | `cpace` + `p256` | CPace, P-256 + SHA-512 |
| `Spake2Ristretto255` | `spake2` + `ristretto255` | SPAKE2, Ristretto255 + SHA-512 |
| `Spake2P256` | `spake2` + `p256` | SPAKE2, P-256 + SHA-256 |
| `Spake2PlusRistretto255` | `spake2plus` + `ristretto255` | SPAKE2+, Ristretto255 + SHA-512 |
| `Spake2PlusP256` | `spake2plus` + `p256` | SPAKE2+, P-256 + SHA-256 |
| `OpaqueRistretto255` | `opaque` + `ristretto255` | OPAQUE, Ristretto255 + SHA-512, **identity KSF** |
| `OpaqueP256` | `opaque` + `p256` | OPAQUE, P-256 + SHA-256, **identity KSF** |
| `OpaqueRistretto255Argon2` | `opaque` + `ristretto255` + `argon2` | OPAQUE, Ristretto255 + SHA-512 + Argon2id |
| `OpaqueP256Argon2` | `opaque` + `p256` + `argon2` | OPAQUE, P-256 + SHA-256 + Argon2id |

The two identity-KSF OPAQUE suites apply **no password hardening** and exist
for testing and for matching RFC 9807 test vectors. Production deployments
want one of the Argon2id suites.

## Example: defining a ciphersuite

```rust
use pakery_cpace::CpaceCiphersuite;
use pakery_crypto::{Ristretto255Group, Sha512Hash};

struct MyCpaceSuite;

impl CpaceCiphersuite for MyCpaceSuite {
    type Group = Ristretto255Group;
    type Hash = Sha512Hash;
    const DSI: &'static [u8] = b"CPaceRistretto255";
    const HASH_BLOCK_SIZE: usize = 128;
    const FIELD_SIZE_BYTES: usize = 32;
}
```

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Enable `std` support |
| `ristretto255` (default) | Ristretto255 / SHA-512 primitives |
| `p256` | P-256 / SHA-256 primitives |
| `argon2` | Argon2id key-stretching function |
| `os_rng` | Enable OS-backed RNG via `rand_core/os_rng` |
| `cpace` | Pre-built CPace ciphersuites (pulls in `pakery-cpace`) |
| `spake2` | Pre-built SPAKE2 ciphersuites (pulls in `pakery-spake2`) |
| `spake2plus` | Pre-built SPAKE2+ ciphersuites (pulls in `pakery-spake2plus`) |
| `opaque` | Pre-built OPAQUE ciphersuites (pulls in `pakery-opaque`) |

## Security

- `#![forbid(unsafe_code)]`
- Constant-time comparisons via [`subtle`](https://crates.io/crates/subtle)
- Secret values zeroized on drop via [`zeroize`](https://crates.io/crates/zeroize)

## MSRV

The minimum supported Rust version is **1.85**.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
