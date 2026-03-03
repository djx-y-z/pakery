# pakery-crypto

[![crates.io](https://img.shields.io/crates/v/pakery-crypto.svg)](https://crates.io/crates/pakery-crypto)
[![docs.rs](https://docs.rs/pakery-crypto/badge.svg)](https://docs.rs/pakery-crypto)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Concrete cryptographic implementations for the [`pakery`](https://github.com/djx-y-z/pakery) PAKE workspace.

This crate provides implementations of the traits defined in [`pakery-core`](https://crates.io/crates/pakery-core), backed by well-known cryptographic libraries. Select the primitives you need via feature flags.

## Usage

```toml
[dependencies]
pakery-crypto = { version = "0.1", features = ["ristretto255"] }
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
| `getrandom` | Enable OS-backed RNG via `rand_core/getrandom` |

## Security

- `#![forbid(unsafe_code)]`
- Constant-time comparisons via [`subtle`](https://crates.io/crates/subtle)
- Secret values zeroized on drop via [`zeroize`](https://crates.io/crates/zeroize)

## MSRV

The minimum supported Rust version is **1.79**.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
