# pakery-core

[![crates.io](https://img.shields.io/crates/v/pakery-core.svg)](https://crates.io/crates/pakery-core)
[![docs.rs](https://docs.rs/pakery-core/badge.svg)](https://docs.rs/pakery-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Shared traits and types for the [`pakery`](https://github.com/djx-y-z/pakery) PAKE workspace.

This crate defines the cryptographic trait abstractions that all protocol crates depend on. Concrete implementations are provided by [`pakery-crypto`](https://crates.io/crates/pakery-crypto).

## Traits

| Trait | Description |
|-------|-------------|
| `Hash` | Cryptographic hash function |
| `Kdf` | Key derivation function |
| `Mac` | Message authentication code |
| `CpaceGroup` | Group operations for CPace |
| `DhGroup` | Diffie-Hellman group operations |
| `Oprf` | Oblivious pseudorandom function |
| `Ksf` | Key-stretching function |

## Usage

```toml
[dependencies]
pakery-core = "0.1"
```

```rust
use pakery_core::crypto::{Hash, Kdf, Mac, CpaceGroup, DhGroup, Oprf, Ksf};
use pakery_core::{PakeError, SharedSecret};
```

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Enable `std` support |
| `getrandom` | Enable OS-backed RNG via `rand_core/getrandom` |

## Security

- `#![forbid(unsafe_code)]`
- Constant-time comparisons via [`subtle`](https://crates.io/crates/subtle)
- Secret values zeroized on drop via [`zeroize`](https://crates.io/crates/zeroize)

## MSRV

The minimum supported Rust version is **1.85**.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
