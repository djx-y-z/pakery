# pakery-cpace

[![crates.io](https://img.shields.io/crates/v/pakery-cpace.svg)](https://crates.io/crates/pakery-cpace)
[![docs.rs](https://docs.rs/pakery-cpace/badge.svg)](https://docs.rs/pakery-cpace)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

CPace balanced PAKE protocol implementation ([draft-irtf-cfrg-cpace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/)).

Part of the [`pakery`](https://github.com/djx-y-z/pakery) workspace.

CPace is a balanced (symmetric) PAKE: both parties share the same password and derive a shared session key. It is simple, efficient, and provably secure in the UC model.

## Usage

```toml
[dependencies]
pakery-cpace = "0.1"
pakery-crypto = { version = "0.1", features = ["ristretto255"] }
```

## Example

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

// Requires the `os_rng` crate feature. In rand_core 0.9 `OsRng` only
// implements `TryRngCore`; `UnwrapErr` adapts it to the `CryptoRng`
// bound used by pakery's API (panics on RNG failure, which never
// happens on a real OS).
let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

// Initiator starts the exchange
let (ya, state) = CpaceInitiator::<MyCpaceSuite>::start(
    b"password", b"channel", b"session", b"ad_a", &mut rng,
).unwrap();

// Responder processes initiator's share and responds
let (yb, resp_out) = CpaceResponder::<MyCpaceSuite>::respond(
    &ya, b"password", b"channel", b"session",
    b"ad_a", b"ad_b", CpaceMode::InitiatorResponder, &mut rng,
).unwrap();

// Initiator finishes
let init_out = state.finish(&yb, b"ad_b", CpaceMode::InitiatorResponder).unwrap();

// Both sides derive the same intermediate session key
assert_eq!(init_out.isk.as_bytes(), resp_out.isk.as_bytes());
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
- Validated against draft-irtf-cfrg-cpace test vectors

## MSRV

The minimum supported Rust version is **1.79**.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
