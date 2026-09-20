# pakery-spake2

[![crates.io](https://img.shields.io/crates/v/pakery-spake2.svg)](https://crates.io/crates/pakery-spake2)
[![docs.rs](https://docs.rs/pakery-spake2/badge.svg)](https://docs.rs/pakery-spake2)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

SPAKE2 balanced PAKE protocol implementation ([RFC 9382](https://www.rfc-editor.org/rfc/rfc9382)).

Part of the [`pakery`](https://github.com/djx-y-z/pakery) workspace.

SPAKE2 is a balanced (symmetric) PAKE with mutual explicit key confirmation. Both parties share a password-derived scalar and agree on a session key with provable security.

## Usage

```toml
[dependencies]
pakery-spake2 = "0.5"
pakery-core = "0.5"
pakery-crypto = { version = "0.5", features = ["ristretto255"] }
# pakery's RNG bound is `rand_core::CryptoRng`, but rand_core 0.10 ships no
# generator of its own: when it dropped its Cargo features it dropped the
# OS-backed `OsRng` with them, and that generator now lives in getrandom as
# `SysRng`. The example therefore names both.
getrandom = { version = "0.4", features = ["sys_rng"] }
rand_core = "0.10"
```

## Example

```rust
use pakery_spake2::{Spake2Ciphersuite, PartyA, PartyB};
use pakery_crypto::{Ristretto255Group, Sha512Hash, HkdfSha512, HmacSha512};
use pakery_crypto::{SPAKE2_M_COMPRESSED, SPAKE2_N_COMPRESSED};
use pakery_core::crypto::{CpaceGroup, Hash};

struct MySpake2Suite;

impl Spake2Ciphersuite for MySpake2Suite {
    type Group = Ristretto255Group;
    type Hash = Sha512Hash;
    type Kdf = HkdfSha512;
    type Mac = HmacSha512;
    const NH: usize = 64;
    const M_BYTES: &'static [u8] = &SPAKE2_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &SPAKE2_N_COMPRESSED;
}

// `SysRng` is fallible (`TryCryptoRng`); `UnwrapErr` adapts it to the
// infallible `CryptoRng` bound used by pakery's API (panics on RNG
// failure, which never happens on a real OS).
let mut rng = rand_core::UnwrapErr(getrandom::SysRng);

// Derive password scalar
let hash = Sha512Hash::digest(b"password");
let w = Ristretto255Group::scalar_from_wide_bytes(&hash).unwrap();

// Both parties exchange shares and derive keys
let (pa, state_a) = PartyA::<MySpake2Suite>::start(
    &w, b"alice", b"bob", b"aad", &mut rng,
).unwrap();

let (pb, state_b) = PartyB::<MySpake2Suite>::start(
    &w, b"alice", b"bob", b"aad", &mut rng,
).unwrap();

let out_a = state_a.finish(&pb).unwrap();
let out_b = state_b.finish(&pa).unwrap();

// Session keys match
assert_eq!(out_a.session_key.as_bytes(), out_b.session_key.as_bytes());

// Verify mutual confirmation MACs
out_a.verify_peer_confirmation(&out_b.confirmation_mac).unwrap();
out_b.verify_peer_confirmation(&out_a.confirmation_mac).unwrap();
```

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Enable `std` support |
| `test-utils` | Expose deterministic constructors for testing |

## Security

- `#![forbid(unsafe_code)]`
- Constant-time comparisons via [`subtle`](https://crates.io/crates/subtle)
- Secret values zeroized on drop via [`zeroize`](https://crates.io/crates/zeroize)
- Validated against the RFC 9382 Appendix B test vectors, which cover the
  `P256-SHA256-HKDF-SHA256-HMAC-SHA256` ciphersuite

> **ristretto255 is not an RFC 9382 suite.** RFC 9382 defines M and N only for
> P-256, P-384, P-521, edwards25519 and edwards448, and for other curves its
> Section 2 says to derive them with RFC 9380 `hash_to_curve`. The ristretto255
> constants shipped in `pakery_crypto` predate that guidance and follow neither
> convention, so `Spake2Ristretto255` is **this crate's own suite**: no RFC test
> vectors apply to it and it has no conformant peer. Use the P-256 suite where
> cross-implementation interoperability matters.

## MSRV

The minimum supported Rust version is **1.85**.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
