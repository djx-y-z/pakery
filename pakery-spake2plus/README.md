# pakery-spake2plus

[![crates.io](https://img.shields.io/crates/v/pakery-spake2plus.svg)](https://crates.io/crates/pakery-spake2plus)
[![docs.rs](https://docs.rs/pakery-spake2plus/badge.svg)](https://docs.rs/pakery-spake2plus)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

SPAKE2+ augmented PAKE protocol implementation ([RFC 9383](https://www.rfc-editor.org/rfc/rfc9383)).

Part of the [`pakery`](https://github.com/djx-y-z/pakery) workspace.

SPAKE2+ is an augmented (asymmetric) PAKE: the server stores a verifier derived from the password rather than the password itself. It provides mutual explicit key confirmation with provable security.

## Usage

```toml
[dependencies]
pakery-spake2plus = "0.1"
pakery-crypto = { version = "0.1", features = ["ristretto255"] }
```

## Example

```rust
use pakery_spake2plus::{Spake2PlusCiphersuite, Prover, Verifier, compute_verifier};
use pakery_crypto::{Ristretto255Group, Sha512Hash, HkdfSha512, HmacSha512};
use pakery_crypto::{SPAKE2_M_COMPRESSED, SPAKE2_N_COMPRESSED};
use pakery_core::crypto::Hash;

struct MySpake2PlusSuite;

impl Spake2PlusCiphersuite for MySpake2PlusSuite {
    type Group = Ristretto255Group;
    type Hash = Sha512Hash;
    type Kdf = HkdfSha512;
    type Mac = HmacSha512;
    const NH: usize = 64;
    const M_BYTES: &'static [u8] = &SPAKE2_M_COMPRESSED;
    const N_BYTES: &'static [u8] = &SPAKE2_N_COMPRESSED;
}

// Requires the `os_rng` crate feature. In rand_core 0.9 `OsRng` only
// implements `TryRngCore`; `UnwrapErr` adapts it to the `CryptoRng`
// bound used by pakery's API (panics on RNG failure, which never
// happens on a real OS).
let mut rng = rand_core::UnwrapErr(rand_core::OsRng);

// Derive password scalars (w0, w1)
let h0 = Sha512Hash::digest(b"passwordw0");
let w0 = Ristretto255Group::scalar_from_wide_bytes(&h0).unwrap();
let h1 = Sha512Hash::digest(b"passwordw1");
let w1 = Ristretto255Group::scalar_from_wide_bytes(&h1).unwrap();

// Server stores the verifier L = w1 * G
let l_bytes = compute_verifier::<MySpake2PlusSuite>(&w1);

// Prover (client) starts
let (share_p, prover_state) = Prover::<MySpake2PlusSuite>::start(
    &w0, &w1, b"context", b"client", b"server", &mut rng,
).unwrap();

// Verifier (server) starts and produces confirmation
let (share_v, confirm_v, verifier_state) = Verifier::<MySpake2PlusSuite>::start(
    &share_p, &w0, &l_bytes, b"context", b"client", b"server", &mut rng,
).unwrap();

// Prover finishes and verifies server's confirmation
let prover_out = prover_state.finish(&share_v, &confirm_v).unwrap();

// Verifier finishes and verifies prover's confirmation
let verifier_out = verifier_state.finish(&prover_out.confirm_p).unwrap();

// Session keys match
assert_eq!(
    prover_out.session_key.as_bytes(),
    verifier_out.session_key.as_bytes(),
);
```

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Enable `std` support |
| `getrandom` | Enable OS-backed RNG via `rand_core/getrandom` |
| `test-utils` | Expose deterministic constructors for testing |

## Security

- `#![forbid(unsafe_code)]`
- Constant-time comparisons via [`subtle`](https://crates.io/crates/subtle)
- Secret values zeroized on drop via [`zeroize`](https://crates.io/crates/zeroize)
- Validated against RFC 9383 test vectors

## MSRV

The minimum supported Rust version is **1.79**.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
