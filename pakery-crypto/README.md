# pakery-crypto

[![crates.io](https://img.shields.io/crates/v/pakery-crypto.svg)](https://crates.io/crates/pakery-crypto)
[![docs.rs](https://docs.rs/pakery-crypto/badge.svg)](https://docs.rs/pakery-crypto)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Concrete cryptographic implementations for the [`pakery`](https://github.com/djx-y-z/pakery) PAKE workspace.

This crate provides implementations of the traits defined in [`pakery-core`](https://crates.io/crates/pakery-core), backed by well-known cryptographic libraries. Select the primitives you need via feature flags.

It also implements the verifiable modes of RFC 9497 — VOPRF and POPRF — as standalone types; see [RFC 9497 VOPRF and POPRF](#rfc-9497-voprf-and-poprf) below.

## Usage

```toml
[dependencies]
pakery-cpace = "0.6"
pakery-crypto = { version = "0.6", features = ["ristretto255"] }
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

| Type | Implements | Cost |
|------|-----------|------|
| `Argon2idKsf` | `Ksf` | RFC 9106 §4 SECOND RECOMMENDED — `m = 64 MiB`, `t = 3`, `p = 4` |

It uses the RFC 9807 §7 salt `zeroes(16)`, and it serves every OPAQUE suite:
RFC 9807 §7 writes `T = Nh` in both of its recommended Argon2id
configurations, tying the stretch length to the ciphersuite, so
`Ksf::stretch` takes it as an argument and `pakery-opaque` passes `Nh`. There
is nothing to pair up and nothing to get wrong. (Before `0.6.0` the length was
a constant on the parameter set, which needed a second alias
`Argon2idKsfNh32` for SHA-256 suites — and before `0.5.0`, `OpaqueP256Argon2`
was wired to the wrong one.) For other cost settings, implement
`Argon2Params` and use `Argon2idKsfWithParams`.

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
want one of the Argon2id suites, which stretch to their own `Nh` without
being paired with anything.

> **Upgrading from `0.4.x` or earlier:** both Argon2id suites changed their
> envelope-producing parameters in `0.5.0` (salt on both, output length on
> P-256). Existing OPAQUE registration records are unreadable; users must
> re-register. See the `0.5.0` entry in `CHANGELOG.md`.

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

## RFC 9497 VOPRF and POPRF

The base OPRF mode above (`Ristretto255Oprf`, `P256Oprf`) is what OPAQUE uses.
The `verifiable_oprf` module adds RFC 9497's two verifiable modes, for both
suites, as standalone types that exchange bytes only:

| Suite (feature) | VOPRF (`0x01`) | POPRF (`0x02`) | Element | Output |
|-----------------|----------------|----------------|---------|--------|
| ristretto255-SHA512 (`ristretto255`) | `Ristretto255Voprf{Server,Client,ClientState}` | `Ristretto255Poprf{Server,Client,ClientState}` | 32 bytes | 64 bytes |
| P256-SHA256 (`p256`) | `P256Voprf{Server,Client,ClientState}` | `P256Poprf{Server,Client,ClientState}` | 33 bytes | 32 bytes |

- **VOPRF:** the server proves, with a DLEQ proof, that it evaluated with the
  key behind its public key.
- **POPRF:** additionally binds a public input `info`, known to both parties,
  into the output.
- Proofs are 64 bytes (`c || s`); errors are `VoprfError`, named after RFC
  9497's. Batches of up to 65535 elements share one proof.
- Every RFC 9497 Appendix A vector for both suites and both modes is a test;
  the implementation is also differential-tested against
  [`voprf`](https://crates.io/crates/voprf).

```toml
[dependencies]
pakery-crypto = "0.6.1"
# The example draws randomness from the OS; pakery-crypto itself only takes a
# `rand_core::CryptoRng` and depends on no RNG.
getrandom = { version = "0.4", features = ["sys_rng"] }
rand_core = "0.10"
```

```rust
use pakery_crypto::{Ristretto255PoprfClient, Ristretto255PoprfServer, VoprfError};

fn main() -> Result<(), VoprfError> {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);

    // Server: a key pair (or `derive` from a seed, or `from_secret_key`).
    let server = Ristretto255PoprfServer::generate(&mut rng);
    let public_key = server.public_key();

    // Client: blind the private input under the public `info`.
    let client = Ristretto255PoprfClient::new(&public_key)?;
    let info = b"example-app/v1 epoch=42";
    let (state, blinded) = client.blind(b"private input", info, &mut rng)?;

    // Server: evaluate, with a proof.
    let (evaluated, proof) = server.blind_evaluate(&blinded, info, &mut rng)?;

    // Client: verify the proof and unblind.
    let output = client.finalize(&state, b"private input", info, &evaluated, &proof)?;
    assert_eq!(*output, *server.evaluate(b"private input", info)?);
    Ok(())
}
```

Read the [`verifiable_oprf` module documentation](https://docs.rs/pakery-crypto/latest/pakery_crypto/verifiable_oprf/)
before deploying: it covers using one key per mode and application, key
consistency, what RFC 9497's security analysis does and does not cover, the
static Diffie-Hellman bound on how many evaluations a key should serve, and
the proof-nonce hedging this crate adds.

The `hazmat` feature adds `deterministic_blind`, which takes the blind as 64
caller-supplied bytes instead of drawing it at random. That trades RFC 9497's
unconditional input secrecy for a computational one and makes repeated
requests linkable; its contract is in the module documentation, and it is a
feature so that using it shows in the dependent's manifest.

## Features

| Feature | Description |
|---------|-------------|
| `std` (default) | Enable `std` support |
| `ristretto255` (default) | Ristretto255 / SHA-512 primitives |
| `p256` | P-256 / SHA-256 primitives |
| `argon2` | Argon2id key-stretching function |
| `cpace` | Pre-built CPace ciphersuites (pulls in `pakery-cpace`) |
| `spake2` | Pre-built SPAKE2 ciphersuites (pulls in `pakery-spake2`) |
| `spake2plus` | Pre-built SPAKE2+ ciphersuites (pulls in `pakery-spake2plus`) |
| `opaque` | Pre-built OPAQUE ciphersuites (pulls in `pakery-opaque`) |
| `hazmat` | `deterministic_blind` on the RFC 9497 VOPRF / POPRF clients (caller-supplied blind; read its contract first) |

## Security

- `#![forbid(unsafe_code)]`
- Constant-time comparisons via [`subtle`](https://crates.io/crates/subtle)
- Secret values zeroized on drop via [`zeroize`](https://crates.io/crates/zeroize)
- P-256 points that are secret are serialized by a constant-time encoder, not
  the SEC1 crate's compression, which branches on the point

## MSRV

The minimum supported Rust version is **1.88**.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
