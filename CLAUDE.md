# CLAUDE.md

## Project overview

**pakery** is a Rust workspace implementing Password-Authenticated Key Exchange (PAKE) protocols. Protocol crates are generic over cryptographic primitives via traits.

## Workspace structure

| Crate | Role |
|-------|------|
| `pakery-core` | Shared traits (`Hash`, `Kdf`, `Mac`, `CpaceGroup`, `DhGroup`, `Oprf`, `Ksf`), error types, encoding utils |
| `pakery-cpace` | CPace balanced PAKE (draft-irtf-cfrg-cpace) |
| `pakery-opaque` | OPAQUE augmented PAKE (RFC 9807) |
| `pakery-spake2` | SPAKE2 balanced PAKE (RFC 9382) |
| `pakery-spake2plus` | SPAKE2+ augmented PAKE (RFC 9383) |
| `pakery-crypto` | Concrete crypto implementations (Ristretto255, P-256) |
| `pakery-tests` | Integration tests with RFC test vectors |

## Key conventions

- Protocol crates depend only on `pakery-core` traits, never on concrete crypto crates
- All crates use `#![forbid(unsafe_code)]`
- All public API must maintain `no_std` compatibility
- Test against RFC test vectors where available
- Lockstep versioning: all crates share a single version from root `Cargo.toml`

## Build & test commands

```bash
cargo check --workspace --all-features
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --all-features --no-deps
```

## Commit style

```
feat(crate): description
fix(crate): description
```

## Language

All code, documentation, and commit messages must be in English.
