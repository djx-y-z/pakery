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

## Security conventions

### Secret material ownership

- Core traits (`Kdf`, `DhGroup`, `Oprf`, `Ksf`) return `Zeroizing<Vec<u8>>` for secret material (keys, PRKs, OPRF outputs). This makes the API safe-by-default — callers get automatic zeroization without manual wrapping.
- Public keys and MAC tags are **not** wrapped in `Zeroizing` — they are not secret.
- `SharedSecret` has `#[derive(ZeroizeOnDrop)]` and redacted `Debug` output. Equality uses `ConstantTimeEq`.

### Zeroization rules

- All structs holding secret state must derive `Zeroize + ZeroizeOnDrop`, or implement `Drop` manually with `.zeroize()` calls.
- Use `Zeroizing::new(...)` for intermediate secret material on the stack (transcripts, hash outputs, DH results, scalar bytes).
- When moving a secret out of a struct that implements `Drop`, use `core::mem::take(&mut *zeroizing_val)` or `core::mem::replace(&mut field, placeholder)` — never `.clone()`.
- To extract the inner `Vec<u8>` from `Zeroizing<Vec<u8>>`, use `core::mem::take(&mut *val)` (there is no `into_inner()` method).
- Fields of type `SharedSecret` in outer structs should be annotated `#[zeroize(skip)]` since `SharedSecret` handles its own zeroization.

### Constant-time operations

- All secret comparisons must use `subtle::ConstantTimeEq::ct_eq` — never `==` on secret data.
- MAC verification, confirmation MAC checks, and `SharedSecret` equality all use `ct_eq`.
- Identity point checks in group implementations (`is_identity()`) must use `ct_eq` against the identity/neutral element.

### Input validation

- Reject identity/neutral group elements after every DH or scalar multiplication (`is_identity()` check). This is defense-in-depth.
- Reject zero scalars before cryptographic operations (OPRF blind, OPRF key derivation).
- Validate point encodings via `from_bytes()` before use; reject invalid encodings early.

### Test-only APIs

- Methods that accept deterministic scalars/seeds (for RFC test vector validation) must be gated behind `#[cfg(feature = "test-utils")]` and documented with a `# Security` warning.
- Never use `test-utils` methods in production code paths.
- Prefer injecting test values through an existing argument over adding such a method: the RFC 9497 VOPRF/POPRF vectors replay their blinds through the `rng` argument, and the one value no public path reproduces (the hedged proof nonce) is injected through a `#[cfg(test)]` helper that never compiles into the library.

### Hazmat APIs

- A production API that is safe only under a caller-side contract the types cannot enforce is gated behind the `hazmat` cargo feature, never `test-utils`. Today that is `deterministic_blind` on the RFC 9497 VOPRF/POPRF clients in `pakery-crypto`.
- Every `hazmat` item carries a `# Security` section stating the contract, and non-`hazmat` library code never calls it.
- A `hazmat` item still rejects degenerate input with an error rather than trusting the caller — `deterministic_blind` refuses bytes that reduce to zero.
- No crate in this repository switches `hazmat` on unconditionally, on a dependency line or in a `default` list: feature unification would switch it on for every build of the dependent, and nothing would test the code without it. A crate that needs it forwards it behind a feature of its own, as `pakery-tests` does. The one exception is the standalone, unpublished `fuzz/` workspace, which nothing depends on. Downstream code opts in on its own dependency line, which is where the opt-in is meant to show.
- `hazmat` adds no dependency. It is listed in `.cargo/mutants.toml` and in CI's feature combinations; dropping it from either leaves its code unmutated or unbuilt.

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
