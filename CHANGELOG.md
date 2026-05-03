## [0.2.0] - 2026-05-03

### Changed

- **Breaking (source-level):** `rand_core` bumped from `0.6` to `0.9`. Public RNG-bound APIs migrate from `impl CryptoRngCore` to `impl CryptoRng`. No behavioural change, but callers must update their `use` statements and trait bounds. Existing `rand_core::OsRng` usage now goes through `rand_core::UnwrapErr(OsRng)` because in `rand_core 0.9` `OsRng` only implements `TryRngCore` directly.
- **Breaking (feature):** the per-crate `getrandom` Cargo feature was renamed to `os_rng` (matches the upstream `rand_core` rename). All six published crates (`pakery-core`, `pakery-cpace`, `pakery-opaque`, `pakery-spake2`, `pakery-spake2plus`, `pakery-crypto`) are affected. Update `features = ["getrandom"]` to `features = ["os_rng"]` in your `Cargo.toml`.
- `getrandom` is bumped from `0.2` to `0.3` transitively via `rand_core 0.9`. Modern `getrandom_backend = "wasm_js"` rustflags are now honoured by the dependency tree. The legacy `getrandom = { version = "0.2", features = ["js"] }` target-specific shim is no longer required for downstream WASM users that do not enable the `os_rng` feature.
- `pakery-core`'s `std` feature now activates `rand_core/std` (previously it was a no-op). No behavioural change unless `os_rng` is also enabled, in which case `getrandom`'s `std` is enabled too.

### Added

- `pakery-spake2plus`: `ProverOutput::into_session_key`, `ProverOutput::into_confirm_p`, and `Spake2PlusOutput::into_session_key` — ergonomic field consumers that replace the `mem::replace` / `mem::take` boilerplate previously required to extract fields from these `ZeroizeOnDrop` outputs. The original `pub` fields stay intact; the methods are additive.
- `pakery-spake2`: `Spake2Output::into_session_key` and `Spake2Output::into_confirmation_mac` — same ergonomic-consumer pattern, mirroring SPAKE2+. The original `pub` fields and `verify_peer_confirmation` method are unchanged.
- `pakery-crypto`: `Argon2Params` trait, `DefaultArgon2Params` zero-sized parameter set, and `Argon2idKsfWithParams<P>` generic. `Argon2idKsf` is now a type alias for `Argon2idKsfWithParams<DefaultArgon2Params>`, letting new users plug in custom Argon2id cost / output-length settings without copying the impl. Trait positions (`type Ksf = Argon2idKsf;`) and stretch outputs are bit-exact backward-compatible with `0.1.x` (verified by a pinned-vector test). Note: `Argon2idKsf` is now a type alias rather than a unit struct, so value-position constructions like `let _ = Argon2idKsf;` or `Argon2idKsf {}` no longer compile — instantiate `Argon2idKsfWithParams::<DefaultArgon2Params>(core::marker::PhantomData)` if you somehow need a value, but trait usage (the only intended path) is unchanged.
- `.cargo/config.toml`: `cargo wasm-check` alias that verifies all user-facing crates compile cleanly against `wasm32-unknown-unknown` with default features off (the contract for WASM downstream users).

### Notes

- The CHANGELOG claim "WASM (`wasm32-unknown-unknown`) support" added in `0.1.0` is now accurate: user-facing crates build cleanly for WASM with default features off, no target-specific `getrandom` shim required. Downstream users who additionally need `os_rng` on WASM still have to enable `getrandom`'s `wasm_js` feature in their own `Cargo.toml` (this is a `getrandom 0.3+` ecosystem requirement).
- `digest 0.11` / `sha2 0.11` / `hmac 0.13` / `hkdf 0.13` are intentionally NOT bumped in this release. They form a coherent group blocked by transitive `digest 0.10` constraints in `curve25519-dalek 4.1` / `p256 0.13` / `elliptic-curve 0.13`. The bump is deferred until those crates ship stable majors (`curve25519-dalek 5.x`, `p256 0.14`, `elliptic-curve 0.14`).

## [0.1.0] - 2026-03-07

### Added

- `pakery-core`: shared cryptographic trait abstractions (`Hash`, `Kdf`, `Mac`, `CpaceGroup`, `DhGroup`, `Oprf`, `Ksf`)
- `pakery-cpace`: CPace balanced PAKE protocol (draft-irtf-cfrg-cpace)
- `pakery-opaque`: OPAQUE augmented PAKE protocol (RFC 9807)
- `pakery-spake2`: SPAKE2 balanced PAKE protocol (RFC 9382)
- `pakery-spake2plus`: SPAKE2+ augmented PAKE protocol (RFC 9383)
- `pakery-crypto`: concrete implementations for Ristretto255 and P-256 cipher suites
- Ristretto255 / SHA-512 cipher suite support
- P-256 / SHA-256 cipher suite support
- Argon2id key-stretching function support for OPAQUE
- Custom RFC 9497 OPRF implementation (Ristretto255 and P-256)
- `no_std` support across all crates (no heap allocation required)
- WASM (`wasm32-unknown-unknown`) support
- RFC test vector validation for all protocols
- Constant-time operations via `subtle`
- Secret zeroization via `zeroize`
