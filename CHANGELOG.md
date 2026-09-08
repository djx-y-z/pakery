## [0.3.0] - 2026-09-08

### Changed

- **Breaking (MSRV): the minimum supported Rust version is now `1.85`** (was `1.79`). Every crate in the coupled RustCrypto group below declares `rust-version = 1.85` and most ship edition-2024 manifests, so the bump is a precondition rather than a choice. Raising the MSRV is semver-relevant for downstream users; it is deliberately paid once, here, for the whole group.
- **Breaking (public dependencies): `p256` and `curve25519-dalek` are public dependencies of `pakery-crypto`.** `CpaceGroup::Scalar` is bound to `p256::Scalar` / `curve25519_dalek::Scalar`, and those types reach default-feature public signatures (e.g. `pakery_spake2::PartyA::start`, `pakery_cpace::CpaceInitiator`). Independently of the MSRV, a downstream crate that names `p256::Scalar` or `curve25519_dalek::Scalar` must move to `p256` 0.14 / `curve25519-dalek` 5.0 in lockstep, or it will get two incompatible copies of the same type in its tree.
- **Coherent dependency group bump.** These were held back together — see the `0.2.0` note about `digest 0.11` — until every member had a stable release. All are now landed in one release:
  - `curve25519-dalek` `4.1` → `5.0`
  - `p256` `0.13` → `0.14` (hash-to-curve moved to the standalone `hash2curve` `0.14` crate, re-exported as `p256::hash2curve`)
  - `digest` `0.10` → `0.11`, `sha2` `0.10` → `0.11`, `hmac` `0.12` → `0.13`, `hkdf` `0.12` → `0.13`
  - `argon2` `0.5` → `0.6` (pulls `blake2` `0.11` and `password-hash` `0.6` transitively)
  - `zeroize` `1.8` → `1.9`, `zeroize_derive` `1.3` → `1.5`
- **No protocol output changes.** All RFC test vectors pass bit-exactly across the bump: RFC 9497 P-256 OPRF (`test_vector_1`/`test_vector_2`, `derive_key_pair`), RFC 9380 `expand_message_xmd`, and the CPace / SPAKE2 / SPAKE2+ / OPAQUE vector suites. The Argon2id KSF output is unchanged too — `Argon2idKsf::stretch` still matches its pinned byte vector (captured from the `v0.2.0` alias, with `v0.1.0` equivalence inferred from per-parameter assertions; see `TODO.md`). `argon2` `0.6` also leaves `Params::new`'s accept/reject bounds untouched, so no existing downstream cost configuration stops being accepted. The OPAQUE differential suite against `opaque-ke` v4 (which stays on the previous RustCrypto wave) continues to agree byte-for-byte on both suites.
- `pakery-crypto`'s hand-rolled scalar sampling is unchanged and remains deliberate: `p256`'s and `curve25519-dalek`'s own `Scalar::random` now take a `rand_core 0.10` RNG, while this workspace's public bound stays `rand_core 0.9`. The 32-byte (P-256) / 64-byte-wide (ristretto255) consumption pattern is a fixed contract the RFC vector tests depend on.

### Removed

- `curve25519-dalek`'s `group` feature is no longer enabled. It had been on since the first commit but was never used — this crate reaches ristretto255 through dalek's own inherent API. Dropping it keeps `group` `0.14`, `ff` `0.14` and a second `rand_core` out of the *default* (`ristretto255`) dependency tree. It does **not** remove them from a `p256` build: `elliptic-curve` `0.14` pulls `group` `0.14` / `ff` `0.14`, and `rand_core` `0.10` arrives independently via `crypto-bigint` `0.7` and `crypto-common` `0.2`. Downstream code that relied on feature unification to get the `group`/`ff` trait impls for `RistrettoPoint` must now enable that feature itself.
- Dead `[workspace.dependencies]` entries `group`, `ff` and `generic-array`, which no member crate inherited.

### Notes

- `rand_core` stays at `0.9`. `rand_core 0.10` ships **no** Cargo features at all, so the `os_rng` (and `std`) features that all six published crates forward to it would have to be removed from their public API — a separate breaking decision, tracked in `TODO.md`.
- The `MSRV` CI job now runs `cargo check --workspace --all-features` rather than a bare `cargo check --workspace`. The bare form never compiled non-default optional features, so a user-reachable feature (`pakery-crypto/argon2`) could silently require a newer toolchain than the declared `rust-version`.
- `pakery-crypto` now selects `p256`'s `group-digest` feature instead of `hash2curve`. This is **not** a rename — `p256` `0.14` has both, with `group-digest = ["hash2curve", "sha2"]` — and the wider one is required because `impl GroupDigest for NistP256` is gated on it (the impl needs `sha2` for its `type ExpandMsg = ExpandMsgXmd<Sha256>`). No downstream effect: `pakery-crypto` pins `p256`'s features itself and forwards none of them. Relatedly, `p256/voprf` disappeared from `pakery-tests`' `differential` feature because `p256` `0.14` no longer has a `voprf` feature; `opaque-ke`'s requirement is now satisfied by the `p256-013` alias.
- Internal note for anyone diffing intermediates: `hash_to_curve` output is unchanged, but `p256`'s `OsswuMap::osswu()` is **not** interchangeable across `0.13`/`0.14`. The `c2` constant changed from `sqrt(-Z^3)` to the RFC 9380 F.2.1.2-literal `sqrt(-Z)`, compensated by `map_to_curve` no longer re-deriving `y` through `decompress`. The composed result is identical (verified against the RFC 9380 J.1.1 vectors); the raw `osswu()` `y` differs for roughly half of inputs.
- `pakery-tests` now pulls `p256 0.13` and `sha2 0.10` under renamed aliases, solely so the `opaque-ke` v4 differential suite keeps compiling: `opaque-ke` names concrete types in its `CipherSuite` associated types and is still on the previous wave. That crate is `publish = false`, so this does not affect published dependency trees.

## [0.2.1] - 2026-07-13

### Security

- **`pakery-crypto` (P-256): reject malleable SEC1 point encodings.** P-256 point deserialization previously accepted the SEC1 *compact* tag (`0x05`): `sec1`/`primeorder` would decompact a 33-byte `0x05 || x` string to the same group element as its compressed (`0x02`/`0x03`) form, so two distinct byte strings mapped to one point — a non-canonical, malleable encoding. `oprf_p256` point parsing is now compressed-SEC1-only (tags `0x02`/`0x03`), rejecting identity, uncompressed, and compact encodings. `P256Group::from_bytes` (CPace / SPAKE2) still accepts compressed and uncompressed forms but now rejects the identity (`0x00`) and compact (`0x05`) tags. Ristretto255 was never affected (its encoding is already canonical). No effect on honest clients, which emit compressed keys.
- **`pakery-crypto` (OPRF, both suites): reject an identity evaluation element in `finalize`.** The OPRF client `finalize` now returns an error instead of proceeding when the server-supplied evaluated element is the group identity — closing a defense-in-depth gap in both the Ristretto255 and P-256 OPRF used by OPAQUE.

### Added

- `pakery-spake2plus`: `KeySchedule` and `VerifierState` now implement `zeroize::Zeroize` publicly. Behaviour is unchanged — their `Drop` impls delegate to `zeroize()` as before — but the trait is now callable directly on a live value.

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
