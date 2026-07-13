# Security testing

How pakery is tested for security, and why these layers were chosen. Every
layer below is wired into CI; local run instructions are given per layer.

This document describes what is **in place**. It grew out of an 8-item
hardening plan (compiled 2026-07-05 from a survey of rustls, opaque-ke,
curve25519-dalek, RustCrypto, graviola, orion, snow, and aws-lc); all of that
work has landed, and the file is kept for its architecture overview and its
record of *why* each choice was made — which the CI workflows and configs
point back to.

## Baseline (predates the layers below)

- RFC/draft positive test vectors for all 4 protocols on both groups (145
  integration tests in `pakery-tests`, incl. wrong-password / tampered-MAC /
  garbage-bytes / identity-point negative tests).
- CI: test, clippy `-D warnings`, fmt, doc, MSRV (1.79), no_std (thumbv7em),
  wasm, feature-combinations, minimal-versions, coverage; weekly `cargo audit`.
- Code-level: `#![forbid(unsafe_code)]` everywhere, `subtle::ct_eq` on all
  secret comparisons, `zeroize` discipline, exact-length guards on all 8 OPAQUE
  `deserialize` fns, identity-point rejection after every DH/scalar-mult.
- Attack-surface audit (2026-07-05): zero unguarded panics on
  attacker-controlled input; every randomized op takes `&mut impl CryptoRng`,
  so fully deterministic driving is possible everywhere.

---

## Layers in place

### Property-based tests (proptest)

Self-play invariants that single-happy-path RFC vectors never exercise:
agreement (both sides derive identical keys), mismatch (differing
passwords/identities/context → confirmation MAC fails, keys never equal),
single-byte tamper rejection, OPAQUE serialization roundtrip, and a truncation
sweep — per protocol (CPace, SPAKE2, SPAKE2+, OPAQUE) × both groups.

- **Where:** `pakery-tests/tests/prop_{cpace,spake2,spake2plus,opaque}.rs`.
- **Run:** `cargo test -p pakery-tests --all-features`.
- **Notes:** randomness is driven through a seeded `rand_chacha` `CryptoRng`
  (no `test-utils` needed); case counts kept modest (32–64) and the identity
  KSF is used so Argon2 does not dominate runtime. proptest 1.11 is left
  **unpinned**: its manifest is edition-2021, so `cargo +1.79 check
  --workspace` still passes with it in the lockfile (dev-deps are not built by
  the MSRV job).

### Negative test vectors

The official CPace negative vectors plus a home-grown sweep of known-bad
encodings across every entry point.

- **Where:** `pakery-tests/vectors/negative_vectors.json` +
  `tests/negative_vectors.rs`; CPace official vectors in
  `cpace_vectors.rs` / `cpace_p256_vectors.rs`.
- **Coverage:** all 29 RFC 9496 A.2 invalid ristretto255 encodings, 6
  constructed bad P-256 encodings, zero + non-canonical scalars — driven
  through `from_bytes`, DH, OPRF evaluate/finalize, and every
  SPAKE2/SPAKE2+/OPAQUE step, both groups.
- **Notes:** CPace vectors are pinned to draft-21 (record the revision in test
  headers; re-check on each draft bump). This sweep found and fixed a real gap:
  OPRF `finalize` (both groups) accepted an identity evaluation element —
  identity rejection was added in `pakery-crypto`.

### Fuzzing (cargo-fuzz) — PR smoke + scheduled long runs

Coverage-guided fuzzing of everything that parses attacker-controlled bytes,
plus full protocol state machines fed adversarial peer messages.

- **Where:** standalone `fuzz/` workspace (excluded from the root workspace,
  OSS-Fuzz-compatible layout). Six targets: `opaque_deserialize`,
  `group_decode`, `cpace_flow`, `spake2_flow`, `spake2plus_flow`,
  `opaque_flow` (structure-aware via `arbitrary`).
- **CI:** `.github/workflows/fuzz.yml` (PR smoke, 60 s/target) and
  `.github/workflows/fuzz-long.yml` (weekly + dispatch, fork mode, `cmin`
  corpus minimization, advisory coverage report; opens/updates a GitHub issue
  on findings).
- **Run:** see `fuzz/README.md`. On CI always pass
  `--target x86_64-unknown-linux-gnu` — the prebuilt cargo-fuzz binary is
  musl-static and would otherwise default `--target` to musl.
- **Notes:** built with `overflow-checks` + `debug-assertions`; runs use
  `-s none` (no sanitizer — see "rejected alternatives"). MAC-verifying targets
  are seeded with zero MACs so their forgery asserts stay sound.

### Differential testing — OPAQUE vs opaque-ke v4

Cross-implementation oracle for the one protocol with a same-spec peer:
`opaque-ke` 4.x implements RFC 9807 final.

- **Where:** `pakery-tests/tests/differential_opaque.rs`, behind the
  `differential` feature.
- **Run:** `cargo test -p pakery-tests --features differential` (also enabled
  by any `--all-features` job).
- **Coverage:** both suites, full registration + login on identical
  deterministic inputs, **byte-compared** — all six messages, registration
  record, export_key, session_key. Only the fake-credentials path is not
  differential-tested (both sides sample fresh randomness by design). Limits
  documented in `pakery-tests/README.md`.

### Constant-time verification (Valgrind + crabgrind)

The graviola/ctgrind pattern: run real protocol flows under Valgrind memcheck
with secret bytes marked undefined, so any secret-dependent branch or memory
index is flagged — in debug **and** release (catches LLVM undoing `subtle`).

- **Where:** `pakery_core::ct` helpers + `__ctgrind` feature (compiled to
  no-ops without it); harness `pakery-tests/tests/ct_flows.rs`; suppressions
  `pakery-tests/valgrind-ct.supp`; workflow `.github/workflows/ct.yml`.
- **Notes:** crabgrind panics at runtime if built without real Valgrind
  headers, so the helpers guard on `ct::is_active()`. `declassify_choice`
  routes the decision byte through `black_box` (without it, release LLVM
  branched on the pre-declassify register copy). The debug leg disables
  overflow-checks/debug-assertions (panic instrumentation floods memcheck on
  intentionally-tainted CT arithmetic in deps). Suppressions cover two
  P-256-only dependency-internal families (invariant-true `CtOption` asserts in
  p256 hash2curve; sec1 tag-byte dispatch); curve25519-dalek needs none.
  OPAQUE uses identity-KSF suites (Argon2id is data-dependent by design).

### Mutation testing (cargo-mutants)

Finds code the tests do not actually constrain — highest yield exactly where
positive RFC vectors never look: error paths, `is_identity()` checks, `ct_eq`
branches, length guards.

- **Where:** config in `.cargo/mutants.toml`; workflow
  `.github/workflows/mutants.yml` (weekly full run sharded 8×, a `summarize`
  job that aggregates survivors into a deduplicated GitHub issue, plus an
  advisory `--in-diff` job on PRs). Runbook in CONTRIBUTING.md.
- **Config notes:** `test_package` lists all 7 workspace members —
  `test_workspace = true` is unusable (it injects a colliding `--workspace` and
  leaves the baseline building only the mutated crates, where the feature names
  do not resolve); `additional_cargo_args = ["--workspace"]` fixes baseline
  feature resolution. Features `p256 + argon2 + differential`: argon2 must be
  **ON** or `ksf.rs` is cfg'd out and its mutants become false survivors;
  `__ctgrind` is **OFF**. `minimum_test_timeout = 120` catches mutants that
  break rejection-sampling loops (they hang → killed by timeout).
- **Exclusions** (each justified in the config): the `ct.rs` no-op helpers, the
  `o_cat` `>`→`>=` equivalent mutant, the `leb128_encode` `==`→`!=` mutant
  (a genuine behavioural change whose OOM failure mode is unrecordable without a
  per-process memory sandbox), and the two spake2plus `Drop` delegations
  (drop-time observation is UB from safe Rust).
- **Exit codes in CI:** cargo-mutants exit 3 (timeouts only) is treated as
  success (a timeout is a kill, not a survivor); survivors (exit 2) are gated
  independently by the `summarize` job reading each shard's `missed.txt`.

### Hygiene — zeroize asserts, scoped Miri, dudect advisory

- **Zeroize tests:** an in-crate unit test per `Zeroize`/`ZeroizeOnDrop` struct
  in every crate, asserting all secret fields are zero after `.zeroize()` on a
  live value (catches a future field added without zeroization). The two
  spake2plus manual `Drop` impls were refactored to `impl Zeroize` + `Drop`
  delegating to it, so they are testable on a live value.
- **Scoped Miri:** `miri` job in `ci.yml`, pinned nightly,
  `-Zmiri-strict-provenance`, `cargo miri test -p pakery-core --lib`, default
  features only (protocol crates use dalek, impractical under Miri).
- **dudect advisory:** standalone `dudect/` workspace (excluded from root),
  weekly non-blocking `.github/workflows/dudect.yml` — statistical timing on
  the confirmation-MAC verify paths and `SharedSecret` equality; fails only on
  `|t| > 5` (shared-runner noise makes `t < 5` prove nothing).

---

## Design decisions & rejected alternatives

**Adopted, in the order above:** property-based tests → CPace negative vectors
→ cargo-fuzz → differential OPAQUE vs opaque-ke v4 → constant-time CI job
(Valgrind + crabgrind) → cargo-mutants → hygiene bundle.

**Rejected, with reasons:**

- **OSS-Fuzz application** — acceptance requires "significant user base /
  critical infrastructure"; no RustCrypto crate, dalek, or opaque-ke is in it.
  Revisit after adoption grows; the `fuzz/` layout is kept OSS-Fuzz-compatible
  so applying later is a small PR. **ClusterFuzzLite** — alive but bit-rotting;
  plain cargo-fuzz in Actions is more dependable.
- **quickcheck / arbtest** — dormant vs proptest; **bolero** — interesting
  unifier, but proptest + cargo-fuzz is the ecosystem-standard path.
- **Differential testing for SPAKE2 / SPAKE2+ / CPace** — no compatible second
  implementation exists: RustCrypto `spake2` is pre-RFC (Ed25519-only, cannot
  instantiate RFC 9382's P-256 suite); no published Rust SPAKE2+ crate matches
  RFC 9383's key schedule; all other CPace crates are draft-haase-01 lineage
  (a different protocol). Self-play property tests + spec vectors fill this gap.
- **Crash-oracle fuzzing of pure group/scalar arithmetic** — documented
  low-yield (bugs there are silent wrong-output, invisible to crash oracles);
  covered instead by RFC vectors, property tests, and the OPAQUE differential
  oracle.
- **haybale-pitchfork** (dead since 2021), **Microwalk / DATA** (research-grade,
  Rust not first-class), **BINSEC** (per-function harnesses only fit tiny leaf
  primitives, which live in dalek/RustCrypto, not here).
- **ASan / MSan** — near-zero value under `forbid(unsafe_code)`. This is why
  fuzz runs use `-s none`.
- **Full-workspace Miri** — dalek under Miri is impractically slow; the scoped
  `pakery-core` variant is used instead.
- **Drop-time zeroization forensics** — reading freed memory is UB, untestable
  from safe Rust. Relies on `zeroize` guarantees + live-value assert-tests.

---

## Watch list (tracked elsewhere)

- `cargo deny` CI gate — planned in TODO.md (v1.0 milestone).
- MSRV 1.85 bump + dep group (dalek 5 / argon2 0.6 / blake2 0.11) — TODO.md;
  unblocks unpinned proptest 1.11 and dudect-bencher 0.7.
- LLVM constant-time intrinsics and Rust secret-types RFC 2859 — nothing usable
  from stable Rust yet.
- Re-verify tool versions periodically (this document's survey is from
  2026-07-05).
