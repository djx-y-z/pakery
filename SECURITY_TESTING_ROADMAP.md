# Security Testing Roadmap

Research-backed plan for hardening pakery's security testing. Compiled 2026-07-05 from
a survey of peer projects (rustls, opaque-ke, curve25519-dalek, RustCrypto, graviola,
orion, snow, aws-lc) and current tooling state. Each item below is scoped to be
executed **in its own session/PR**, in order. Check items off as they land.

## Baseline (already in place — do not redo)

- RFC/draft positive test vectors for all 4 protocols on both groups (145 integration
  tests in `pakery-tests`, incl. wrong-password / tampered-MAC / garbage-bytes /
  identity-point negative tests).
- CI: test, clippy `-D warnings`, fmt, doc, MSRV (1.79), no_std (thumbv7em), wasm,
  feature-combinations, minimal-versions, coverage; weekly `cargo audit`.
- Code-level: `#![forbid(unsafe_code)]` everywhere, `subtle::ct_eq` on all secret
  comparisons, `zeroize` discipline, exact-length guards on all 8 OPAQUE
  `deserialize` fns, identity-point rejection after every DH/scalar-mult.
- Attack-surface audit (2026-07-05) found **zero unguarded panics on
  attacker-controlled input** and clean RNG injection (every randomized op takes
  `&mut impl CryptoRng` — fully deterministic driving is possible everywhere).

## Decisions

**Adopted** (in priority order): property-based tests (proptest) → CPace negative
vectors → cargo-fuzz (deserializers + protocol state machines) → differential
testing of OPAQUE vs opaque-ke v4 → ctgrind-style constant-time CI job
(Valgrind + crabgrind, graviola pattern) → cargo-mutants (scheduled) →
small hygiene bundle (zeroize assert-tests, scoped Miri, dudect advisory job).

**Rejected, with reasons:**
- **OSS-Fuzz application** — acceptance requires "significant user base / critical
  infrastructure"; no RustCrypto crate, dalek, or opaque-ke is in it. Revisit after
  adoption grows. Keep the fuzz layout OSS-Fuzz-compatible so applying later is a
  small PR. **ClusterFuzzLite** — alive but bit-rotting (unfixed CI breakage
  issues); plain cargo-fuzz in Actions is more dependable.
- **quickcheck / arbtest** — dormant vs proptest; **bolero** — interesting unifier
  but proptest + cargo-fuzz is the ecosystem-standard path.
- **Differential testing for SPAKE2 / SPAKE2+ / CPace** — no compatible second
  implementation exists: RustCrypto `spake2` is pre-RFC (draft-10 conventions,
  Ed25519-only — cannot even instantiate RFC 9382's P-256 suite); no published Rust
  SPAKE2+ crate (Matter implementations pin an early draft-bar rev with a different
  key schedule); all other CPace crates are draft-haase-01 lineage (different
  protocol). Self-play property tests + spec vectors fill this gap.
- **Crash-oracle fuzzing of pure group/scalar arithmetic** — documented low-yield
  (bugs there are silent wrong-output, invisible to crash oracles); covered instead
  by RFC vectors, property tests, and the OPAQUE differential oracle.
- **haybale-pitchfork** (dead since 2021), **Microwalk / DATA** (research-grade,
  Rust not first-class), **BINSEC** (maintained but per-function harnesses only fit
  tiny leaf primitives, which live in dalek/RustCrypto, not here).
- **ASan/MSan** — near-zero value under `forbid(unsafe_code)`.
- **Full-workspace Miri** — dalek under Miri is impractically slow; scoped variant
  adopted in item 7.
- **Drop-time zeroization forensics** — reading freed memory is UB; untestable from
  safe Rust. Rely on `zeroize` guarantees + live-value assert-tests (item 7).

---

## Item 1 — Property-based test suite (proptest)

**Status:** [x] done (2026-07-05, branch `security/prop-tests`). Landed
`pakery-tests/tests/prop_{cpace,spake2,spake2plus,opaque}.rs` — 42 tests
(agreement / mismatch / tamper / truncation, plus OPAQUE roundtrip), 32 cases
per property, both suites each. proptest 1.11 landed **unpinned**: its manifest
is edition 2021, and `cargo +1.79 check --workspace` passes with it in the
lockfile (dev-dependencies are not built by the MSRV job). `rand_chacha 0.9`
added for seeded `CryptoRng` driving.

**Goal:** add a proptest layer in `pakery-tests` covering self-play invariants that
RFC vectors (single happy path) never exercise.

**Properties to implement, per protocol (CPace, SPAKE2, SPAKE2+, OPAQUE) × both
groups (ristretto255, P-256):**
1. *Agreement:* random passwords/identities/context → both sides complete and derive
   an identical shared key / session key + export key (OPAQUE).
2. *Mismatch:* differing passwords (and, where applicable, differing
   identities/context/sid/ad) → confirmation MAC verification fails on both sides;
   the derived keys are never equal.
3. *Tamper rejection:* flip any single byte (proptest picks index) in any protocol
   message → the receiving step returns `Err`, never silent success. For OPAQUE,
   tamper each field of KE1/KE2/KE3 and registration messages.
4. *Serialization roundtrip (OPAQUE):* for each of the 8 message types,
   `deserialize(m.serialize()) == m` and `deserialize` of any length ≠ expected
   returns `Err` (both truncated and extended).
5. *Truncation sweep:* every prefix of every valid message → `Err` (cheap,
   deterministic loop; can be a plain test rather than proptest).

**Implementation notes:**
- Drive all randomness through a seeded `CryptoRng` (e.g. `rand_chacha` from a
  proptest-generated seed) — the codebase already injects RNG everywhere; no
  `test-utils` needed for property tests.
- proptest 1.11 has MSRV 1.85; workspace MSRV is still 1.79. Since proptest is a
  dev-dependency of `pakery-tests` only, verify the `MSRV (1.79)` CI job
  (`cargo check --workspace`) still passes with it in the lockfile (edition-2024
  manifests break 1.79 parsing — same failure mode as the zeroize 1.9 hold, see
  TODO.md). If it breaks: pin the newest proptest whose manifest parses under 1.79,
  and note to un-pin when the planned MSRV 1.85 bump lands.
- Keep case counts modest in CI (e.g. 32–64 cases per property; the KSF/argon2
  feature makes OPAQUE flows slow — use the identity KSF for property tests).

**Acceptance:** new `pakery-tests/tests/prop_*.rs` files; all CI jobs green
(including MSRV); properties documented in the test-file headers.

---

## Item 2 — CPace negative test vectors + negative-vector sweep

**Status:** [x] done (2026-07-05, branch `security/negative-vectors`). The vector
repo had moved from draft-18 to draft-21 (published 2026-07-02): only the
example CI input changed (`o_cat`-ordered → plain `lv(A)||lv(B)`), not the
protocol — our implementation reproduces every draft-21 value, so
`cpace_vectors.rs` was bumped to -21 (source commit `8fb4056e` recorded in
test headers). Official negative vectors landed for both suites: B.3.10/B.3.11
(ristretto255) in `cpace_vectors.rs`, B.5.10/B.5.11 (P-256 point validation;
positive vectors N/A — our suite differs from the draft's SSWU suite) in
`cpace_p256_vectors.rs`, each asserting protocol MUST-abort on Y_i1/Y_i2 from
both roles. Home-grown sweep: `pakery-tests/vectors/negative_vectors.json`
(all 29 RFC 9496 A.2 invalid ristretto255 encodings, 6 constructed bad P-256
encodings, zero + non-canonical scalars) driven by
`pakery-tests/tests/negative_vectors.rs` across `from_bytes`, DH, OPRF
evaluate/finalize, and all SPAKE2/SPAKE2+/OPAQUE step functions, both groups.
Finding fixed along the way: OPRF `finalize` (both groups) accepted an
identity evaluation element — identity rejection added in `pakery-crypto`
plus unit tests.

**Goal:** consume the official CPace negative vectors — the only spec here that
ships any — and extend the same idea to the other protocols.

**Tasks:**
1. From https://github.com/cfrg/draft-irtf-cfrg-cpace (`testvectors.json`, also
   embedded per-section in `testvectors.md`): add the ristretto255 (and NIST-curve
   if applicable to our P-256 suite) **"invalid inputs for scalar_mult_vfy" and
   "low-order points"** vectors — each must be rejected by our implementation.
   Record which draft revision the vectors came from (currently -21); re-check on
   every draft bump.
2. Verify our pinned draft revision still matches what `cpace_vectors.rs` claims
   (draft-18 per current test file) — if the vector repo has moved on, decide
   whether to bump.
3. Home-grown negative vectors for OPAQUE/SPAKE2/SPAKE2+ (specs ship none, verified
   against RFC 9807/9382/9383 appendices): commit a small JSON of known-bad inputs —
   identity-point encodings, non-canonical encodings, off-curve P-256 points,
   order-n scalar edge cases — asserted rejected across all entry points
   (`from_bytes`, DH, OPRF evaluate/finalize, protocol step fns).

**Acceptance:** new vector files + tests; every negative vector rejected; source
and draft revision documented in test headers.

---

## Item 3 — cargo-fuzz harness + PR smoke job

**Status:** [ ] not started

**Goal:** coverage-guided fuzzing of everything that parses attacker-controlled
bytes, plus full protocol state machines fed adversarial peer messages
(rustls/snow pattern).

**Layout:** single `fuzz/` dir at repo root, **excluded from the root workspace**
(`cargo fuzz init --fuzzing-workspace=true`, i.e. its own workspace) so the MSRV /
no_std / minimal-versions / wasm CI jobs are unaffected. Depends on all protocol
crates + `pakery-crypto` (fuzz targets must instantiate concrete suites). Keep the
layout OSS-Fuzz-compatible (project dir maps 1:1 to a future `projects/pakery`).

**Targets:**
1. `opaque_deserialize` — one target dispatching first input byte over the 8 OPAQUE
   message types × both ciphersuites; invariant: `Ok` or `Err`, never panic/OOM;
   on `Ok`, re-serialize and assert byte-identical roundtrip.
2. `group_decode` — `from_bytes` / `from_uniform_bytes` / `scalar_from_wide_bytes`
   for Ristretto255Group and P256Group; plus `diffie_hellman(sk, pk)` on fuzz bytes
   (both args) and OPRF `server_evaluate` / `finalize` on fuzz bytes.
3. `cpace_flow` — complete initiator start with fixed seed, then feed fuzz bytes as
   `responder_share` to `finish`; same for responder receiving fuzz
   `initiator_share`.
4. `spake2_flow`, `spake2plus_flow` — same shape: honest local side (seeded RNG),
   fuzz bytes as the peer's share and confirmation MAC.
5. `opaque_flow` — structure-aware (`arbitrary` crate): an `Arbitrary` enum of
   client/server operations + fuzz-mutated message bytes driven through
   registration and login flows, including `start_fake`.

Build fuzz targets with `overflow-checks = true` and `debug-assertions = true` in
the fuzz profile.

**CI (extend `ci.yml` or a new `fuzz.yml`):** PR smoke job — nightly toolchain,
`cargo fuzz run <target> -- -max_total_time=60` per target (matrix); upload crash
artifacts on failure. Corpus: seed with valid RFC-vector messages; persist via
`actions/cache` with restore-key fallback so PR and scheduled jobs share it.

**Acceptance:** all targets build and run 60 s each without findings (or findings
fixed); smoke job wired into PR CI; `fuzz/README.md` documents how to run locally.

---

## Item 4 — Scheduled long fuzz runs

**Status:** [ ] not started (requires item 3)

**Goal:** weekly (or nightly) cron workflow running each target 600–1800 s with
`-fork=$(nproc)`, `--stop-after-first-failure`, corpus shared via the same
`actions/cache` keys, plus periodic `cargo fuzz cmin` corpus minimization. Open a
GitHub issue automatically (or fail loudly) on findings. Optionally add
`cargo fuzz coverage` reporting to spot dead corners.

**Acceptance:** scheduled workflow green for a full week; corpus growth visible in
cache; runbook note in `fuzz/README.md`.

---

## Item 5 — Differential testing: OPAQUE vs opaque-ke v4

**Status:** [ ] not started

**Goal:** cross-implementation oracle for the one protocol where a same-spec peer
exists: `opaque-ke` v4.0.1+ implements **RFC 9807 final** (v4.0.0 changelog:
"synced implementation with RFC 9807", vectors updated) and is actively maintained.

**Tasks:**
1. Add `opaque-ke = "4"` as an optional dev-dependency of `pakery-tests` behind a
   new `differential` feature (it pulls a large dep tree — keep it out of default
   test runs; check its MSRV ≥ our CI toolchain and gate the CI job accordingly).
2. Match ciphersuites: ristretto255-SHA512 suite and P-256 suite as available in
   opaque-ke's generic config. Confirm identity-KSF equivalence for comparison runs.
3. Drive both implementations with identical deterministic inputs (password,
   credential identifier, identities, OPRF seed, keypair seeds, nonces — via our
   `test-utils` constructors and opaque-ke's test-vector/seeded-RNG machinery) and
   assert equality of: registration record, KE1/KE2/KE3 bytes, export_key,
   session_key. Randomize inputs with proptest (small case count).
4. CI: run under the existing test job with `--features differential` (or a
   separate job if runtime is significant).

**Note:** interop at the byte level requires both sides to agree on every input
derivation; if opaque-ke derives (e.g.) keypairs from seeds differently, compare at
the highest layer where inputs can be forced equal, and document what is and isn't
byte-compared.

**Acceptance:** differential suite passing in CI; README of `pakery-tests` explains
the oracle and its limits.

---

## Item 6 — Constant-time CI job (ctgrind pattern: Valgrind + crabgrind)

**Status:** [ ] not started

**Goal:** deterministic CT verification in CI — the graviola pattern (its
`ctgrind.yml` runs daily + per-PR on ubuntu-latest). This checks secret-dependent
branches and memory indexing in the *compiled artifact*, including release mode
(catches LLVM undoing `subtle`'s intent). Peer context: subtle/dalek/RustCrypto run
nothing in CI for CT; graviola/aws-lc/NSS all chose this Valgrind approach.

**Tasks:**
1. Add `crabgrind` (v0.3+, actively maintained, safe API — compatible with
   `forbid(unsafe_code)`) behind a private `__ctgrind` cargo feature (compiles to
   no-ops without it). Helpers: `mark_secret(&[u8])` / `declassify(&[u8])` marking
   memory undefined/defined, graviola `ct.rs`-style.
2. Mark as secret: password bytes, scalars/private keys, DH outputs, OPRF outputs,
   PRKs/derived keys, envelope contents. Declassify: public key encodings before
   serialization, MAC tags before wire output, and boolean accept/reject results
   after `ct_eq` (the decision itself is public).
3. Test harness (in `pakery-tests`, feature-gated): run full protocol flows for all
   4 protocols × both groups under
   `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --track-origins=yes --error-exitcode=99"`,
   debug **and** release.
4. New workflow `ct.yml`: per-PR or daily on ubuntu-latest (deterministic — shared
   runners are fine, unlike dudect).

**Expectation management:** first run may flag issues inside dalek/p256/argon2 —
triage; suppress or declassify at our boundary if the leak is in a dependency and
known-accepted, and record each suppression.

**Acceptance:** `ct.yml` green in debug+release for all protocol flows; suppression
list (if any) documented with justification.

---

## Item 7 — Hygiene bundle: zeroize assert-tests, scoped Miri, dudect advisory

**Status:** [ ] not started

Three small independent tasks, one PR:
1. **Zeroize unit tests:** for every struct deriving `Zeroize`/`ZeroizeOnDrop` (and
   the manual `Drop` impls), a test that calls `.zeroize()` on a live value and
   asserts all secret fields are zero. Verifies our impls cover every field (catches
   a future field added without zeroization). Drop-time memory forensics is
   deliberately out of scope (UB from safe Rust).
2. **Scoped Miri job:** `cargo +nightly miri test -p pakery-core --lib` (pinned
   nightly, `-Zmiri-strict-provenance`) — the crypto-bigint pattern. Do **not**
   attempt protocol crates (dalek under Miri is impractical).
3. **dudect-bencher advisory job:** dudect-bencher 0.7 (maintained, MSRV 1.85 —
   needs nightly-adjacent toolchain choice or wait for MSRV bump) harness for the
   confirmation-MAC verify paths (fixed-vs-random peer MAC) and `SharedSecret`
   equality. **Weekly scheduled, non-blocking** (orion pattern — statistical, noisy
   on shared runners; |t| > 5 fails, t < 5 proves nothing). Not a PR gate.

**Acceptance:** all three jobs/tests green; dudect job explicitly marked
`continue-on-error: true` or in a separate non-required workflow.

---

## Item 8 — cargo-mutants (scheduled mutation testing)

**Status:** [ ] not started (best after items 1–2 so mutants have tests to kill)

**Goal:** find code our tests don't actually constrain. Expected value concentrates
exactly where positive RFC vectors never look: error paths, `is_identity()` checks,
`ct_eq` branches, length guards.

**Tasks:**
1. `cargo-mutants` v27+: configure `--test-package pakery-tests` (integration tests
   live in a separate crate — without this, mutants in protocol crates won't be
   caught) plus per-crate unit tests.
2. CI: weekly scheduled full run (sharded `--shard k/n` if slow), **and/or**
   `--in-diff` incremental mode on PRs (advisory). Not a required gate initially.
3. Triage the first full run: each surviving mutant is either a missing test
   (file an item-1-style property or a unit test) or provably-equivalent code
   (document it in `.cargo/mutants.toml` exclusions).

**Acceptance:** workflow landed; first-run report triaged with issues filed for
legitimate gaps.

---

## Related, tracked elsewhere

- `cargo deny` CI gate — already planned in TODO.md (v1.0 milestone).
- MSRV 1.85 bump + dep group (dalek 5 / argon2 0.6 / blake2 0.11) — TODO.md;
  unblocks unpinned proptest 1.11 and dudect-bencher 0.7 here.
- LLVM constant-time intrinsics (`__builtin_ct_select`, ToB RFC, landing LLVM 21+)
  and Rust secret-types RFC 2859 — watch; nothing usable from stable Rust yet.
- Re-verify this roadmap's tool versions before each item — compiled 2026-07-05.
