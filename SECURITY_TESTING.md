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

- RFC/draft positive test vectors for **5 of the 8** protocol x group
  combinations (over 200 integration tests in `pakery-tests`, incl.
  wrong-password / tampered-MAC / garbage-bytes / identity-point negative
  tests; count them with `cargo test -p pakery-tests --all-features`).
  The other three have no vectors to run, because no standard defines the
  suite -- each is covered by round-trip and property tests instead, and each
  says so in its own test-file header:

  | | ristretto255 | P-256 |
  |---|---|---|
  | CPace | draft-21 App. B.3 | none -- suite deviates from the draft |
  | SPAKE2 | none -- not an RFC 9382 suite | RFC 9382 App. B |
  | SPAKE2+ | none -- not an RFC 9383 suite | RFC 9383 App. C.1 |
  | OPAQUE | RFC 9807 App. C.1.1/C.1.2 | RFC 9807 App. C.1.5/C.1.6 |

  The RFC 9497 VOPRF and POPRF, added in `0.6.1`, have vectors for both
  suites and both modes (App. A.1.2/A.1.3, A.3.2/A.3.3, batch vectors
  included). They run as unit tests in pakery-crypto, through the public
  types, except the "Proof" bytes: the proof nonce is hedged, so those are
  checked through a test-only entry that takes the vectors' nonce.
- CI: test, clippy `-D warnings`, fmt, doc, MSRV (1.88), no_std (thumbv7em),
  wasm, feature-combinations, minimal-versions, coverage, and the
  documentation gate (`ci/check-docs.py`); `cargo audit` (over all three
  lockfiles: the workspace's, `fuzz/`'s and `dudect/`'s) and cargo-deny on
  every push and PR plus a weekly cron. cargo-deny runs twice, over two
  different graphs: advisories, licences and sources over every crate cargo
  resolves, and duplicate versions over the published graph alone
  (`--exclude-unpublished`), because that gate is about what a consumer gets
  rather than what the test crate pins. A plain `cargo deny check` therefore
  fails by design — `deny.toml` carries both commands and the reasoning.
- Code-level: `#![forbid(unsafe_code)]` everywhere, `subtle::ct_eq` on all
  secret comparisons, `zeroize` discipline, exact-length guards on all 8 OPAQUE
  `deserialize` fns, identity-point rejection after every DH/scalar-mult.
- Attack-surface audit (2026-07-05): zero unguarded panics on
  attacker-controlled input; every randomized op takes `&mut impl CryptoRng`,
  so fully deterministic driving is possible everywhere. The RFC 9497 modes
  added in `0.6.1` keep both properties: peer bytes reach them only through
  decoders that return a `VoprfError`, which the `verifiable_oprf` fuzz
  target checks, and every randomized operation takes the caller's RNG.

---

## Layers in place

### Property-based tests (proptest)

Self-play invariants that single-happy-path RFC vectors never exercise:
agreement (both sides derive identical keys), mismatch (differing
passwords/identities/context → confirmation MAC fails, keys never equal),
single-byte tamper rejection, OPAQUE serialization roundtrip, and a truncation
sweep — per protocol (CPace, SPAKE2, SPAKE2+, OPAQUE) × both groups. For the
RFC 9497 VOPRF / POPRF: agreement with the server's `Evaluate`, single and
batched; tamper rejection; that `finalize` is bound to the blinded input; the
role of the POPRF `info` (finalizing succeeds exactly when it matches the
server's); and, with `hazmat`, that the deterministic blind agrees with the
random one fed the same bytes.

- **Where:** `pakery-tests/tests/prop_{cpace,spake2,spake2plus,opaque,voprf}.rs`.
- **Run:** `cargo test -p pakery-tests --all-features`.
- **Notes:** randomness is driven through a seeded `rand_chacha` `CryptoRng`
  (no `test-utils` needed); case counts kept modest (32–64) and the identity
  KSF is used so Argon2 does not dominate runtime — the KSF itself is covered
  by the differential Argon2id cases instead (see "Differential testing"). proptest is left
  **unpinned**: its 1.12 releases require Rust 1.88, the workspace MSRV, so
  they are within range, and the MSRV job does not build dev-dependencies
  anyway.

### Negative test vectors

The official CPace negative vectors plus a home-grown sweep of known-bad
encodings across every entry point.

- **Where:** `pakery-tests/vectors/negative_vectors.json` +
  `tests/negative_vectors.rs`; CPace official vectors in
  `cpace_vectors.rs` / `cpace_p256_vectors.rs`.
- **Coverage:** all 29 RFC 9496 A.2 invalid ristretto255 encodings, 6
  constructed bad P-256 encodings, zero + non-canonical scalars — driven
  through `from_bytes`, DH, OPRF evaluate/finalize, every
  SPAKE2/SPAKE2+/OPAQUE step, and every VOPRF / POPRF entry point that takes
  peer bytes (the public key, blinded and evaluated elements single and
  batched, the secret key, the proof's scalars), both groups.
- **Notes:** CPace vectors are pinned to draft-21 (record the revision in test
  headers; re-check on each draft bump). This sweep found and fixed a real gap:
  OPRF `finalize` (both groups) accepted an identity evaluation element —
  identity rejection was added in `pakery-crypto`.

### Fuzzing (cargo-fuzz) — PR smoke + scheduled long runs

Coverage-guided fuzzing of everything that parses attacker-controlled bytes,
plus full protocol state machines fed adversarial peer messages.

- **Where:** standalone `fuzz/` workspace (excluded from the root workspace,
  OSS-Fuzz-compatible layout). Seven targets: `opaque_deserialize`,
  `group_decode`, `cpace_flow`, `spake2_flow`, `spake2plus_flow`, and the
  structure-aware (`arbitrary`) `opaque_flow` and `verifiable_oprf`. A new
  target is listed in four places — the `fuzz.yml` matrix, the
  `fuzz-long.yml` matrix, its corpus-restore steps and its coverage loop —
  and its seed directory must be committed: both workflows pass it.
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
  `verifiable_oprf` never compares proof bytes — the proof nonce is hedged —
  only whether a proof verifies.

### Differential testing — OPAQUE vs opaque-ke v4

Cross-implementation oracle for OPAQUE, which has a same-spec peer:
`opaque-ke` 4.x implements RFC 9807 final. (The RFC 9497 VOPRF / POPRF have
one too; see the next section.)

- **Where:** `pakery-tests/tests/differential_opaque.rs`, behind the
  `differential` feature.
- **Run:** `cargo test -p pakery-tests --features differential` (also enabled
  by any `--all-features` job).
- **Coverage:** both suites, full registration + login on identical
  deterministic inputs, **byte-compared** — all six messages, registration
  record, export_key, session_key. Only the fake-credentials path is not
  differential-tested (both sides sample fresh randomness by design). Limits
  documented in `pakery-tests/README.md`.
- **KSF coverage, and why it is called out.** Through `0.4.0` every case ran
  the identity KSF on both sides, and the `0.3.0` / `0.4.0` changelogs cited
  this suite as the evidence for cross-implementation agreement. Substituting
  the identity KSF removes the component under test, so the suite could not
  observe the Argon2id salt defect fixed in `0.5.0` — correct logic over an
  input set that excluded the bug. Four `*_argon2_*` cases now drive the real
  Argon2id KSF on both sides (ours via `Argon2idKsfWithParams`, opaque-ke's
  via its `impl Ksf for argon2::Argon2`), plus a direct stretch comparison.
  They pin two properties no same-implementation round-trip can see: the salt
  is `zeroes(16)`, and the stretch output is `T = Nh` (64 for
  ristretto255-SHA512, 32 for P256-SHA256). Costs are minimal (`m = 8`,
  `t = 1`, `p = 1`) — both properties are cost-independent.

### Differential testing — VOPRF / POPRF vs voprf 0.5

`voprf` 0.5, the RFC 9497 implementation `opaque-ke` builds on, as the peer
for the verifiable modes added in `0.6.1`.

- **Where:** `pakery-tests/tests/differential_voprf.rs`, behind the same
  `differential` feature.
- **Coverage:** both suites, both modes, batches of 1 to 4. Byte-compared: the
  derived secret and public keys, blinded elements, evaluated elements, and the
  PRF output four ways — each implementation's client finalizing each
  implementation's proof — against both servers' `Evaluate`. Blinds are
  equalized through a planned RNG that serves each call exactly one chunk of
  exactly the planned length and fails if anything is left over, so a change in
  either side's RNG consumption fails loudly.
- **Not compared, deliberately:** proof bytes (pakery hedges the nonce; the
  cross-verification is the comparison, and the RFC vectors pin the bytes),
  and rejection of malformed input (`voprf` ignores trailing bytes, and on
  P-256 decompacts SEC1 `0x05` encodings and zero-pads short keys, so it is
  not an oracle for that). Two known divergences are pinned by their own tests.
  Limits documented in `pakery-tests/README.md`.

### Constant-time verification (Valgrind + crabgrind)

The graviola/ctgrind pattern: run real protocol flows under Valgrind memcheck
with secret bytes marked undefined, so any secret-dependent branch or memory
index is flagged — in debug **and** release (catches LLVM undoing `subtle`).

- **Where:** `pakery_core::ct` helpers + `__ctgrind` feature (compiled to
  no-ops without it); harness `pakery-tests/tests/ct_flows.rs`; suppressions
  `pakery-tests/valgrind-ct.supp`; workflow `.github/workflows/ct.yml`.
- **Notes:** crabgrind panics at runtime if built without real Valgrind
  headers, so the helpers guard on `ct::is_active()`. Under `ct.yml`, which
  sets `PAKERY_CT_EXPECT_ARMED=1`, `ct_harness_is_armed` fails the run unless
  the helpers are armed, the binary is actually running under Valgrind, and
  memcheck is the tool answering its requests. `declassify_choice`
  routes the decision byte through `black_box` (without it, release LLVM
  branched on the pre-declassify register copy). The debug leg disables
  overflow-checks/debug-assertions (panic instrumentation floods memcheck on
  intentionally-tainted CT arithmetic in deps). The suppressions cover one
  P-256-only, dependency-internal pattern: an invariant-true `CtOption`
  assert in the OSSWU map of p256's hash-to-curve. There is one entry per
  build, since release inlines the assert's `unwrap` and debug does not, and
  each is the assert's own two frames, with no leading `...`. Valgrind
  commons errors up by the top four code addresses on their stack, to which
  an inlined frame adds none, so an entry also covers later errors that
  share them; for these two entries that can only be the same assert.
  Everything else runs unsuppressed: the rest of the hash-to-curve, the
  field inversion, and every SEC1 encoding. Nothing has to take that on
  trust: `ct.yml` runs Valgrind with `-s`, which lists each entry used and
  how many errors it absorbed, and `ci/check-ct-suppressions.py` fails the
  run unless that list is exactly the one `pakery-tests/valgrind-ct.expected`
  gives for the build — an entry missing, an entry not listed (Valgrind's
  default ones included) or a count that moves all fail it, and
  `ci/test-check-ct-suppressions.py` break-tests the check on every run.
  Anchors are matched against mangled symbol names (inlined frames by their
  bare names), not the demangled names Valgrind prints. curve25519-dalek
  needs none. One pattern is never suppressed: a report in crypto-bigint's
  `safegcd` inversion, which p256's field and scalar inversions use and which
  is constant time by construction. Such a report is a branch or an index on
  secret data inside it; whether that diverges in time is for the assembly
  and upstream to settle, and nothing at pakery's boundary can fix or justify
  it. So no release is tagged, no entry is added, and it is reported
  upstream with the log. `valgrind-ct.supp`'s header states the rule, and
  `ci/check-ct-suppressions.py` refuses an entry that names `safegcd`. OPAQUE uses identity-KSF suites (Argon2id is
  data-dependent by design).
  The flows cover the RFC 9497 VOPRF / POPRF too — both suites and modes,
  random and deterministic blinds, single and batched, with the server key
  taken three ways — and `DhGroup::public_key_from_private`, which no OPAQUE
  flow calls (tainted on P-256; ristretto255 launders its canonicity check
  by design, so there it only runs). A guard test fails a run built without
  `p256` or `hazmat`, whose flows would otherwise be compiled out in silence.
  Ephemeral secrets are marked from the start: the rejection sampling of
  P-256's `random_scalar` and base-mode blind decides on an unmarked
  candidate and then marks the accepted bytes and re-derives the scalar
  from them, as the RFC 9497 suites do; `DhGroup::derive_keypair` marks its
  seed on both groups, which OPAQUE fills from the RNG for its ephemeral
  key shares; and a guard test asks memcheck (`GET_VBITS`) whether each
  group's `random_scalar` and `derive_keypair` return marked secrets. Until
  `0.6.1` these scalars went unmarked until after use (the base-mode blind
  was marked only after `t * r`), so every P-256 multiplication by one ran
  with that scalar unmarked: CPace's `K`, the SPAKE2+ verifier's `V`, the
  fixed-base `x * G` and `y * G` of SPAKE2 and SPAKE2+, and OPAQUE's
  ephemeral public keys and the Diffie-Hellman products computed with an
  ephemeral key carried no taint at all, and the others (CPace's shares,
  SPAKE2's `K`, SPAKE2+'s `Z`, the base-mode `t * r`) were tainted only
  through their points.
- **The `0.6.1` P-256 fix, and why the harness had not caught it.** sec1's
  *compressed* encoding branches on the parity of y. Until `0.6.1` it encoded
  two secret points — the unblinded value in the base-mode OPRF's `finalize`
  (and so OPAQUE P-256's client) and the `P256Dh` shared point (OPAQUE
  P-256's 3DH, on the server a static key times a peer-chosen point) — and the
  harness saw neither: the secret scalars were parsed from *laundered* copies,
  so the points carried no taint, and three suppressions anchored on the
  encoder's name would have hidden them anyway, on the false ground that only
  public elements reached it. Every P-256 encoding now goes through a
  constant-time encoder: the compressed ones, and the uncompressed one in
  `P256Group::to_bytes` (CPace, SPAKE2, SPAKE2+), whose sec1 tag dispatch
  revealed only whether the point is the identity but needed a suppression
  that, in the debug build, also took in every later tag dispatch through
  sec1's `as_bytes`. The secret scalars stay tainted through the parse (only
  the accept/reject decision is declassified), and no suppression touches
  sec1 any more: a run that put either sec1 encoder back failed both legs of
  `ct.yml`.

### Mutation testing (cargo-mutants)

Finds code the tests do not actually constrain — highest yield exactly where
positive RFC vectors never look: error paths, `is_identity()` checks, `ct_eq`
branches, length guards.

- **Where:** config in `.cargo/mutants.toml`; workflow
  `.github/workflows/mutants.yml` (weekly full run sharded 8×, a `summarize`
  job that aggregates survivors into a deduplicated GitHub issue, plus an
  advisory `--in-diff` job on PRs). Runbook in CONTRIBUTING.md.
- **It does not run on a push to `main`**, and neither does `dudect.yml`:
  `mutants.yml` triggers on `schedule` + `workflow_dispatch` + `pull_request`,
  `dudect.yml` on `schedule` + `workflow_dispatch`. A release cut mid-week
  therefore ships unchecked by either unless they are dispatched by hand
  (`gh workflow run Mutants --ref main`). `CI`, `CT`, `Fuzz` and `audit` do
  run on push.
- **Compare `caught` across runs, never `missed`.** An `exclude_re` entry
  added to silence a survivor drives `missed` to 0 while shrinking `caught`,
  and no other signal in the workflow reports that. The `summarize` job puts
  both on the run summary for exactly this comparison.
- **Config notes:** `test_package` lists all 7 workspace members —
  `test_workspace = true` is unusable (it injects a colliding `--workspace` and
  leaves the baseline building only the mutated crates, where the feature names
  do not resolve); `additional_cargo_args = ["--workspace"]` fixes baseline
  feature resolution. Features `p256 + argon2 + differential + hazmat`: argon2
  and hazmat must be **ON** or `ksf.rs` and the deterministic-blind path are
  cfg'd out and their mutants become false survivors; `__ctgrind` is **OFF**. `minimum_test_timeout = 120` catches mutants that
  break rejection-sampling loops (they hang → killed by timeout).
- **Exclusions** (each justified in the config): the `ct.rs` no-op helpers, the
  `o_cat` `>`→`>=` equivalent mutant, the `leb128_encode` `==`→`!=` mutant
  (a genuine behavioural change whose OOM failure mode is unrecordable without a
  per-process memory sandbox), four `Drop` delegations to `zeroize()` —
  two in spake2plus, and the server and client-state cores of the verifiable
  OPRF modes — matched by one entry (drop-time observation is UB from safe
  Rust), and four equivalent mutants matched by one entry: the verifiable
  modes' `identity` and `scalar_zero` replaced with `Default::default()`,
  which the curve crates define as that same identity and zero. The test
  `curve_defaults_are_the_identity_and_zero` in each suite file asserts that
  against the crates' own constants, so a dependency bump that changed it
  fails a test instead of hiding a mutant. Ten entries as of `0.6.1`: the
  `Drop` entry's pattern was widened for the two cores rather than an entry
  added, and the tenth is the group-constant one. The verifiable modes' public
  types are generated by a `macro_rules!`, whose bodies cargo-mutants does not
  mutate, so every branch lives in the generic core and the generated wrappers
  only delegate.
- **Coverage totals are reported, because `missed = 0` does not mean coverage
  held.** An `exclude_re` entry added to silence a survivor drives `missed` to
  zero while shrinking `caught`, and nothing else in the workflow reports
  that. The `summarize` job now aggregates every shard's `outcomes.json` and
  writes total / caught / missed / timeout / unviable plus the current
  `exclude_re` count to the run's summary page, so a drop is visible without
  reading logs. It also warns if it aggregated fewer than 8 shard files —
  summarizing over a missing shard would otherwise look like a clean run.
- **Exit codes in CI:** cargo-mutants exit 3 (timeouts only) is treated as
  success (a timeout is a kill, not a survivor); survivors (exit 2) are gated
  independently by the `summarize` job reading each shard's `missed.txt`.

### Hygiene — zeroize asserts, scoped Miri, dudect advisory

- **Zeroize tests:** an in-crate unit test per `Zeroize`/`ZeroizeOnDrop` struct
  in every crate, asserting all secret fields are zero after `.zeroize()` on a
  live value (catches a future field added without zeroization). The two
  spake2plus manual `Drop` impls were refactored to `impl Zeroize` + `Drop`
  delegating to it, so they are testable on a live value; the VOPRF / POPRF
  server and client state follow the same pattern, and a wiped server or state
  is refused rather than used.
- **Scoped Miri:** `miri` job in `ci.yml`, pinned nightly,
  `-Zmiri-strict-provenance`, `cargo miri test -p pakery-core --lib`, default
  features only (protocol crates use dalek, impractical under Miri).
- **dudect advisory:** standalone `dudect/` workspace (excluded from root),
  weekly non-blocking `.github/workflows/dudect.yml` — statistical timing on
  the confirmation-MAC verify paths and `SharedSecret` equality. Both verify
  benches contrast two *wrong* tags differing in where the first mismatching
  byte falls, rather than a correct tag against a wrong one: the accept/reject
  outcome is public by design — `pakery_core::ct` declassifies it, per the
  marking policy above — so classes split that way measure the cost of a
  public decision and can report a difference with nothing wrong. The job
  fails on `|t| > 5`, which is a prompt to re-run rather than a finding — on
  byte-identical code one bench has reported -4.55, +20.17 and +3.02 within
  minutes; `dudect/README.md` carries the five measurements and the
  interpretation rules. `t < 5` proves nothing either.

---

## Documentation gate — and what it cannot check

`ci/check-docs.py` runs on every push and PR. It is a Baseline check, older
than the layers above and not one of them: four checks — feature tables,
install-snippet versions and MSRV, `[package.metadata.docs.rs]` coverage, and
every fenced `rust` example compiled *and run* as a standalone crate built
from the `toml` block above it — each named after a doc regression this
workspace has actually shipped. The script's own docstring records which.
Its break-tests (`ci/test-check-docs.py`) run first and are not optional: two
of these checks have failed *open* before, printing "all claims verified"
because a parse bug had stopped them from looking.

Two blind spots remain. Both are known, both need review, and neither has a
mechanical fix worth what it would cost.

- **Fenced blocks tagged `bash` are not checked.** The gate parses info
  strings and branches on `rust` and `toml` only, so the commands documented
  in `pakery-tests/README.md`, `fuzz/README.md` and `dudect/README.md` are prose
  that nothing runs. The cheap ones were verified by hand in the `0.3.1`
  audit; the rest need Valgrind (unavailable on darwin/arm64), nightly plus
  cargo-fuzz, or multi-minute runs — which is why they are not wired into a
  gate every PR waits on. Re-verify them by hand when the surrounding tooling
  changes.
- **Prose claims are not checked at all.** A sentence asserting conformance,
  coverage or provenance is verifiable only by reading it against the code,
  and this is where documentation actually drifts. The `0.5.0` audit found
  three that had: `Spake2Ristretto255` and `Spake2PlusRistretto255` described
  as RFC-validated, where neither RFC tabulates that group; `pakery-cpace`
  claiming validation against the draft's vectors without saying that only
  the ristretto255 suite has them; and this file claiming positive vectors
  "for all 4 protocols on both groups" where 5 of 8 combinations have them.
  Each was contradicted by a test file in this same repository, and nothing
  mechanical would have caught any of them. Treat a prose claim about what is
  tested as unverified until someone has read it against the test that is
  supposed to back it.

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
  covered instead by RFC vectors, property tests, and the OPAQUE and VOPRF /
  POPRF differential oracles.
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

- MSRV 1.85 bump + dep group (dalek 5 / argon2 0.6 / p256 0.14 / digest 0.11
  wave) — DONE; see CHANGELOG. `rand_core` 0.10 followed in 0.4.0, removing the
  `os_rng` feature from six published crates and putting the whole tree on one
  rand_core.
- LLVM constant-time intrinsics and Rust secret-types RFC 2859 — nothing usable
  from stable Rust yet.
- Re-verify tool versions periodically (this document's survey is from
  2026-07-05).
