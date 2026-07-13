# pakery fuzz harness

Coverage-guided fuzzing (cargo-fuzz / libFuzzer) of everything that parses
attacker-controlled bytes, plus the protocol state machines fed adversarial
peer messages. This directory is a standalone cargo workspace, excluded from
the root one, so the MSRV / no_std / minimal-versions / wasm CI jobs never
see it. The layout is OSS-Fuzz-compatible (maps 1:1 to a future
`projects/pakery`).

## Targets

| Target | What it fuzzes | Extra invariants beyond "no panic" |
|--------|----------------|-------------------------------------|
| `opaque_deserialize` | All 8 OPAQUE wire messages × both suites | `Ok` ⇒ byte-identical re-serialization |
| `group_decode` | `from_bytes` / `from_uniform_bytes` / `scalar_from_wide_bytes`, DH, OPRF evaluate/finalize, both groups | ristretto255 decode ⇒ canonical re-encode; P-256 decode/encode roundtrip |
| `cpace_flow` | Honest CPace side receives fuzz peer share (both roles, both modes, both suites) | — |
| `spake2_flow` | Honest SPAKE2 side receives fuzz share + fuzz confirmation MAC | fuzz MAC never verifies |
| `spake2plus_flow` | Honest SPAKE2+ prover/verifier receives fuzz shareP / shareV+confirmV / confirmP | fuzz confirmV/confirmP never verify |
| `opaque_flow` | Structure-aware (`arbitrary`) full registration + login, incl. `start_fake` and replace/XOR tampering of any wire message | honest flow completes with equal keys; tampered flow never completes; `start_fake` client never completes |

The fuzz profile builds with `overflow-checks` and `debug-assertions`
enabled, so arithmetic and internal invariants are oracles too.

## Running locally

Requires a nightly toolchain and cargo-fuzz (`cargo install cargo-fuzz`).
From the repository root:

```bash
# list targets
cargo +nightly fuzz list

# run one target (seeded with the checked-in corpus)
mkdir -p fuzz/corpus/opaque_deserialize
cargo +nightly fuzz run opaque_deserialize \
    fuzz/corpus/opaque_deserialize fuzz/seeds/opaque_deserialize \
    -s none -- -max_total_time=60
```

`-s none` disables ASan: the whole workspace is `#![forbid(unsafe_code)]`
(sanitizers were evaluated and rejected in SECURITY_TESTING.md), and
running without it roughly doubles throughput. The oracles are panics,
overflow checks, debug assertions, and the per-target invariants above.

Reproduce a finding:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file> -s none
```

## Seed corpus

`fuzz/seeds/<target>/` is checked in: RFC 9807 test-vector messages plus
valid messages from deterministic honest flows (see
`examples/gen_seeds.rs`; regenerate with `cargo run --example gen_seeds`
from `fuzz/`). The MAC-verifying targets are deliberately seeded with
all-zero MACs only — a valid share+MAC pair built with the harness password
would (correctly) trip their forgery asserts.

CI keeps the growing corpus in the actions cache under
`fuzz-corpus-<target>-*` keys (see `.github/workflows/fuzz.yml`); PR smoke
runs and the scheduled long runs share it via restore-key fallback.

## Scheduled long runs (runbook)

`.github/workflows/fuzz-long.yml` runs weekly (Monday 03:17 UTC) and on
manual dispatch (the `max_total_time` input overrides the default 1800 s
per target). Each target gets a fork-mode run:

```bash
cargo fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target> -s none -- \
    -fork=$(nproc) -ignore_crashes=0 -ignore_ooms=0 -ignore_timeouts=0 \
    -max_total_time=1800
```

`-ignore_crashes=0` stops the fork server on the first failure — cargo-fuzz
0.13 has no `--stop-after-first-failure` flag; this is the libFuzzer
equivalent. After a clean run the corpus is minimized in place with
`cargo fuzz cmin <target> -s none` and saved back to the shared
`fuzz-corpus-<target>-*` cache. A failed run does **not** save its corpus
(the cache post step skips on failure), so crashing inputs never pollute
the shared corpus.

**On findings** the job uploads `fuzz/artifacts/<target>/` as a run
artifact and opens a GitHub issue titled
`Scheduled fuzz failure: <target>` (or comments on the open one — no
duplicates). To triage: download the artifact, drop the crash file into
`fuzz/artifacts/<target>/`, and reproduce with

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file> -s none
```

**Coverage** (advisory, never blocks): after the long jobs, a follow-up job
replays each target's corpus + seeds under instrumentation and uploads
per-target `llvm-cov report` summaries as the `fuzz-coverage-reports` run
artifact — use them to spot dead corners the fuzzers never reach.
Locally:

```bash
cargo +nightly fuzz coverage <target> fuzz/corpus/<target> fuzz/seeds/<target> -s none
# binary lands under target/ at the repo root, NOT fuzz/target/
"$(rustc +nightly --print sysroot)/lib/rustlib/<triple>/bin/llvm-cov" report \
    target/<triple>/coverage/<triple>/release/<target> \
    -instr-profile=fuzz/coverage/<target>/coverage.profdata \
    -ignore-filename-regex='(\.cargo/registry|\.rustup|/rustc/)'
```
