# pakery dudect harness

Advisory statistical constant-time testing of pakery's secret-comparison
paths, using [dudect-bencher](https://crates.io/crates/dudect-bencher) (the
[DudeCT](https://eprint.iacr.org/2016/1123.pdf) methodology: two input
classes and Welch's t-test over runtime distributions).

This directory is a standalone cargo workspace, deliberately excluded from
the root one: dudect-bencher 0.7 pulls a clap 2-era dependency tree that
would otherwise burden the MSRV, minimal-versions, and audit CI jobs.

## Benches

| Bench | Path under test | Left class | Right class |
|-------|-----------------|------------|-------------|
| `spake2_confirm_verify` | `Spake2Output::verify_peer_confirmation` (the `ct_eq`-on-`Vec<u8>` shape shared by every confirmation check) | wrong MAC, first byte differs | wrong MAC, last byte differs |
| `hmac_verify` | `Mac::verify` (HMAC recompute + `ct_eq`) — the primitive under the SPAKE2+/OPAQUE confirmation paths, whose state machines consume `self` and cannot be re-measured in a loop | wrong tag, first byte differs | wrong tag, last byte differs |
| `shared_secret_eq` | `SharedSecret == SharedSecret` | equal secret | random secret |

### Why the verify benches compare two *wrong* tags

Both verification benches reject every sample, and their classes differ only
in where the first mismatching byte falls. The obvious split — correct tag
against wrong tag — would separate the classes by the accept/reject
*outcome*, which pakery declares **public** by design: `pakery_core::ct`
declassifies that decision, and the callers branch on it to build `Ok` or
`Err`. A class split along a bit the code is allowed to branch on cannot
tell a leaking comparison from a public decision that costs something.
Holding the outcome fixed leaves the mismatch position as the only variable,
which is precisely what `ct_eq` exists to make invisible. Each bench asserts
that both of its classes are rejected before it times anything, so the
property cannot quietly stop holding.

`shared_secret_eq` keeps an equal/random split: the same argument applies to
it in weaker form, since `SharedSecret::eq` returns a `bool` and has no
error arm to construct.

### What these classes catch, and what they miss

Measured on arm64, three runs each, with `Mac::verify`'s `ct_eq` swapped for
a deliberately leaky comparison over the same two classes:

| Comparison under test | max \|t\|, three runs |
|---|---|
| `ct_eq` — what ships | -5.74, -1.03, +1.77 |
| hand-rolled `iter().zip(..).all(..)` early exit | **-59.43, -167.06, -151.53** |
| slice `==` (memcmp) | -4.02, +7.61, -1.52 |

A hand-rolled early exit is caught in every run, by two orders of magnitude.
Slice `==` is **not**: at 64 bytes a vectorized memcmp resolves a first-byte
and a last-byte mismatch in close to the same time. That spelling is
`ct.yml`'s to catch rather than this harness's, because memcheck does not
need the difference to be large enough to measure: `expected_peer_mac` is
deliberately never declassified (`pakery-spake2/src/transcript.rs:105-107`,
"stays secret until compared"), which is the marking that would make a
byte-wise branch on it visible. Not confirmed here — Valgrind does not run on
darwin/arm64.

## Running locally

```bash
cd dudect
cargo run --release                     # all benches
cargo run --release -- --filter hmac    # subset by name
cargo run --release -- --continuous spake2_confirm_verify  # keep sampling
```

## Interpreting results

- **A single `|t| > 5` is a prompt to re-run, not a finding.** The CI job
  fails on it and opens an issue; that issue is the prompt. Re-run before
  investigating, and before believing it.
- **`|t| > 5` that reproduces** — strong evidence of a timing leak.
- **`|t| < 5`** — proves *nothing*: another input distribution might still
  leak, and the table above names one spelling of the bug this harness does
  not resolve. Deterministic constant-time verification is `ct.yml`'s job
  (Valgrind + crabgrind, roadmap item 6); this workflow
  (`.github/workflows/dudect.yml`) is weekly, `continue-on-error: true`, and
  never a PR gate (orion pattern).

### Why a single spike means so little

Measured 2026-09-20 on byte-identical code — `a896c9c` and `014abe7` differ
by zero `.rs` files — `hmac_verify` reported **-4.55**, then **+20.17**
(which opened issue #33), then **+3.02** three minutes later on the same
commit. Across five runs on that code the sign never settled:

    -3.20, +2.64, -4.55, +20.17, +3.02

Nothing under test changed between any two of them. One run is one sample of
a noisy statistic; read it as that.
