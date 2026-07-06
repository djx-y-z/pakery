# pakery dudect harness

Advisory statistical constant-time testing of pakery's secret-comparison
paths, using [dudect-bencher](https://crates.io/crates/dudect-bencher) (the
[DudeCT](https://eprint.iacr.org/2016/1123.pdf) methodology: two input
classes — fixed vs random — and Welch's t-test over runtime distributions).

This directory is a standalone cargo workspace, deliberately excluded from
the root one: dudect-bencher 0.7 has MSRV 1.85 (the workspace MSRV is 1.79)
and pulls a clap 2-era dependency tree that would otherwise burden the MSRV,
minimal-versions, and audit CI jobs.

## Benches

| Bench | Path under test | Left class | Right class |
|-------|-----------------|------------|-------------|
| `spake2_confirm_verify` | `Spake2Output::verify_peer_confirmation` (the `ct_eq`-on-`Vec<u8>` shape shared by every confirmation check) | correct peer MAC | random MAC |
| `hmac_verify` | `Mac::verify` (HMAC recompute + `ct_eq`) — the primitive under the SPAKE2+/OPAQUE confirmation paths, whose state machines consume `self` and cannot be re-measured in a loop | correct tag | random tag |
| `shared_secret_eq` | `SharedSecret == SharedSecret` | equal secret | random secret |

## Running locally

```bash
cd dudect
cargo run --release                     # all benches
cargo run --release -- --filter hmac    # subset by name
cargo run --release -- --continuous spake2_confirm_verify  # keep sampling
```

## Interpreting results

- **|t| > 5** — strong evidence of a timing leak; the CI job fails.
- **t < 5** — proves *nothing*: another input distribution might still leak,
  and local-machine statistics are noisy. This is why the CI job
  (`.github/workflows/dudect.yml`) is weekly, `continue-on-error: true`, and
  never a PR gate (orion pattern). Deterministic constant-time verification
  is `ct.yml`'s job (Valgrind + crabgrind, roadmap item 6).
