# pakery-tests

Integration tests for the pakery workspace: RFC/draft test vectors, negative
vectors, property-based tests, and differential testing. Not published.

## Test layers

| Layer | Files | Runs by default |
|-------|-------|-----------------|
| RFC/draft positive vectors | `*_vectors.rs` | yes (`p256` feature for P-256 suites) |
| Negative vectors (official CPace + home-grown sweep) | `negative_vectors.rs`, `cpace*_vectors.rs`, `vectors/negative_vectors.json` | yes |
| Property-based tests (proptest) | `prop_*.rs` | yes |
| Differential testing vs opaque-ke | `differential_opaque.rs` | no — `differential` feature |
| Differential testing vs voprf (RFC 9497 VOPRF / POPRF) | `differential_voprf.rs` | no — `differential` feature |
| Constant-time harness (ctgrind) | `ct_flows.rs` | no — `__ctgrind` feature |

## Feature flags

- `p256` — enables the P-256 suites in vector and property tests.
- `argon2` — enables the Argon2id KSF tests.
- `differential` — enables the OPAQUE differential suite against
  [opaque-ke](https://crates.io/crates/opaque-ke) v4, and the RFC 9497 VOPRF /
  POPRF differential suite against [voprf](https://crates.io/crates/voprf)
  0.5. Implies `p256` and
  `argon2` (the suite covers an Argon2id case on both sides, which is what
  pins the KSF salt and `T = Nh` against a conformant peer). Kept out
  of default runs because opaque-ke pulls a large dependency tree; CI covers it
  through the `--all-features` test/check jobs. Note the MSRV job does **not**
  cover it: `ci.yml` runs `cargo check --workspace --exclude pakery-tests
  --all-features` on 1.85, deliberately excluding this crate so that an
  opaque-ke release raising its own MSRV cannot redden a gate that exists to
  protect the *published* crates.
- `hazmat` — forwards pakery-crypto's `hazmat`, so the property tests and
  the constant-time harness also exercise the VOPRF / POPRF
  `deterministic_blind`. It is deliberately not on the pakery-crypto
  dependency line: feature unification would then build every plain
  `cargo test --workspace` with it, and nothing would test the build without
  it.
- `__ctgrind` (private) — enables the constant-time verification harness
  (`ct_flows.rs`) and turns `pakery_core::ct`'s helpers into Valgrind
  memcheck client requests via [crabgrind](https://crates.io/crates/crabgrind).
  The `ct.yml` workflow runs it under
  `valgrind --track-origins=yes --error-exitcode=99` in debug and release;
  secret-dependent branches or memory indexing fail the run. Outside Valgrind
  (or when crabgrind was built without real Valgrind headers, e.g. on macOS)
  the marks are no-ops, so `--all-features` runs stay harmless. The marking
  and declassification policy — including the accepted dependency-boundary
  laundering of dalek/p256 scalar canonicity checks — is documented in
  `pakery_core::ct`'s module docs and at each `ctgrind:` call-site comment.

```bash
cargo test -p pakery-tests --features differential --test differential_opaque
cargo test -p pakery-tests --features differential --test differential_voprf

# Constant-time harness (Linux with valgrind installed):
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --track-origins=yes --error-exitcode=99 --quiet" \
  PAKERY_CT_EXPECT_ARMED=1 \
  cargo test -p pakery-tests --features __ctgrind,p256,hazmat --test ct_flows -- --test-threads=1
```

## The differential oracle and its limits

`differential_opaque.rs` drives our OPAQUE implementation and opaque-ke v4
(RFC 9807 final) through full registration + login flows on identical
deterministic inputs, for both matched ciphersuites:

- ristretto255 + SHA-512 + identity KSF
- P-256 + SHA-256 + identity KSF

Inputs are equalized as follows: server long-term material is injected into
opaque-ke via `ServerSetup::deserialize` and into ours via the `test-utils`
constructor; nonces and ephemeral-keypair seeds are supplied positionally
through a chunk-per-call mock RNG matching opaque-ke 4.0.1's internal RNG
consumption order (a changed order panics loudly instead of comparing
garbage); OPRF blinds are sampled by opaque-ke, then the exact blind scalar is
extracted from its serialized client state and replayed into our
implementation through the RNG.

**Byte-compared:** all six protocol messages (registration request/response,
registration record, KE1/KE2/KE3), `export_key` (registration and login) and
`session_key` (client and server side, both implementations — four-way
equality).

**Not byte-compared:** nothing in the honest flow. The one deliberately
untested path is fake credentials for unknown users (opaque-ke's
`password_file: None` vs our `ServerLogin::start_fake`): both sample fresh
randomness for the fake record by design (ours generates a random fake client
public key, opaque-ke reuses the long-term `dummy_pk` from `ServerSetup`), so
their outputs are incomparable by construction. That path is covered by our
own unit/property/fuzz tests instead.

Cases: four fixed deterministic runs (default and explicit identities per
suite) plus proptest-randomized inputs (16 cases per suite: passwords,
credential ids, identities, context, seeds, nonces, blinds).

## The VOPRF / POPRF oracle and its limits

`differential_voprf.rs` compares pakery-crypto's RFC 9497 VOPRF and POPRF with
`voprf` 0.5, the implementation opaque-ke builds on, for both suites
(ristretto255-SHA512 and P256-SHA256). Keys come from `DeriveKeyPair` on both
sides; blinds are equalized by feeding both the same RNG bytes through a
planned RNG that serves each call exactly one chunk of exactly the planned
length and checks on drop that nothing was left over.

**Byte-compared:** secret and public keys, blinded elements, evaluated elements
(single and batched), and the PRF output four ways — each implementation's
client finalizing each implementation's proof — against both servers'
`Evaluate`.

**Not byte-compared:** proofs. pakery-crypto hedges the proof nonce with the key
and the statement, so its proofs differ from `voprf`'s on equal RNG bytes; each
client verifying the other's proof is the comparison, and the proof bytes are
pinned by the RFC vectors in pakery-crypto. Nor is `voprf` used as an oracle
for rejecting malformed bytes: its deserializers ignore trailing bytes, and
its P-256 path decompacts SEC1 `0x05` encodings and zero-pads short keys in
`new_with_key`.

**Known divergences, pinned by their own tests:** a proof with a zero `c` or
`s` is a deserialization error in `voprf` and a verification failure here
(RFC 9497 §4 lets `DeserializeScalar` return any value in `[0, p - 1]`); and
`voprf`'s POPRF `evaluate(input, None)` leaves out the `info` framing its own
`finalize(.., None)` includes, so the suite always passes `Some(info)`.

Cases: the RFC 9497 Appendix A key material as a fixed case, plus 16
proptest-randomized cases per suite and mode (batches of 1 to 4).
