## [0.6.0] - 2026-09-22

Breaking release, and a narrow one: it closes the one instance of the defect class `0.5.0` was about that `0.5.0` could not reach, and wipes four buffers of secret material that were dropped on an error path.

`0.5.0` tied an `OpaqueCiphersuite`'s nine length constants to the primitives they restate. A tenth quantity — RFC 9807 §7's `T = Nh`, the KSF's output length — could not join them, because the `Ksf` trait had no length to check against and the copy lived on `Argon2Params`, which `pakery-opaque` cannot see. `0.5.0` answered it with prose in two places and a test over the *shipped* Argon2id suites, which is no check at all for a ciphersuite this crate does not ship — and `pakery-opaque/README.md` teaches exactly how to write one. The length is now an argument to `Ksf::stretch`, so the mismatch is no longer representable, and the result is verified against `Nh` at the call site, so an implementation that ignores the argument is rejected rather than used.

Auditing that fix turned up the quantity that *could* have joined the nine and had not: the OPRF's own output length, which is also `Nh` and which every argument here leans on. It is the tenth assertion now.

**No wire format changes, and no re-registration.** Every RFC vector passes unchanged, and all four pre-built OPAQUE suites produce byte-identical output to `0.5.0` — the identity-KSF suites because their bytes are pinned to RFC 9807 Appendix C literals, whose vectors use the identity KSF; the Argon2id suites by construction, because the salt and the cost parameters are unchanged and the length now passed in is the constant it replaced. Nothing compares `0.5.0` bytes to `0.6.0` bytes directly. What the differential suite against `opaque-ke` adds is independent: it agrees byte-for-byte on both Argon2id suites, pinning the salt and `T = Nh` against a conformant peer at both `Nh` values. What changes is how that is guaranteed, not what it produces. The breaking changes affect code that implements `Ksf`, `Argon2Params` or `Oprf`, or names the `Nh32` types.

### Changed

- **Breaking: `Ksf::stretch` takes the output length as an argument** — `stretch(input: &[u8], output_len: usize)`. RFC 9807 §7 writes `T = Nh` in both of its recommended Argon2id configurations, tying it to the ciphersuite, so it belongs to the call — and the caller is the only party that knows `Nh`.
  - *The type system had already said so.* `IdentityKsf` backs both `OpaqueRistretto255` (`Nh = 64`) and `OpaqueP256` (`Nh = 32`), so no single constant on the implementation can be right for both. Any design that keeps the length on the type needs an "unconstrained" escape hatch for it — and an escape hatch on a length check is a one-token way to switch the check off.
  - *It is also the shape everything around it already has.* `argon2` 0.6, `scrypt` 0.12 and `pbkdf2` 0.13 all take the output length **at the call rather than as a property of the type** — each writes into a caller-supplied slice. (Each also carries an output length on its `Params`; scrypt's own documentation says that one is for the `PasswordHasher` API and that the low-level call "determines the output length using the size of the `output` slice".) `opaque-ke` — the conformant implementation this crate differential-tests against — spells its KSF `hash<L>`, mapping `L` to `L`; it reads the length off the input type rather than taking it as an argument, which is a different route to the same conclusion: the length is not an associated constant of the implementation.
  - *Migration:* add the parameter and honour it. An implementation that cannot produce the requested length must return an error, not a different length.
- **Breaking: `Argon2Params::OUTPUT_LEN`, `DefaultArgon2ParamsNh32` and `Argon2idKsfNh32` are removed.** `Argon2Params` is now a pure cost parameter set (`M_COST`, `T_COST`, `P_COST`), and one `Argon2idKsf` serves every suite. `0.5.0` added those two items to give `OpaqueP256Argon2` a 32-byte KSF; with the length at the call site there is nothing left for them to carry.
  - *Migration:* `Argon2idKsfNh32` → `Argon2idKsf`; drop `OUTPUT_LEN` from any `Argon2Params` impl. Nothing else changes, including the bytes either alias produced.
- **Breaking (behaviour, in the fail-closed direction): a stretch result that is not `Nh` bytes is rejected.** `derive_randomized_password` now fails with `OpaqueError::InternalError("KSF output length != Nh (RFC 9807 §7: T = Nh)")` instead of concatenating a wrong-length value into the `Extract` input.
  - *This is the half a signature cannot reach.* Passing `Nh` in makes the mismatch unrepresentable for a KSF that honours its argument; one that ignores it is the only remaining way to reproduce the pre-`0.5.0` P-256 defect, and it is the shape a hand-written downstream KSF can still take. The check is tied to the bytes returned, not to any declaration about them.
  - *No new error variant*, so the error enums are unchanged; and the condition depends only on the local ciphersuite, never on remote input, so it is not an oracle under `OpaqueError`'s own security note.
- **Breaking (behaviour): `IdentityKsf` rejects an `output_len` that differs from its input length** rather than silently returning the input at the wrong length. In OPAQUE both are `Nh`, which this release now enforces rather than assumes (see the `Oprf::OUTPUT_LEN` entry below), so no shipped suite reaches the error — and a hand-written suite that would have reaches a build error first. The failure surfaces as `PakeError::InvalidInput`, which `pakery-opaque` maps to `OpaqueError::InvalidInput`; it is a different path from the `T = Nh` check below, which reports `InternalError`.

### Added

- **Breaking: `Oprf::OUTPUT_LEN`, and the tenth compile-time assertion it makes possible.** `Oprf` declared `KEY_LEN` (`Nok`) and `ELEMENT_LEN` (`Noe`), but nothing for the length of `OprfClientState::finalize`'s output — which is `Nh`. So the claim this release leans on ("the KSF input is the OPRF output, which is `Nh` bytes") held for the four shipped suites and was unenforced for every other. `assert_lengths` now runs ten `const` assertions, and `NH` is checked twice: against `Hash::OUTPUT_SIZE` and against `Oprf::OUTPUT_LEN`.
  - *It was reachable.* A hand-written suite naming a SHA-512 `Hash` (`NH = 64`) and a SHA-256 `Oprf` (32-byte output) passed all nine `0.5.0` assertions and built. It is now a build error naming the constant — verified by reinjecting the defect, as with the other nine.
  - *Migration:* declare `OUTPUT_LEN` on any `Oprf` impl — the length your `finalize` returns, 64 for a SHA-512 OPRF and 32 for a SHA-256 one. Every implementation in this workspace is updated.
- **`derive_randomized_password` verifies the OPRF output it was handed, not only the stretched result.** The assertion above pins what an `Oprf` *declares*; `finalize` returns a `Vec<u8>`, so this is the check tied to the bytes. It fails with `OpaqueError::InternalError("OPRF output length != Nh")` before the KSF is called, so no work is done on a wrong-length input.

### Fixed

- **Four buffers of secret material were dropped unwiped when a fallible call in front of them failed**, against this repository's own rule that intermediate secrets on the stack are built with `Zeroizing::new`.
  - `pakery-opaque`'s `ServerSetup::new` is the one that mattered: `oprf_seed` is filled from the RNG and *then* `DhGroup::generate_keypair` runs, which can fail — on that early return a buffer holding the server's long-term secret was dropped as a plain `Vec`. The struct's `ZeroizeOnDrop` only starts covering it once it is a field.
  - `Argon2idKsfWithParams::stretch` and both `Kdf::expand` implementations (`HkdfSha512`, `HkdfSha256`) hold the same shape. There the documented error paths all fail before anything is written, so in practice the dropped buffer was zeros — but that is an argument about *when* a dependency writes, which a future version could invalidate silently.

### Notes

- **The `0.5.0` wiring test is retired, not quietly deleted.** `opaque_vectors.rs::test_shipped_argon2_suites_stretch_to_their_nh` asserted that each shipped Argon2id suite was paired with the KSF alias of the matching length. There is one alias now and `pakery-opaque` passes `NH` to it, so the pairing it guarded no longer exists — the test would assert that `stretch(_, NH)` returns `NH` bytes, which is a tautology. What replaces it pins the half that is still reachable: a ciphersuite whose KSF ignores the requested length must fail registration rather than produce a record. Every new runtime branch is mutation-verified by hand — gutting it, or inverting its comparison, fails a named test.
- **A second structural guard, `the_only_ksf_stretch_call_is_followed_by_the_length_check`**, built in the shape of the existing `every_entry_point_asserts_lengths`. It asserts there is exactly one `Ksf` stretch call in `pakery-opaque` and that the `T = Nh` check sits directly behind it. The check is a property of that call site rather than of the trait, so a second call added later would reopen the hole while every test still passed.
  - *Both guards now walk `src/` recursively instead of naming the files they scan, and match with whitespace removed.* A hardcoded `include_str!` list does not see a file added later, a literal substring does not see `Ksf::stretch (`, and a non-recursive walk does not see `src/<subdir>/<file>.rs` — the last reproduces the first one level up, and no file count notices, because the number of `.rs` files directly under `src/` is unchanged. All three evasions were measured rather than assumed. The guards remain a backstop: they match source text, so a local alias for the trait is invisible to them, and the control is the runtime check. The walk needs `std`, which `cargo test` has by default; the `--no-default-features` jobs only ever run `cargo check`, which does not build test code at all.
- **Supersedes the `0.3.0` entry on the `argon2` `0.5` → `0.6` bump, which recorded a behaviour change it did not have.** That entry established that no protocol output changed and that `Params::new`'s accept/reject bounds were untouched. It did not record that memory allocation became *fallible*: `hash_password_into` allocated `vec![Block::default(); m]` in `0.5` — infallible, so exhaustion reached the allocation error handler and aborted the process — while `0.6` allocates through `Blocks::new(len).ok_or(Error::OutOfMemory)?`, which surfaces here as `PakeError::ProtocolError("argon2 hash")`. It is a robustness improvement rather than a regression, and it is most visible on `wasm32-unknown-unknown`, where an abort is a module trap the caller cannot inspect rather than a value it can handle, and where RFC 9807 §7's own recommended `m = 2^21` (2 GiB) makes exhaustion reachable. Downstreams that hand-rolled `try_reserve` + `hash_password_into_with_memory` to avoid the abort can stop. The released `0.3.0` entry is deliberately **not** edited in place, for the reason the `0.4.0` supersede note gives: `ci/release-notes.py` derives the published GitHub release body from it and a published body cannot be amended.
- **Provenance.** The KSF length gap, the undocumented `argon2` behaviour change and the `stretch` buffer were raised by a downstream integrator reviewing `0.5.0`. The `ServerSetup::new` instance and the two `Kdf::expand` ones were found by auditing the shape they pointed at. The structural fix shipped here is not the one that report recommended — it suggested an `Option<usize>` constant on the trait plus a tenth compile-time assertion; that is where the `IdentityKsf` argument above comes from, and it is why the length moved to the call instead.

## [0.5.0] - 2026-09-21

Breaking release. Two interop defects in the Argon2id key-stretching function, plus the structural gap that let them ship: an OPAQUE ciphersuite's nine length constants were hand-written and tied to nothing, so four of them could be wrong without a single pakery-to-pakery test noticing. They are now checked against the primitives at compile time, which required new associated constants on four `pakery-core` traits.

Every OPAQUE envelope this crate produced under an Argon2id suite was undecryptable by a conformant peer, and both failures were silent. **Users of the Argon2id suites must re-register.** Users on `IdentityKsf` or a hand-written `Ksf` are unaffected.

**No wire format changes beyond the Argon2id KSF.** CPace, SPAKE2, SPAKE2+ and the identity-KSF OPAQUE suites are byte-identical to `0.4.0`; every RFC vector passes unchanged. The other breaking change is to the trait surface, and it affects only code that implements a `pakery-core` crypto trait itself — not code that merely uses the shipped ciphersuites.

### Fixed

- **Breaking: the Argon2id KSF salt was `b"OPAQUE-Argon2id"`, not `zeroes(16)`.** RFC 9807 §7 specifies `S = zeroes(16)` for both of its recommended Argon2id configurations, and that is what conformant implementations use — `opaque-ke`'s `Ksf` impl passes `&[0; argon2::RECOMMENDED_SALT_LEN]`, which `argon2` defines as `16`. The old value was wrong on two counts by two separate standards: wrong bytes per RFC 9807 §7, and wrong length per RFC 9106 §4, which recommends a 128-bit salt for both of its options — `b"OPAQUE-Argon2id"` is 15 bytes. It never errored because `argon2`'s `MIN_SALT_LEN` is `8`.
  - *Scoped honestly.* §7 opens "Absent an application-specific profile, the following configurations are RECOMMENDED", so this is an interop defect rather than a specification violation. The interop framing is the stronger one regardless, because the constant's own docstring made the interop claim — "Fixed at `b"OPAQUE-Argon2id"` for cross-implementation interop" — about the one value that does not have that property.
  - *The failure was silent.* Registration and login both succeed. Only a conformant peer fails to open the envelope, where it presents as a wrong password.
- **Breaking: `OpaqueP256Argon2` stretched to 64 bytes where RFC 9807 §7 requires `T = Nh` = 32.** The KSF output is concatenated into the `Extract` input that derives the randomized password (`randomized_pwd = Extract("", concat(oprf_output, Harden(oprf_output)))`), so its length changes the result. `OpaqueP256Argon2` declares `NH = 32` but used `Argon2idKsf`, whose `OUTPUT_LEN` is 64 — correct for ristretto255-SHA512, wrong for P256-SHA256. opaque-ke's KSF is length-preserving (`hash<L>` maps `L` to `L`, called with the OPRF output), so a conformant peer stretches to exactly `Nh`.
  - The ristretto255 suite was never affected by this second defect: `Nh` is 64 there, which is what it used.
  - **New:** `Argon2idKsfNh32` (and its parameter set `DefaultArgon2ParamsNh32`) — the same costs with `OUTPUT_LEN = 32`. `OpaqueP256Argon2` now uses it. Hand-written SHA-256 ciphersuites should too; `Argon2idKsf` remains correct for SHA-512 suites.
  - *Same root cause as the salt, in a different dress:* a parameter that is suite-dependent by specification was hardcoded once, globally.

### Added

- **Length constants on four `pakery-core` traits, so OPAQUE's can be checked against them.** `Mac::OUTPUT_SIZE`, `Kdf::EXTRACT_SIZE`, `DhGroup::SK_LEN` / `PK_LEN`, and `Oprf::KEY_LEN` / `ELEMENT_LEN`. RFC 9807 defines `Nm`, `Nx`, `Nsk`, `Npk`, `Nok` and `Noe` as exactly these quantities; until now Rust had no way to read them off the associated types, so `OpaqueCiphersuite` restated them and nothing compared the two.
  - **Breaking for implementors of those four traits**, which must now declare the constants. It is *not* breaking for code that only names the shipped types or writes an `OpaqueCiphersuite` impl. Every implementation in this workspace is updated; the concrete values are `HmacSha512` 64 / `HmacSha256` 32, `HkdfSha512` 64 / `HkdfSha256` 32, `Ristretto255Dh` 32/32, `P256Dh` 32/33, `Ristretto255Oprf` 32/32, `P256Oprf` 32/33.

### Changed

- **Breaking (behaviour, in the fail-closed direction): every `OpaqueCiphersuite` is now length-checked at compile time.** A private `assert_lengths::<C>()` runs nine `const` assertions — `NN == 32`, `NSEED == 32`, and the other seven against the primitives above — and is called from all nine public entry points (`ServerSetup::new` / `new_with_key`, `ClientRegistration::start`, `ServerRegistration::start`, `ClientLogin::start` / `start_with_blind_and_nonce_and_seed`, `ServerLogin::start` / `start_with_nonce_and_seed` / `start_fake`). A suite whose constants disagree with its own primitives no longer builds, and the error names the offending constant.
  - *A shipped suite that was already correct is unaffected.* All four pre-built OPAQUE suites pass unchanged.
  - *These are post-monomorphization const evaluations*, so they fire on `cargo build` and `cargo test`, not on `cargo check` — which is why the MSRV job, which only checks, is not where this gate lives. A downstream crate sees the error when it builds its own call to an entry point.
- **`NN` and `NSEED` now default to 32 and should not be spelled out.** RFC 9807 §2 fixes both for every configuration — "all random nonces and seeds ... are of length Nn and Nseed bytes, respectively, where Nn = Nseed = 32" — so offering them as free required constants was itself the defect. Existing impls that state `= 32` keep compiling; the `pakery-opaque` README example no longer lists them.
- **`Argon2Params` documents that `OUTPUT_LEN` is not a free tuning knob.** It is `Nh` of the ciphersuite the KSF is paired with. The trait shape is unchanged, and the salt remains deliberately outside it — RFC 9807 §7 fixes it, so exposing it would only add a supported way to produce envelopes no conformant peer can open. Callers with a genuine need implement `Ksf` directly; the escape hatch is the trait, not a knob on the default path.

### Fixed (documentation)

Three user-facing claims were broader than what the code does. No wire format changes; each was contradicted by a test file in this repository that said the opposite.

- **`Spake2Ristretto255` and `Spake2PlusRistretto255` are not RFC suites, and the READMEs said they were validated as such.** RFC 9382 and RFC 9383 tabulate M and N for P-256, P-384, P-521, edwards25519 and edwards448 only; ristretto255 is in neither. For other groups RFC 9382 §2 says to derive the points with RFC 9380 `hash_to_curve` from a seed like `"M SPAKE2 seed OID x"`, and Appendix A generated the tabulated ones from `"<OID or name> point generation seed (M)"`. This crate's constants use `SHA-512("M SPAKE2 ristretto255")` fed to `from_uniform_bytes` — neither recipe, and not `hash_to_curve` at all (no `expand_message_xmd`, no DST). An implementation following RFC 9382 §2 arrives at different points, so these suites have **no conformant peer**. The constants are kept, because they have shipped since `0.1.0` and changing them would break every deployment without buying interoperability with anything; they are documented as non-standard instead, in the READMEs, in `spake2_constants.rs` and on both suite types.
- **`pakery-cpace`'s README claimed validation against the draft's test vectors without saying which suite.** True for ristretto255 (draft-21 Appendix B.3); not true for `CpaceP256`, which deliberately uses its own DSI and SHA-512 because CPace needs a hash output of at least twice the field size, and to which only the draft's suite-independent point-validation vectors apply. Both the README and the `CpaceP256` docstring now say so.
- **`SECURITY_TESTING.md` claimed positive vectors "for all 4 protocols on both groups".** Five of the eight combinations have them; the other three have no standard to draw them from and are covered by round-trip and property tests. The entry is now a table naming the appendix behind each.
- Smaller provenance corrections: the OPAQUE vector files cited the draft and its reference implementation, but the pinned values are byte-identical to RFC 9807 Appendix C.1.1/C.1.2 (ristretto255) and C.1.5/C.1.6 (P-256), verified against the published RFC — they now cite it, and `fuzz/examples/gen_seeds.rs` no longer calls C.1.1 "D.1.1". `pakery-cpace`'s `generator.rs` and `transcript.rs` headers said draft-18 while the vectors and `SECURITY_TESTING.md` say draft-21.

### Notes

- **The cost parameters did not change, and that is deliberate.** `DefaultArgon2Params` stays at `m = 65536` KiB (64 MiB), `t = 3`, `p = 4` — which is bit-exactly RFC 9106 §4's **SECOND RECOMMENDED** Argon2id option, the one §4 designates for memory-constrained environments. It is a named standardized configuration, not an arbitrary undershoot, and it sits about 3.4× above OWASP's 2025 baseline of 19 MiB. RFC 9807 §7 names RFC 9106's *first* recommended option instead (`m = 2^21`, 2 GiB, `t = 1`); both are standardized, and 2 GiB per stretch is not a workable default for a browser or a phone, where it would fail at runtime rather than at compile time. Applications that can afford it should spell out an `Argon2Params` impl with `M_COST = 1 << 21` and `T_COST = 1`. The docstrings now name the standard instead of claiming "production-tuned", which was unfalsifiable and is what let the question go unexamined for four releases.
- **Supersedes a sentence in the `0.4.0` notes.** That entry said "`multiple-versions` stays at `warn` until `opaque-ke` ships a stable release on the current wave". It stopped being true before this release: `deny.toml` sets `multiple-versions = "deny"`, and the graph is split across two `cargo deny` invocations rather than the check being loosened — `check advisories licenses sources` on the full graph, `--exclude-unpublished check bans` on the published one. `opaque-ke` is in fact still on the previous RustCrypto wave; that was never what gated the flip. The released `0.4.0` entry is deliberately **not** edited in place, because `ci/release-notes.py` derives the published GitHub release body from it and a published body cannot be amended.
- **This release adds one more duplicate to the test-only set, by design.** `opaque-ke` 4.0.1 implements its `Ksf` trait for `argon2` 0.5 while the workspace is on 0.6, so the differential Argon2id cases reach it through `opaque_ke::argon2` — the exact build opaque-ke dispatches on, rather than a fourth renamed alias that could drift. Like the `proptest` and `opaque-ke` copies the `0.4.0` notes describe, it reaches only `pakery-tests`, which is `publish = false`, so `--exclude-unpublished check bans` prunes it: verified `bans ok` on this tree. Argon2id output is identical across the two lines, which those cases rely on and also prove — our side stretches with 0.6, opaque-ke's with 0.5, and the results are byte-compared.
- **Two CI gates were reporting in ways that could mislead, and are fixed here.** `ci/docsrs-build.py` run on a stable toolchain failed every crate with `E0554` — each one gates its `doc_cfg` attributes behind `#![cfg_attr(docsrs, feature(doc_cfg))]` — and then reported "6 crate(s) do not document cleanly", blaming the crates for what was a wrong invocation and sending the reader after a documentation defect that did not exist. It now refuses to run on a non-nightly toolchain and says why. Separately, the `mutants` `summarize` job reported only survivors: an `exclude_re` entry added to silence one drives `missed` to zero while shrinking `caught`, which nothing reported. It now aggregates each shard's `outcomes.json` and puts total / caught / missed / timeout / unviable and the `exclude_re` count on the run summary, and warns when it has aggregated fewer than 8 shard files. Neither changes a published crate.
- **No in-place migration is possible.** RFC 9807 §8 already requires re-registration for any KSF change: "Any such change will require users to reregister to create a new RegistrationRecord." There is nothing to offer beyond saying so.

### Why four releases shipped this

Three tests covered the KSF and none could see the salt defect, each blind for a different reason. The P-256 output-length defect had no test at all.

- `differential_opaque.rs` was the only test comparing against a conformant implementation, and the only evidence the `0.3.0` and `0.4.0` changelogs cited for cross-implementation agreement — but it substituted the identity KSF on **both** sides, removing exactly the component that diverged. Correct logic over an input set that excluded the bug.
- `opaque_vectors.rs::argon2_tests::test_argon2_roundtrip` drove the real Argon2id KSF but compared this crate to itself. A wrong salt applied symmetrically round-trips perfectly.
- `ksf.rs::default_alias_matches_v0_1_config` pinned the stretch output against this crate's own `v0.1.0` and **asserted the defective constant** — a backward-compatibility pin wearing the shape of a correctness pin.
- Nothing instantiated a P-256 Argon2id ciphersuite anywhere in the workspace, so the `T = Nh` mismatch had no test to be blind to.

Together the first three read as thorough coverage. `zeroes(16)` as a KSF salt appeared nowhere in the workspace: there was no conformance test to fix, only one to write.

**What replaces them.** The salt and the output length are now pinned as observable *properties* rather than as constants:

- A known-answer test compares `Argon2idKsfWithParams::stretch` against `argon2` invoked by hand with `S = [0u8; 16]`, with the pre-`0.5.0` salt as a negative control. Editing the constant makes the two diverge — which an assertion of a constant against its own literal cannot detect.
- The differential suite gains four Argon2id cases (both suites × default and explicit identities) running the real KSF on **both** sides, plus a direct stretch comparison against opaque-ke at both `Nh` values. The P-256 cases pin the salt and `T = Nh` simultaneously against a conformant peer. Costs are minimal (`m = 8`, `t = 1`, `p = 1`); both properties are cost-independent, so a fast run proves them in full.
- A wiring test asserts, for each *shipped* Argon2id suite, that its KSF stretches to its own `NH` — the invariant the P-256 defect violated. It runs beside `test_argon2_roundtrip` in `opaque_vectors.rs`, which is precisely the file that had no P-256 Argon2id coverage, and it fails on the pre-`0.5.0` wiring while the round-trip beside it still passes.
- The `v0.1.x` vector is **deleted** rather than renamed. Its 64 pinned bytes were produced with the old salt, so no rename or `#[ignore]` leaves it meaningful — and keeping a green test that asserts the old constant is what this release is fixing. Its one durable part, the assertions on `m`/`t`/`p`/`OUTPUT_LEN`, is re-homed into a test that names the standard those values come from and costs no Argon2 run.

Each of these was verified to fail against a reintroduced defect, not merely to pass against the fix.

**The same root cause, everywhere else it lives.** `T = Nh` was one instance of a general shape: a quantity the specification derives from something else, written out by hand, with nothing tying the copy to the source. Auditing the rest of `OpaqueCiphersuite` for that shape found four more. Each constant was set to a wrong value and two oracles were run — `prop_opaque` (pakery against pakery, including serialize/deserialize round-trip and a truncation sweep) and the RFC 9807 vectors:

| Constant | Wrong value | `prop_opaque` | RFC 9807 vectors |
|---|---|---|---|
| `NN` | 32 -> 16 | **0 failed** | 3 failed |
| `NSEED` | 32 -> 16 | **0 failed** | 8 failed |
| `NOK` | 32 -> 7 | **0 failed** | **0 failed** |
| `NSK` | 32 -> 999 | **0 failed** | **0 failed** |
| `NOE` | 32 -> 33 | 2 failed | 2 failed |
| `NM` | 64 -> 32 | 5 failed | 11 failed |
| `NPK` | 32 -> 33 | 5 failed | 12 failed |
| `NX` | 64 -> 32 | 7 failed | 17 failed |
| `NH` | 64 -> 32 | 8 failed | 19 failed |

`NN` and `NSEED` changed the bytes on the wire while every pakery-to-pakery test stayed green. `NOK` and `NSK` were never read by the library at all — `grep` found zero uses outside their own declarations — so any value passed everything, including all 27 RFC 9807 vector tests.

The shipped suites were correct, but only because RFC 9807 publishes vectors for exactly the two ciphersuites this crate ships. A hand-written suite — which `pakery-opaque`'s README teaches, and which warned about `T = Nh` and nothing else — had no such net. The sibling crates already carried the idiom that was missing here: `pakery-cpace/src/generator.rs`, `pakery-spake2/src/transcript.rs` and `pakery-spake2plus/src/transcript.rs` each tie a declared constant to `Hash::OUTPUT_SIZE` with a `const` assertion. `pakery-opaque`, with nine hand-written constants, had none.

All nine are now checked at compile time, and each check was verified by reintroducing its defect and confirming the build fails naming that constant. Because the checks only fire for a ciphersuite monomorphized through an entry point, a source-level test asserts that all nine entry points call `assert_lengths::<C>()` as their first statement — it fails when a call is removed, which is the only failure mode a ciphersuite test cannot see.

**And the guard was itself unverified, which `cargo-mutants` caught.** The first mutation run over this release reported one survivor: replacing the body of `assert_lengths` with `()`. Measured directly — gut the body, and all 354 tests stayed green *and* a suite declaring `NH = 32` against a SHA-512 hash built cleanly. So the mutant was not equivalent; it disabled the guard outright, and nothing in the suite could tell. That is the same lesson one level up: a compile-time assertion has no runtime effect for a *correct* input, and its only observable consequence is which *wrong* programs fail to build — of which a test binary contains none, by construction. `assert_lengths` now returns the number of invariants it checks, and a unit test asserts that count: emptying the body is a type error, and replacing the count fails the test. The count is a tripwire on the body being intact, not a proof of the assertions themselves — those remain verified by defect reinjection.

## [0.4.0] - 2026-09-19

Breaking release: the RNG bound moves from `rand_core` 0.9 to 0.10. This is a public-dependency break of the same kind as `p256` / `curve25519-dalek` in `0.3.0` — downstream code must move to the rand_core 0.10 wave in lockstep, or its generator will not satisfy the bound. No protocol output changes: every RFC test vector passes bit-exactly across the bump, and MSRV stays at `1.85`. This settles the decision `0.3.0` deferred in its Notes.

### Changed

- **Breaking (public dependency): the RNG bound is now `rand_core` 0.10.** In 0.10, `CryptoRng` is a blanket impl over `TryCryptoRng<Error = Infallible>` rather than a trait a generator implements by hand, so a type that satisfied the 0.9 bound does not satisfy this one. The bound sits in every public entry point that consumes randomness — `CpaceInitiator::start`, `CpaceResponder::respond`, `PartyA::start`, `PartyB::start`, `Prover::start`, `Verifier::start`, `ServerSetup::new`, the OPAQUE registration and login entry points together with the `oprf_client_blind` helper beside them — and in the three core traits `CpaceGroup::random_scalar`, `DhGroup::generate_keypair` and `Oprf::client_blind`. **Callers** therefore break, not only this workspace. Move `rand`, `rand_chacha` and `getrandom` to the 0.10 wave (`rand` 0.10, `rand_chacha` 0.10, `getrandom` 0.4) together with this crate.
  - *Replacing `OsRng`.* `rand_core::OsRng` no longer exists — 0.10 dropped it along with the Cargo features that gated it. The OS-backed generator is now `getrandom::SysRng`, still fallible, so the adapter is unchanged: write `rand_core::UnwrapErr(getrandom::SysRng)` where you had `rand_core::UnwrapErr(rand_core::OsRng)`, and add `getrandom = { version = "0.4", features = ["sys_rng"] }`. getrandom re-exports the matching `rand_core`, so `getrandom::rand_core::UnwrapErr` also works if you would rather not name it twice.
  - *Hand-written generators.* `rand_core::RngCore` is deprecated in 0.10 and carries a blanket impl, so it can no longer be implemented. Implement `TryRng` with `type Error = rand_core::Infallible` and the `TryCryptoRng` marker instead; `Rng` and `CryptoRng` then follow automatically. This affects deterministic test RNGs in particular.
- **docs.rs now labels every feature-gated item with the feature that gates it.** With `all-features = true` (added in `0.3.1` so the full API renders at all), `Argon2idKsf`, the entire P-256 half of `pakery-crypto`, the ten pre-built ciphersuites, the eight `test-utils` methods and the `std`-only `Error` impls all appeared next to unconditional API with nothing to mark them optional. Each crate now opts into rustdoc's `doc_cfg`, and each manifest asks docs.rs for it. No effect on any build that is not docs.rs.

### Removed

- **Breaking: the `os_rng` feature, from all six published crates.** `rand_core` 0.10 ships no `[features]` section at all, so there is nothing left for it to forward to; a manifest that still enables it now fails with `the package does not have the feature 'os_rng'`. Little is lost: no source in this workspace ever read the feature, and reaching `OsRng` always required naming `rand_core` as a direct dependency anyway. Depend on `getrandom` (or `rand`) for a generator instead.
- `pakery-core`'s `std` feature no longer forwards to `rand_core/std`, which 0.10 also does not have. The feature itself stays and still drives `#![no_std]`, so no downstream action is needed.

### Fixed

- **`pakery-core` documented an intra-doc link that docs.rs could not resolve.** The `ct` module links to `crabgrind`, which is an optional dependency behind the private `__ctgrind` feature — and `pakery-core` deliberately pins docs.rs to `features = ["std"]` to keep that feature out of a documentation build. The link has therefore rendered as plain text since it was written, on `0.3.1`'s page as much as on any other. It is an explicit URL now, which resolves in every feature configuration. CI never caught it because the `doc` job builds `--all-features`, where crabgrind is present; a new `docs.rs configuration` job closes that gap, building each crate on nightly with the feature set its own `[package.metadata.docs.rs]` declares.

### Notes

- **No protocol output changes.** The CPace, SPAKE2, SPAKE2+ and OPAQUE vector suites, the RFC 9497 P-256 OPRF vectors and the `opaque-ke` v4 differential suite all agree byte-for-byte across the bump. That is the substantive check on the migration: the deterministic RNGs those vectors replay had to be rewritten against `TryRng`, and any change to how many bytes they hand out, or in what order, would have moved the outputs.
- **`pakery-crypto`'s hand-rolled scalar sampling is unchanged, and now for a different reason.** Through `0.3.x` the comments said `Scalar::random` could not be called because `ff` and `curve25519-dalek` want a rand_core 0.10 RNG while the bound here was 0.9. For P-256 that is no longer true, and the reason not to call it is the one that always mattered: the 32-byte rejection-sampling contract the RFC 9497 / 9807 vectors depend on. For ristretto255 the original reason still holds — dalek's `Scalar::random` is `#[cfg(feature = "rand_core")]`, and that feature is off because `0.3.0` dropped `group`.
- **Published dependency trees now hold one `rand_core`.** A `p256` build carried both 0.9 (this workspace's bound) and 0.10 (via `elliptic-curve` 0.14 / `crypto-bigint` 0.7 and `crypto-common` 0.2) through `0.3.x`; it resolves a single 0.10 now. The 0.9 and 0.6 copies that remain in the repository reach only `pakery-tests`, which is `publish = false`, through `proptest` and `opaque-ke` v4's older wave. `deny.toml` records this; `multiple-versions` stays at `warn` until `opaque-ke` ships a stable release on the current wave.
- **The documentation gate behind these claims can now fail.** Two of its checks had been passing by not looking: a fence-parsing bug left a space-separated info string (`rust ignore` rather than `rust,ignore`) unrecognised as an *opening* fence, so every later block in a README went unchecked while the script still reported success, and examples that spell their own `fn main()` were wrapped into a nested function nobody called, so they compiled but never ran. Both are fixed, a third check compares each crate's `[package.metadata.docs.rs]` against its `[features]`, and `ci/test-check-docs.py` rebuilds every one of these shapes as a fixture repository and asserts the checker reports it — so the gate's own failure path is exercised on each run rather than assumed.
- `rand_core` 0.10, `rand_chacha` 0.10 and `getrandom` 0.4 all declare `rust-version = 1.85`, so this release does **not** move the MSRV. The `-Z minimal-versions` job resolves their floors — `rand_core` 0.10.0, `getrandom` 0.4.0, `rand_chacha` 0.10.0 — and builds on them.

## [0.3.1] - 2026-09-09

Documentation-only release. **No code changes** — the compiled output of every crate is byte-identical to `0.3.0`. The manifests change only in metadata: the `categories` correction and the `[package.metadata.docs.rs]` block, both below.

`0.3.0` was published before its README fixes landed, so its crates.io and docs.rs pages document a Cargo feature that does not exist and show examples that cannot be built. A published version's README can never be amended, and both sites render the *latest* version by default, so this release exists to replace what a new reader sees.

### Fixed

- **Feature tables named a `getrandom` feature that was renamed to `os_rng` in `0.2.0`.** Copying the documented feature name gave `error: the package does not have the feature 'getrandom'`. Affected all seven READMEs.
- **Install snippets did not declare everything their own examples import.** Every crate example calls `rand_core::OsRng` while no snippet listed `rand_core` (E0433); the `pakery-opaque`, `pakery-spake2` and `pakery-spake2plus` examples import `pakery_core`, and the `pakery-crypto` example imports `pakery_cpace`, none of which were listed (E0432/E0433). Five of the six crate READMEs could not be built by following them.
- **The root README's example did not compile and had no `[dependencies]` block at all.** It used `rand_core::OsRng` directly, which since `rand_core` 0.9 implements only `TryRngCore` — `error[E0277]: the trait bound OsRng: CryptoRng is not satisfied`. The per-crate READMEs were corrected for this in `0.2.0`; the root one was missed.
- **The SPAKE2 and SPAKE2+ examples called `Ristretto255Group::scalar_from_wide_bytes` without importing the `CpaceGroup` trait that provides it** (E0599).
- **`pakery-crypto` documented four of its nine features.** The `cpace`, `spake2`, `spake2plus` and `opaque` features were undocumented (`os_rng` was there under the wrong name, per the first bullet), and with them the entire `suites` module of ten pre-built ciphersuites (`CpaceRistretto255`, `OpaqueP256Argon2`, …) — so the documentation taught spelling out a ciphersuite by hand, length constants and all, and never mentioned the ready-made ones. `SPAKE2_S_COMPRESSED` was likewise missing from the exported-type tables.
- **The OPAQUE example used `IdentityKsf` without a warning.** `pakery-opaque`'s own introduction sells resistance to offline dictionary attack, which an identity key-stretching function removes. The example now says so and points at `Argon2idKsf` and the Argon2id suites.
- **`CONTRIBUTING.md` gave the wrong publication order** (`pakery-crypto` second rather than last), which would fail a manual release: `pakery-crypto`'s optional features depend on the four protocol crates, and crates.io requires them to exist on the registry first.
- Smaller corrections: `pakery-tests/README.md` claimed MSRV-job coverage that `ci.yml` deliberately excludes; `SECURITY_TESTING.md` carried a stale test count and described `cargo audit` / `cargo deny` as weekly when they also run per push and PR; the architecture diagram omitted `Ksf` and Argon2id.

### Changed

- **docs.rs now renders each crate's full API.** No crate declared `[package.metadata.docs.rs]`, so docs.rs built with default features only, hiding most of the public surface. For `pakery-crypto` (`default = ["std", "ristretto255"]`) that meant the rendered documentation contained **no P-256 types, no `Argon2idKsf`, and no `suites` module at all** — while the README documents all of them. Every published crate now pins its docs.rs feature set: `all-features = true`, except `pakery-core`, which is pinned to `["std", "os_rng"]` so the private `__ctgrind` feature (crabgrind, Valgrind client requests) stays out of a documentation build.
- **crates.io category `no-std::no-alloc` → `no-std`** for all six published crates. Every crate unconditionally declares `extern crate alloc` and uses `Vec<u8>` on protocol paths, so `no-alloc` was never accurate.

### Notes

- These regressions shipped because READMEs were free-form Markdown that nothing compiled and nothing compared against the manifests. `ci/check-docs.py` now gates the repository: feature tables are checked against `[features]` in both directions, version requirements and the stated MSRV against `[workspace.package]`, and every documented example is **built and run** as a standalone crate whose `Cargo.toml` is the snippet the README itself shows. Since `publish.yml` runs the full CI suite, this release is also the first to have its documentation verified before publication.
- Test-only: `SPAKE2_S_COMPRESSED` is now pinned by a derivation test (it is public API that no ciphersuite consumes, so nothing constrained it), and the Argon2 backward-compatibility vector's provenance was re-captured by running the published `pakery-crypto` `0.1.0` rather than inferred from the `0.2.0` alias.

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
