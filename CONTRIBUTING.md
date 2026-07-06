# Contributing to pakery

Thank you for considering contributing to pakery!

## Getting started

1. Fork the repository and clone it locally
2. Install Rust 1.79+ via [rustup](https://rustup.rs/)
3. Enable the pre-commit hook:

```bash
git config core.hooksPath .githooks
```

4. Run the test suite to make sure everything works:

```bash
cargo test --workspace --all-features
```

## Development workflow

### Running checks locally

Before submitting a PR, run the full CI suite locally:

```bash
# Build
cargo check --workspace --all-features

# Tests
cargo test --workspace --all-features

# Linting
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Formatting
cargo fmt --all -- --check

# Documentation
RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --all-features --no-deps
```

### Mutation testing (advisory)

CI runs [cargo-mutants](https://mutants.rs) weekly over the whole workspace
(sharded) and incrementally on PR diffs (advisory, never a merge gate); see
`.github/workflows/mutants.yml`. Configuration — the feature set, the
test-package list, and every exclusion with its justification — lives in
`.cargo/mutants.toml`.

```bash
cargo install cargo-mutants

# Mutants in code you changed (fast):
git diff main | cargo mutants --in-diff /dev/stdin

# Full run (hours; -j 4 on an 8-core machine):
cargo mutants -j 4
```

Results land in `mutants.out/` (`missed.txt` is the list that matters). Every
surviving mutant is either a missing test — add one — or provably equivalent
code — document it in `.cargo/mutants.toml` `exclude_re` with a justification.

### Project structure

| Crate | Description |
|-------|-------------|
| `pakery-core` | Shared cryptographic traits (`Hash`, `Kdf`, `Mac`, `CpaceGroup`, `DhGroup`, `Oprf`, `Ksf`) |
| `pakery-cpace` | CPace balanced PAKE (draft-irtf-cfrg-cpace) |
| `pakery-opaque` | OPAQUE augmented PAKE (RFC 9807) |
| `pakery-spake2` | SPAKE2 balanced PAKE (RFC 9382) |
| `pakery-spake2plus` | SPAKE2+ augmented PAKE (RFC 9383) |
| `pakery-crypto` | Concrete crypto implementations (Ristretto255, P-256) |
| `pakery-tests` | Integration tests with RFC test vectors |

### Key conventions

- Protocol crates depend only on `pakery-core` traits, never on concrete crypto
- All crates use `#![forbid(unsafe_code)]`
- All public API changes must maintain `no_std` compatibility
- Test against RFC test vectors where available
- Commit messages: `feat(crate): description`, `fix(crate): description`

## Submitting changes

1. Create a branch from `main`
2. Make your changes with clear, focused commits
3. Ensure all CI checks pass locally (see above)
4. Open a pull request against `main`

## Releasing a new version

This workspace uses **lockstep versioning** — all crates share a single version defined in the root `Cargo.toml`. When releasing, every crate is published with the same version number.

### How to bump the version

All version numbers are centralized in `Cargo.toml` at the workspace root:

1. Update `[workspace.package] version` (the version of all crates)
2. Update `[workspace.dependencies] pakery-core` version (the dependency version used by other crates)
3. Update `[workspace.dependencies] pakery-*` versions for any other inter-crate dependencies
4. Update `CHANGELOG.md` with the new version and changes
5. Commit, tag with `v<version>`, and push — the publish workflow handles the rest

### Publication order (handled by CI)

1. `pakery-core` (no internal dependencies)
2. `pakery-crypto` (depends on `pakery-core`)
3. `pakery-cpace`, `pakery-opaque`, `pakery-spake2`, `pakery-spake2plus` (depend on `pakery-core`)

## Reporting security issues

If you discover a security vulnerability, please **do not** open a public issue. Instead, report it privately via GitHub's [security advisory](https://github.com/djx-y-z/pakery/security/advisories/new) feature.

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project: MIT OR Apache-2.0.
