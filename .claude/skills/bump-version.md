Bump the workspace version for all pakery crates.

The user provides the new version as: $ARGUMENTS

## Instructions

1. Read the root `Cargo.toml` to find the current version in `[workspace.package]`.

2. Validate the new version:
   - It must be a valid semver string (e.g., `0.2.0`, `1.0.0-rc.1`)
   - It must be greater than the current version
   - If validation fails, report the error and stop

3. Update the root `Cargo.toml`:
   - `[workspace.package] version` — set to the new version
   - `[workspace.dependencies] pakery-core` — update `version` field to the new version
   - `[workspace.dependencies] pakery-cpace` — update `version` field to the new version
   - `[workspace.dependencies] pakery-opaque` — update `version` field to the new version
   - `[workspace.dependencies] pakery-spake2` — update `version` field to the new version
   - `[workspace.dependencies] pakery-spake2plus` — update `version` field to the new version
   - `[workspace.dependencies] pakery-crypto` — update `version` field to the new version

4. Update the `[dependencies]` snippets in the READMEs. Each crate README
   and the root README show `pakery-* = "<major>.<minor>"`; cargo treats
   `0.a` and `0.b` as incompatible, so a stale snippet installs an old
   release. A patch bump needs no edit (`^0.3` accepts `0.3.1`), but a
   minor or major bump does — and `ci/check-docs.py`'s example check runs
   inside `publish.yml`, so forgetting this fails the release, not just CI.
   Verify with `python3 ci/check-docs.py --only versions`.

5. Update `CHANGELOG.md`:
   - Add a new `## [<version>] - <today's date YYYY-MM-DD>` section after the header
   - Include placeholder subsections `### Added`, `### Changed`, `### Fixed` (only the ones relevant — ask the user what changed)

6. Run `cargo check --workspace --all-features` and `python3 ci/check-docs.py`
   to verify everything compiles and the docs still match.

7. Report the summary:
   - Previous version → new version
   - List all files modified
   - Remind the user to fill in the CHANGELOG, commit, and tag with `v<version>`
