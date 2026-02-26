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

4. Update `CHANGELOG.md`:
   - Add a new `## [<version>] - <today's date YYYY-MM-DD>` section after the header
   - Include placeholder subsections `### Added`, `### Changed`, `### Fixed` (only the ones relevant — ask the user what changed)

5. Run `cargo check --workspace --all-features` to verify everything compiles.

6. Report the summary:
   - Previous version → new version
   - List all files modified
   - Remind the user to fill in the CHANGELOG, commit, and tag with `v<version>`
