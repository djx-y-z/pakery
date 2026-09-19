#!/usr/bin/env python3
"""Verify that the Markdown documentation matches the code and manifests.

Three independent checks, each targeting a doc regression this workspace has
actually shipped:

  features  Cargo feature tables in READMEs vs `[features]` in the manifests,
            in BOTH directions (documented-but-absent / declared-but-
            undocumented), including the `(default)` annotation.
            Regression it would have caught: the `getrandom` -> `os_rng`
            rename in 0.2.0, undocumented in all seven READMEs until 0.3.0.

  versions  Version requirements in ```toml install snippets, and the stated
            MSRV, vs `[workspace.package]`.
            Regression it would have caught: install snippets pinned to
            `pakery-* = "0.1"` while the workspace shipped 0.2.x / 0.3.0.

  docsrs    `[package.metadata.docs.rs]` vs `[features]`: every public
            feature of a published crate must be reachable from the feature
            set docs.rs builds with.
            Regression it would have caught: pakery-crypto 0.3.0 rendered 6
            of its 15 modules on docs.rs — no `suites`, no P-256, no
            `Argon2idKsf` — because it declared no docs.rs metadata.

  examples  Every ```rust block is compiled AND run as a standalone crate
            built from the ```toml block that precedes it, with `pakery-*`
            dependencies redirected to this checkout via `path` (the declared
            `version` is kept, so cargo also rejects a stale requirement).
            This is the "do exactly what the README says in a clean project"
            test: it fails if the snippet omits a crate the example imports,
            omits a feature it needs, or if the code no longer compiles.
            Regression it would have caught: `rand_core::OsRng` used directly
            after rand_core 0.9 made it `TryRngCore`-only.

Each check is exercised by a break-test in ci/test-check-docs.py, which
builds a fixture repository per known failure shape and asserts this script
reports it. Run that after changing anything here: two of these checks have
failed *open* in the past, printing "all claims verified" because a parse bug
had stopped them from looking.

Usage:  python3 ci/check-docs.py [--only features,versions,docsrs,examples] [-v]
Exit code 0 = all checks pass, 1 = at least one finding.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Crates whose README carries a per-crate feature table.
CRATES = [
    "pakery-core",
    "pakery-cpace",
    "pakery-crypto",
    "pakery-opaque",
    "pakery-spake2",
    "pakery-spake2plus",
    "pakery-tests",
]

# Protocol crates: the root README's feature table claims to list features
# common to all of these, so it is checked as a subset rather than an exact
# match.
PROTOCOL_CRATES = ["pakery-cpace", "pakery-opaque", "pakery-spake2", "pakery-spake2plus"]

# Features exempt from the "declared but not documented" direction only.
# `__`-prefixed features are private, semver-exempt and CI-internal; a README
# may document one (pakery-tests does) but is not required to.
PRIVATE_FEATURE_RE = re.compile(r"^__")

findings: list[str] = []


def fail(where: str, msg: str) -> None:
    findings.append(f"{where}: {msg}")


# --------------------------------------------------------------------------
# Markdown helpers
# --------------------------------------------------------------------------

# CommonMark: a fence is three or more backticks, optionally indented by up
# to three spaces, and its info string runs to end of line. Matching a
# narrower character class used to leave ```rust ignore unrecognised as an
# *opening* fence — spaces separate info-string words as legitimately as
# commas, and rustdoc treats the two forms alike — while its closing fence
# still matched. Parity inverted and every block after it became invisible,
# so the checker went quiet and reported success. This parse must stay
# permissive: anything it fails to recognise, it fails to check.
FENCE_RE = re.compile(r"^ {0,3}(`{3,})([^`]*)$")


def fenced_blocks(text: str) -> list[tuple[str, list[str], int, str]]:
    """Return [(lang, flags, start_line_1based, body)] for each fenced block.

    `lang` is the first word of the info string and `flags` the rest, split
    on commas and whitespace alike, so ```rust,ignore and ```rust ignore are
    the same block to every caller.
    """
    out: list[tuple[str, list[str], int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        ticks, info = m.group(1), m.group(2)
        tokens = [t for t in re.split(r"[,\s]+", info.strip()) if t]
        start = i + 1
        body: list[str] = []
        i += 1
        while i < len(lines):
            c = FENCE_RE.match(lines[i])
            # A closing fence is at least as long and carries no info string.
            if c and len(c.group(1)) >= len(ticks) and not c.group(2).strip():
                break
            body.append(lines[i])
            i += 1
        lang = tokens[0] if tokens else ""
        out.append((lang, tokens[1:], start, "\n".join(body)))
        i += 1
    return out


def manifest(crate: str) -> dict:
    with (REPO / crate / "Cargo.toml").open("rb") as fh:
        return tomllib.load(fh)


def manifest_features(crate: str) -> dict[str, list[str]]:
    return manifest(crate).get("features", {})


def workspace_meta() -> dict:
    with (REPO / "Cargo.toml").open("rb") as fh:
        return tomllib.load(fh)["workspace"]["package"]


# --------------------------------------------------------------------------
# Check 1: feature tables
# --------------------------------------------------------------------------

# A feature is documented either as a table row
#     | `name` (default) | description |
# or as a bullet (pakery-tests/README.md uses this form)
#     - `name` (private) — description
# Feature names may contain `-` (e.g. `test-utils`), so the character class
# must not be restricted to identifier characters.
FEATURE_ROW_RE = re.compile(r"^\|\s*`([A-Za-z0-9_-]+)`\s*(\(default\))?\s*\|")
FEATURE_BULLET_RE = re.compile(r"^\s*[-*]\s*`([A-Za-z0-9_-]+)`\s*(\(default\))?")

# Only a heading that is *about* features opens the features section. Matching
# any heading merely containing "feature" would also swallow pakery-crypto's
# "### Ristretto255 (`ristretto255` feature)" type tables.
FEATURES_HEADING_RE = re.compile(r"^#+\s*(cargo )?features?( flags)?\s*$", re.I)


def documented_features(readme: Path) -> dict[str, tuple[bool, int]]:
    """Map feature name -> (marked_default, line_number).

    Only rows/bullets sitting under a `## Features` (or `## Feature flags`)
    heading count: a backticked name elsewhere in the README — a type name in
    an "Available types" table, say — must not be able to satisfy the
    "declared but not documented" direction by accident.
    """
    out: dict[str, tuple[bool, int]] = {}
    in_features = False
    for n, line in enumerate(readme.read_text().splitlines(), 1):
        if line.startswith("#"):
            in_features = bool(FEATURES_HEADING_RE.match(line))
            continue
        if not in_features:
            continue
        m = FEATURE_ROW_RE.match(line) or FEATURE_BULLET_RE.match(line)
        if m:
            out[m.group(1)] = (m.group(2) is not None, n)
    return out


def check_features() -> None:
    for crate in CRATES:
        readme = REPO / crate / "README.md"
        if not readme.exists():
            fail(f"{crate}/README.md", "missing")
            continue
        declared = manifest_features(crate)
        defaults = set(declared.get("default", []))
        documented = documented_features(readme)

        for name, (is_default, line) in documented.items():
            if name not in declared:
                fail(
                    f"{crate}/README.md:{line}",
                    f"documents Cargo feature `{name}`, which "
                    f"{crate}/Cargo.toml does not declare "
                    f"(declared: {sorted(declared)})",
                )
                continue
            if is_default and name not in defaults and name != "default":
                fail(
                    f"{crate}/README.md:{line}",
                    f"marks `{name}` as (default), but it is not in "
                    f"`default = {sorted(defaults)}`",
                )
            if not is_default and name in defaults:
                fail(
                    f"{crate}/README.md:{line}",
                    f"does not mark `{name}` as (default), but "
                    f"`default = {sorted(defaults)}` includes it",
                )

        for name in declared:
            if name == "default" or PRIVATE_FEATURE_RE.match(name):
                continue
            if name not in documented:
                fail(
                    f"{crate}/README.md",
                    f"does not document Cargo feature `{name}`, which "
                    f"{crate}/Cargo.toml declares",
                )

    # Root README: claims a table of features common to all protocol crates.
    root = REPO / "README.md"
    common = set.intersection(
        *(set(manifest_features(c)) - {"default"} for c in PROTOCOL_CRATES)
    )
    for name, (_is_default, line) in documented_features(root).items():
        if name not in common:
            fail(
                f"README.md:{line}",
                f"lists `{name}` as supported by all protocol crates, but it "
                f"is not declared by all of {PROTOCOL_CRATES} "
                f"(common: {sorted(common)})",
            )


# --------------------------------------------------------------------------
# Check 2: version requirements and MSRV
# --------------------------------------------------------------------------

DEP_LINE_RE = re.compile(r'^\s*(pakery-[a-z0-9]+)\s*=\s*(.+?)\s*$')
VERSION_IN_RE = re.compile(r'version\s*=\s*"([^"]+)"')
BARE_VERSION_RE = re.compile(r'^"([^"]+)"$')


def semver_req_matches(req: str, version: str) -> bool:
    """Caret semantics for 0.x: `0.3` matches 0.3.z only."""
    req = req.lstrip("^").strip()
    rp = req.split(".")
    vp = version.split(".")
    if rp[0] != vp[0]:
        return False
    if rp[0] == "0":
        # 0.x: minor must match exactly.
        return len(rp) < 2 or rp[1] == vp[1]
    return True


def check_versions() -> None:
    meta = workspace_meta()
    version, msrv = meta["version"], meta["rust-version"]

    for md in sorted(REPO.rglob("*.md")):
        # CHANGELOG.md is a historical record: its older entries legitimately
        # quote the version requirements and MSRV that were current then, and
        # rewriting them to match today's workspace would be the opposite of
        # accurate. Every other Markdown file describes the present.
        if "target" in md.parts or md.name == "CHANGELOG.md":
            continue
        rel = md.relative_to(REPO)
        text = md.read_text()
        for lang, _flags, start, body in fenced_blocks(text):
            if lang != "toml":
                continue
            for off, line in enumerate(body.splitlines(), 1):
                m = DEP_LINE_RE.match(line)
                if not m:
                    continue
                name, rhs = m.group(1), m.group(2)
                vm = BARE_VERSION_RE.match(rhs) or VERSION_IN_RE.search(rhs)
                if not vm:
                    continue
                req = vm.group(1)
                if not semver_req_matches(req, version):
                    fail(
                        f"{rel}:{start + off}",
                        f"install snippet requires `{name} = \"{req}\"`, which "
                        f"does not accept the current workspace version "
                        f"{version} (for 0.x, cargo treats 0.a and 0.b as "
                        f"incompatible)",
                    )

        # MSRV prose.
        for n, line in enumerate(text.splitlines(), 1):
            for m in re.finditer(
                r"minimum supported Rust version is \*\*([0-9.]+)\*\*", line
            ):
                if m.group(1) != msrv:
                    fail(
                        f"{rel}:{n}",
                        f"states MSRV {m.group(1)}, manifests declare "
                        f"rust-version = {msrv}",
                    )
            for m in re.finditer(r"Install Rust ([0-9.]+)\+", line):
                if m.group(1) != msrv:
                    fail(
                        f"{rel}:{n}",
                        f"tells contributors to install Rust {m.group(1)}+, "
                        f"manifests declare rust-version = {msrv}",
                    )


# --------------------------------------------------------------------------
# Check 3: compile and run every documented example
# --------------------------------------------------------------------------

MAIN_FN_RE = re.compile(r"^\s*(pub\s+)?(async\s+)?fn\s+main\s*\(", re.M)
PATH_REWRITE_TABLE_RE = re.compile(r"^\s*(pakery-[a-z0-9]+)\s*=\s*\{(.*)\}\s*$")
PATH_REWRITE_BARE_RE = re.compile(r'^\s*(pakery-[a-z0-9]+)\s*=\s*("[^"]+")\s*$')


def redirect_to_checkout(dep_block: str) -> str:
    """Add `path = ...` to every pakery-* dependency, keeping its version req.

    Keeping the declared version means cargo still refuses a stale
    requirement (`^0.1` against a local 0.3.0), so this check subsumes the
    stale-snippet regression as well as the compile regression.
    """
    out = []
    for line in dep_block.splitlines():
        m = PATH_REWRITE_BARE_RE.match(line)
        if m:
            name, ver = m.group(1), m.group(2)
            out.append(f'{name} = {{ version = {ver}, path = "{REPO / name}" }}')
            continue
        m = PATH_REWRITE_TABLE_RE.match(line)
        if m:
            name, inner = m.group(1), m.group(2).strip().rstrip(",")
            out.append(f'{name} = {{ {inner}, path = "{REPO / name}" }}')
            continue
        out.append(line)
    return "\n".join(out)


def example_units(md: Path) -> list[tuple[int, str, str]]:
    """Pair each ```rust block with the nearest preceding ```toml block."""
    units = []
    current_toml = None
    for lang, flags, start, body in fenced_blocks(md.read_text()):
        if lang == "toml" and "[dependencies]" in body:
            current_toml = body
        elif lang == "rust":
            if "ignore" in flags or "no_check" in flags:
                continue
            units.append((start, current_toml, body))
    return units


def check_examples(target_dir: Path, verbose: bool) -> None:
    scratch = target_dir / "doc-examples"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)

    edition = workspace_meta().get("edition", "2021")
    env = dict(os.environ, CARGO_TARGET_DIR=str(target_dir / "shared"))

    for md in sorted(REPO.rglob("README.md")):
        if "target" in md.parts:
            continue
        rel = md.relative_to(REPO)
        for start, dep_block, code in example_units(md):
            name = re.sub(r"[^a-z0-9]+", "_", str(rel).lower()) + f"_{start}"
            if dep_block is None:
                fail(
                    f"{rel}:{start}",
                    "```rust example has no preceding ```toml block declaring "
                    "its dependencies, so what a reader must put in Cargo.toml "
                    "to build it is undocumented and unverifiable",
                )
                continue
            proj = scratch / name
            (proj / "src").mkdir(parents=True)
            (proj / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion = "0.0.0"\n'
                f'edition = "{edition}"\n\n'
                f"{redirect_to_checkout(dep_block)}\n"
                f"\n[workspace]\n"
            )
            # Wrapping a snippet that already spells its own `fn main()`
            # buries it in a nested function nobody calls: it still compiles,
            # so the build passes, but nothing in it runs and a false
            # assertion inside it cannot fail. That silently downgrades this
            # check from "built and run" to "built". rustdoc draws the same
            # distinction, so follow it.
            body = code if MAIN_FN_RE.search(code) else f"fn main() {{\n{code}\n}}"
            (proj / "src" / "main.rs").write_text(
                "#![allow(unused_imports, unused_variables, unused_mut)]\n"
                + body
                + "\n"
            )
            if verbose:
                print(f"  building {rel}:{start} -> {name}", file=sys.stderr)
            r = subprocess.run(
                ["cargo", "run", "--quiet"],
                cwd=proj,
                env=env,
                capture_output=True,
                text=True,
            )
            if r.returncode != 0:
                detail = (r.stderr or r.stdout).strip().splitlines()
                head = "\n      ".join(detail[:14])
                fail(
                    f"{rel}:{start}",
                    "the documented example does not build/run from the "
                    "dependencies the README itself declares:\n      " + head,
                )


# --------------------------------------------------------------------------
# Check 4: docs.rs renders every public feature
# --------------------------------------------------------------------------


def docs_rs_feature_closure(features: dict, meta: dict) -> set[str]:
    """The feature set docs.rs actually builds, expanded transitively.

    Mirrors docs.rs' own rules: default features unless `no-default-features`
    turns them off, plus whatever `features` lists, plus everything those
    transitively enable.
    """
    seed = set(meta.get("features", []))
    if not meta.get("no-default-features", False) and "default" in features:
        seed.add("default")
    seen: set[str] = set()
    queue = list(seed)
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        # `dep:foo` activates an optional dependency and `foo/bar` a feature
        # of one; neither names a feature of this crate.
        queue += [e for e in features.get(name, []) if e in features]
    return seen


def check_docs_rs_features() -> None:
    """Every public feature must be reachable from what docs.rs builds.

    docs.rs builds default features only unless `[package.metadata.docs.rs]`
    says otherwise, so an item behind an optional feature is simply absent
    from the rendered documentation — silently, with the build still green.
    Regression it would have caught: pakery-crypto 0.3.0 carried no docs.rs
    metadata and published 6 of its 15 modules, without `suites`, P-256 or
    `Argon2idKsf`.

    `__`-prefixed features are exempt: excluding them is deliberate.
    pakery-core keeps `__ctgrind` off docs.rs because it pulls crabgrind and
    emits Valgrind client requests, which is why this check asks for
    coverage rather than for `all-features = true`.
    """
    for crate in CRATES:
        man = manifest(crate)
        pkg = man.get("package", {})
        if pkg.get("publish") is False:
            continue
        features = man.get("features", {})
        meta = pkg.get("metadata", {}).get("docs", {}).get("rs", {})
        if meta.get("all-features"):
            continue
        public = {
            f for f in features
            if f != "default" and not PRIVATE_FEATURE_RE.match(f)
        }
        missing = sorted(public - docs_rs_feature_closure(features, meta))
        if not missing:
            continue
        how = (
            "declares no [package.metadata.docs.rs], so docs.rs builds only "
            "its default features"
            if not meta
            else "[package.metadata.docs.rs] lists a feature set that does "
            "not reach every public feature"
        )
        fail(
            f"{crate}/Cargo.toml",
            f"{how}; docs.rs would render nothing gated on {missing}. Add "
            f"them to `features`, or set `all-features = true`",
        )


# --------------------------------------------------------------------------
# Check 3b: the docs.rs cfg handshake
# --------------------------------------------------------------------------

# `#![cfg_attr(docsrs, feature(doc_cfg))]` is inert unless the build passes
# `--cfg docsrs`, and docs.rs passes it only when the manifest asks for it.
# The two halves sit in different files and nothing ties them together: delete
# the `rustdoc-args` line and every feature badge silently vanishes from the
# published page -- no warning, no failing build, and pakery-crypto alone
# renders 101 of them. Published documentation can never be amended, so both
# directions are checked.
DOCSRS_CFG_ATTR_RE = re.compile(r"^\s*#!\[cfg_attr\(\s*docsrs\s*,", re.M)


def passes_cfg_docsrs(rustdoc_args: list[str]) -> bool:
    """Whether these rustdoc-args amount to `--cfg docsrs`.

    Both spellings rustdoc accepts: `["--cfg", "docsrs"]` as two elements and
    `["--cfg=docsrs"]` as one.
    """
    for i, arg in enumerate(rustdoc_args):
        if arg == "--cfg=docsrs":
            return True
        if arg == "--cfg" and rustdoc_args[i + 1 : i + 2] == ["docsrs"]:
            return True
    return False


def check_docs_rs_cfg() -> None:
    """`cfg_attr(docsrs, ...)` in the source and `--cfg docsrs` in the manifest
    must either both be present or both be absent."""
    for crate in CRATES:
        man = manifest(crate)
        pkg = man.get("package", {})
        if pkg.get("publish") is False:
            continue
        lib = REPO / crate / "src" / "lib.rs"
        if not lib.exists():
            continue
        opted_in = bool(DOCSRS_CFG_ATTR_RE.search(lib.read_text()))
        meta = pkg.get("metadata", {}).get("docs", {}).get("rs", {})
        asked_for = passes_cfg_docsrs(meta.get("rustdoc-args", []))
        if opted_in and not asked_for:
            fail(
                f"{crate}/Cargo.toml",
                "src/lib.rs has `#![cfg_attr(docsrs, ...)]` but "
                "[package.metadata.docs.rs] does not pass `--cfg docsrs`, so "
                "docs.rs renders the crate with every feature badge missing "
                'and no error. Add `rustdoc-args = ["--cfg", "docsrs"]`',
            )
        elif asked_for and not opted_in:
            fail(
                f"{crate}/src/lib.rs",
                "[package.metadata.docs.rs] passes `--cfg docsrs` but no "
                "`#![cfg_attr(docsrs, ...)]` reads it, so the flag does "
                "nothing. Add the attribute, or drop `rustdoc-args`",
            )


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="features,versions,docsrs,examples")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--target-dir", default=str(REPO / "target" / "doc-check"))
    args = ap.parse_args()
    selected = {s.strip() for s in args.only.split(",") if s.strip()}

    if "features" in selected:
        check_features()
    if "versions" in selected:
        check_versions()
    if "docsrs" in selected:
        check_docs_rs_features()
        check_docs_rs_cfg()
    if "examples" in selected:
        check_examples(Path(args.target_dir), args.verbose)

    if findings:
        print(f"\n{len(findings)} documentation finding(s):\n")
        for f in findings:
            print(f"  - {f}")
        print(
            "\nThese are claims the documentation makes that the code, the "
            "manifests or the compiler contradict."
        )
        return 1
    print("docs check: all claims verified against code and manifests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
