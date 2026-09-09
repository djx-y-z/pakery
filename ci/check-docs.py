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

  examples  Every ```rust block is compiled AND run as a standalone crate
            built from the ```toml block that precedes it, with `pakery-*`
            dependencies redirected to this checkout via `path` (the declared
            `version` is kept, so cargo also rejects a stale requirement).
            This is the "do exactly what the README says in a clean project"
            test: it fails if the snippet omits a crate the example imports,
            omits a feature it needs, or if the code no longer compiles.
            Regression it would have caught: `rand_core::OsRng` used directly
            after rand_core 0.9 made it `TryRngCore`-only.

Usage:  python3 ci/check-docs.py [--only features,versions,examples] [-v]
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

FENCE_RE = re.compile(r"^```([A-Za-z0-9_,+-]*)\s*$")


def fenced_blocks(text: str) -> list[tuple[str, int, str]]:
    """Return [(info_string, start_line_1based, body)] for each fenced block."""
    out: list[tuple[str, int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        info = m.group(1)
        start = i + 1
        body: list[str] = []
        i += 1
        while i < len(lines) and not FENCE_RE.match(lines[i]):
            body.append(lines[i])
            i += 1
        out.append((info, start, "\n".join(body)))
        i += 1
    return out


def manifest_features(crate: str) -> dict[str, list[str]]:
    with (REPO / crate / "Cargo.toml").open("rb") as fh:
        return tomllib.load(fh).get("features", {})


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
        for info, start, body in fenced_blocks(text):
            if info.split(",")[0] != "toml":
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
    for info, start, body in fenced_blocks(md.read_text()):
        kind = info.split(",")[0]
        flags = info.split(",")[1:]
        if kind == "toml" and "[dependencies]" in body:
            current_toml = body
        elif kind == "rust":
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
            (proj / "src" / "main.rs").write_text(
                "#![allow(unused_imports, unused_variables, unused_mut)]\n"
                "fn main() {\n" + code + "\n}\n"
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="features,versions,examples")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--target-dir", default=str(REPO / "target" / "doc-check"))
    args = ap.parse_args()
    selected = {s.strip() for s in args.only.split(",") if s.strip()}

    if "features" in selected:
        check_features()
    if "versions" in selected:
        check_versions()
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
