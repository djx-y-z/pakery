#!/usr/bin/env python3
"""Build every published crate the way docs.rs will build it.

The `doc` job in ci.yml runs `cargo doc --workspace --all-features`. docs.rs
does not: it builds each crate on its own, with the feature set that crate's
`[package.metadata.docs.rs]` declares, and with the `rustdoc-args` it asks
for. Nothing checked that configuration, and one release shipped through the
gap -- `pakery-core` pins docs.rs to `features = ["std"]` to keep crabgrind
out of a documentation build, so its `ct` module's intra-doc link to
`crabgrind` could not resolve there. Under `--all-features` crabgrind is
present and the link resolves, so CI stayed green while the published 0.3.1
page rendered the link as plain text. It was found by hand.

0.4.0 raises the stakes: `#![cfg_attr(docsrs, feature(doc_cfg))]` is a
nightly-only code path that *only* docs.rs compiles. Published documentation
can never be amended -- the only fix is another release.

This script reads each publishable crate's declared configuration and builds
exactly that, under `-Dwarnings`. It hardcodes nothing: a hardcoded feature
list is the same drift that caused the original defect.

Usage:  python3 ci/docsrs-build.py [--toolchain nightly] [-n]
Exit code 0 = every crate documents cleanly, 1 = at least one does not.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load(path: Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def publishable_crates() -> list[str]:
    """Workspace members that actually reach crates.io, in manifest order."""
    members = load(REPO / "Cargo.toml")["workspace"]["members"]
    out = []
    for m in members:
        man = REPO / m / "Cargo.toml"
        if not man.exists():
            sys.exit(f"docsrs-build: workspace member {m} has no Cargo.toml")
        if load(man).get("package", {}).get("publish") is False:
            continue
        out.append(m)
    return out


def plan_for(crate: str) -> tuple[list[str], list[str]]:
    """(cargo feature arguments, rustdoc-args) exactly as docs.rs would use."""
    pkg = load(REPO / crate / "Cargo.toml").get("package", {})
    meta = pkg.get("metadata", {}).get("docs", {}).get("rs", {})
    args: list[str] = []
    if meta.get("all-features"):
        args.append("--all-features")
    else:
        if meta.get("no-default-features"):
            args.append("--no-default-features")
        features = meta.get("features", [])
        if features:
            args += ["--features", ",".join(features)]
    return args, list(meta.get("rustdoc-args", []))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--toolchain",
        default="",
        help="cargo toolchain to insert as +NAME (docs.rs builds on nightly)",
    )
    ap.add_argument(
        "-n", "--dry-run", action="store_true", help="print the plan, build nothing"
    )
    ap.add_argument("--target-dir", default=str(REPO / "target" / "docsrs"))
    args = ap.parse_args()

    crates = publishable_crates()
    # The realistic way this job fails open is not rustdoc going quiet, it is
    # this list coming back empty or short -- a moved manifest key, a widened
    # `publish = false` filter -- and the loop below then reporting success
    # over nothing at all. Six is the count the release process publishes.
    if len(crates) != 6:
        sys.exit(
            f"docsrs-build: expected 6 publishable crates, resolved "
            f"{len(crates)}: {crates}. Refusing to report success over a "
            f"list this script did not build by mistake -- if the workspace "
            f"really changed, update this count deliberately."
        )

    failures: list[str] = []
    for crate in crates:
        feature_args, rustdoc_args = plan_for(crate)
        cmd = ["cargo"]
        if args.toolchain:
            cmd.append(f"+{args.toolchain}")
        cmd += ["doc", "-p", crate, "--no-deps", "--target-dir", args.target_dir]
        cmd += feature_args
        env = dict(os.environ)
        env["RUSTDOCFLAGS"] = " ".join(rustdoc_args + ["-Dwarnings"])

        print(f"\n=== {crate} ===")
        print(f"  RUSTDOCFLAGS={env['RUSTDOCFLAGS']}")
        print(f"  {' '.join(cmd)}")
        if args.dry_run:
            continue
        if subprocess.run(cmd, cwd=REPO, env=env).returncode != 0:
            failures.append(crate)

    if args.dry_run:
        print(f"\nplan only, {len(crates)} crate(s), nothing built")
        return 0
    if failures:
        print(
            f"\n{len(failures)} crate(s) do not document cleanly in the "
            f"configuration docs.rs will use: {', '.join(failures)}"
        )
        print(
            "docs.rs builds each crate with its own "
            "[package.metadata.docs.rs], not --all-features, and a published "
            "page cannot be amended afterwards."
        )
        return 1
    print(f"\ndocs.rs build: {len(crates)} crate(s) document cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
