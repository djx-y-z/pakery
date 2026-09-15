#!/usr/bin/env python3
"""Break-tests for ci/check-docs.py: prove each check can actually fail.

A documentation gate nobody has seen fail is decoration. Every case below is
a regression that some version of the checker let through silently, rebuilt
as a fixture repository: the case asserts the checker reports a finding.

Two of the three fixtures target *fail-open* parse bugs, where the checker
printed "all claims verified" precisely because it had stopped looking. That
is why a case is only meaningful next to the version that missed it, so the
A/B is reproducible:

    python3 ci/test-check-docs.py --script <older copy of check-docs.py>

must report the cases that version predates as NOT DETECTED. A case that is
red against both versions proves nothing about the fix.

Each case therefore says what it proves. A "fix" case reproduces a defect
that was actually shipped, and an older checker has to miss it. A "guard"
case pins behaviour that has always been correct, so it is red against every
version -- it earns its place by failing if someone breaks that behaviour
later, not by demonstrating a past bug. Reading a guard as evidence of a fix
would be exactly the mistake this file exists to prevent.

Fixtures are synthetic repositories in a temp dir; the checker's module-level
REPO (and CRATES, where the crate list is not what is under test) is pointed
at them, so nothing here depends on the real workspace's current contents.
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

# Importing the checker must not leave a ci/__pycache__ behind and dirty the
# tree of whoever runs this.
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
DEFAULT_SCRIPT = HERE / "check-docs.py"

# Every fixture workspace needs these: check-docs.py reads the workspace
# version, MSRV and edition from the repo root before doing anything else.
ROOT_MANIFEST = """\
[workspace]
members = []

[workspace.package]
version = "0.3.1"
rust-version = "1.85"
edition = "2021"
"""


def load(script: Path):
    spec = importlib.util.spec_from_file_location("check_docs_under_test", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------
# Fixtures. Each returns (description, builder, runner).
# --------------------------------------------------------------------------

# A space-separated info string is valid CommonMark and rustdoc accepts it;
# the comma form was handled but the space form was not, so the *opening*
# fence went unrecognised and the *closing* one was parsed as an opening
# fence. Fence parity inverted for the rest of the file and every later block
# became invisible -- including the plainly broken ```rust block here.
FENCE_PARITY_EXAMPLES = """\
# Fixture

```toml
[dependencies]
```

```rust ignore
let this_block_is_legitimately_skipped = 1;
```

```rust
THIS_IS_NOT_RUST_AND_MUST_NOT_COMPILE;
```
"""

# Same root cause, different victim: the version check never sees the ```toml
# block that follows a space-separated info string, so a stale install
# snippet sails through.
FENCE_PARITY_VERSIONS = """\
# Fixture

```rust ignore
let x = 1;
```

```toml
[dependencies]
pakery-core = "0.1"
```
"""

# Blocks were wrapped in `fn main() { ... }` unconditionally, so a snippet
# that spells its own `fn main()` became a nested function nobody calls: it
# compiled, it never ran, and the gate's headline property ("built AND run")
# quietly did not hold for it.
OWN_MAIN = """\
# Fixture

```toml
[dependencies]
```

```rust
fn main() {
    assert_eq!(2 + 2, 5, "this example must fail when it is actually run");
}
```
"""


def case_fence_parity_examples(repo: Path) -> None:
    (repo / "Cargo.toml").write_text(ROOT_MANIFEST)
    (repo / "README.md").write_text(FENCE_PARITY_EXAMPLES)


def case_fence_parity_versions(repo: Path) -> None:
    (repo / "Cargo.toml").write_text(ROOT_MANIFEST)
    (repo / "README.md").write_text(FENCE_PARITY_VERSIONS)


def case_own_main(repo: Path) -> None:
    (repo / "Cargo.toml").write_text(ROOT_MANIFEST)
    (repo / "README.md").write_text(OWN_MAIN)


def _fixture_crate(repo: Path, body: str) -> None:
    (repo / "Cargo.toml").write_text(ROOT_MANIFEST)
    crate = repo / "fixture-crate"
    crate.mkdir()
    (crate / "Cargo.toml").write_text(body)


# docs.rs builds default features only unless told otherwise, so a public
# feature missing from a hand-written `features` list is simply absent from
# the rendered documentation -- the exact defect 0.3.1 existed to fix,
# recreated where no check was looking.
STALE_DOCS_RS = """\
[package]
name = "fixture-crate"
version = "0.0.0"

[package.metadata.docs.rs]
features = ["std"]

[features]
default = ["std"]
std = []
newthing = []
__private = []
"""

# The mirror image, and the reason the check cannot simply demand
# `all-features = true`: pakery-core deliberately excludes `__ctgrind`, which
# pulls crabgrind and emits Valgrind client requests. A private feature left
# out of the docs.rs set is correct, and must stay green.
DELIBERATE_PRIVATE_EXCLUSION = """\
[package]
name = "fixture-crate"
version = "0.0.0"

[package.metadata.docs.rs]
features = ["std", "os_rng"]

[features]
default = ["std"]
std = []
os_rng = []
__ctgrind = []
"""


def case_stale_docs_rs(repo: Path) -> None:
    _fixture_crate(repo, STALE_DOCS_RS)


def case_private_exclusion(repo: Path) -> None:
    _fixture_crate(repo, DELIBERATE_PRIVATE_EXCLUSION)


# check_features was verified in 60b2976 against four historical regression
# shapes, so these are guards rather than reproductions: one per direction of
# the check, including the `(default)` annotation, which is the easiest of the
# three to break without noticing.
FEATURES_MANIFEST = """\
[package]
name = "fixture-crate"
version = "0.0.0"

[package.metadata.docs.rs]
all-features = true

[features]
default = ["std"]
std = []
os_rng = []
"""

FEATURES_README = """\
# fixture-crate

## Features

| Feature | Description |
|---|---|
| `std` (default) | standard library support |
| `os_rng` | operating-system RNG |
"""


def _features_fixture(repo: Path, manifest: str, readme: str) -> None:
    (repo / "Cargo.toml").write_text(ROOT_MANIFEST)
    # The root README is checked separately, for features common to every
    # protocol crate. It carries no features section here, so it is silent.
    (repo / "README.md").write_text("# Fixture workspace\n")
    crate = repo / "fixture-crate"
    crate.mkdir()
    (crate / "Cargo.toml").write_text(manifest)
    (crate / "README.md").write_text(readme)


def case_feature_undeclared(repo: Path) -> None:
    _features_fixture(
        repo,
        FEATURES_MANIFEST,
        FEATURES_README + "| `phantom` | documented, never declared |\n",
    )


def case_feature_undocumented(repo: Path) -> None:
    _features_fixture(
        repo,
        FEATURES_MANIFEST + "newthing = []\n",
        FEATURES_README,
    )


def case_default_annotation_wrong(repo: Path) -> None:
    _features_fixture(
        repo,
        FEATURES_MANIFEST,
        FEATURES_README.replace("| `os_rng` |", "| `os_rng` (default) |"),
    )


def run_features(mod, repo: Path, target: Path) -> None:
    mod.CRATES = ["fixture-crate"]
    mod.PROTOCOL_CRATES = ["fixture-crate"]
    mod.check_features()


def run_examples(mod, repo: Path, target: Path) -> None:
    mod.check_examples(target, False)


def run_versions(mod, repo: Path, target: Path) -> None:
    mod.check_versions()


def run_docsrs(mod, repo: Path, target: Path) -> None:
    # Absent in versions that predate the check: that is the "not detected"
    # state for this case, not an error in the harness.
    fn = getattr(mod, "check_docs_rs_features", None)
    if fn is None:
        return
    mod.CRATES = ["fixture-crate"]
    fn()


CASES = [
    (
        "fence-parity-examples",
        "a space-separated info string (```rust ignore) hides every later "
        "block, so a plainly broken example is never compiled",
        case_fence_parity_examples,
        run_examples,
        True,
        "fix",
    ),
    (
        "fence-parity-versions",
        "the same inverted parity hides a ```toml install snippet pinned to "
        "a version the workspace no longer publishes",
        case_fence_parity_versions,
        run_versions,
        True,
        "fix",
    ),
    (
        "example-with-own-main",
        "an example that spells its own fn main() is compiled but never run, "
        "so a false assertion in it cannot fail",
        case_own_main,
        run_examples,
        True,
        "fix",
    ),
    (
        "stale-docs-rs-features",
        "a public feature missing from the hand-written docs.rs feature list "
        "is silently absent from the rendered documentation",
        case_stale_docs_rs,
        run_docsrs,
        True,
        "fix",
    ),
    (
        "private-feature-excluded-on-purpose",
        "a __-prefixed private feature left out of the docs.rs list is "
        "correct and must NOT be reported",
        case_private_exclusion,
        run_docsrs,
        False,
        "guard",
    ),
    (
        "feature-documented-but-not-declared",
        "a README feature table naming a feature the manifest never declares",
        case_feature_undeclared,
        run_features,
        True,
        "guard",
    ),
    (
        "feature-declared-but-not-documented",
        "a manifest feature the README feature table never mentions",
        case_feature_undocumented,
        run_features,
        True,
        "guard",
    ),
    (
        "default-annotation-wrong",
        "a README marking a feature (default) that `default = [...]` omits",
        case_default_annotation_wrong,
        run_features,
        True,
        "guard",
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--script",
        default=str(DEFAULT_SCRIPT),
        help="checker to exercise; point at an older copy to reproduce the A/B",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--only", default="", help="run just this case by name")
    args = ap.parse_args()

    script = Path(args.script).resolve()
    print(f"exercising {script}\n")

    base = Path(tempfile.mkdtemp(prefix="check-docs-selftest-"))
    failures = []
    try:
        for name, why, build, run, want_finding, proves in CASES:
            if args.only and args.only != name:
                continue
            repo = base / name
            repo.mkdir()
            build(repo)

            mod = load(script)
            mod.REPO = repo
            mod.findings.clear()
            run(mod, repo, base / "target")
            got = list(mod.findings)

            if bool(got) == want_finding:
                verdict = "ok" if want_finding else "ok (correctly silent)"
                print(f"  [{verdict}] {name} ({proves})")
            elif want_finding:
                print(f"  [NOT DETECTED] {name} ({proves})\n      {why}")
                failures.append((name, proves))
            else:
                print(f"  [FALSE POSITIVE] {name} ({proves})\n      {why}")
                failures.append((name, proves))
            if args.verbose and got:
                for f in got:
                    print(f"        finding: {f.splitlines()[0]}")
    finally:
        shutil.rmtree(base, ignore_errors=True)

    print()
    if failures:
        names = [f"{name} ({proves})" for name, proves in failures]
        print(f"{len(failures)} case(s) not handled as expected: {names}")
        if any(proves == "guard" for _, proves in failures):
            print(
                "At least one is a `guard` case, which pins behaviour that "
                "has always been correct. A guard must be red against every "
                "version of the checker, including older copies passed with "
                "--script, so this is a real regression whichever script was "
                "exercised."
            )
        else:
            print(
                "All of these are `fix` cases. Against the current checker "
                "that is a real regression; against an older copy passed "
                "with --script it is the expected result, and is exactly "
                "what makes the fix meaningful."
            )
        return 1
    print(f"all {len(CASES) if not args.only else 1} break-test case(s) behaved as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
