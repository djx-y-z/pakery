#!/usr/bin/env python3
"""Print the CHANGELOG.md section for one release as a GitHub release body.

`gh release create --generate-notes` summarises the pull requests merged since
the previous tag. A release commit pushed straight to `main` has no pull
request to summarise, so for v0.2.1 and v0.3.1 it produced a couple of hundred
characters crediting an unrelated PR and saying nothing about the release
itself. The CHANGELOG entry already *is* the release note; this extracts it.

Usage:  python3 ci/release-notes.py v0.3.1

Exits non-zero having written nothing to stdout if the version has no section
or its section is empty. That is deliberate: a release whose notes cannot be
produced must fail loudly rather than publish an empty body, which is the
failure this script exists to prevent.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HEADING_RE = re.compile(r"^## \[([0-9][0-9A-Za-z.\-+]*)\]")


def repo_url() -> str:
    with (REPO / "Cargo.toml").open("rb") as fh:
        return tomllib.load(fh)["workspace"]["package"]["repository"].rstrip("/")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <tag-or-version>", file=sys.stderr)
        return 2
    version = argv[1].lstrip("vV")

    lines = (REPO / "CHANGELOG.md").read_text().splitlines()
    starts: list[tuple[int, str]] = [
        (n, m.group(1))
        for n, line in enumerate(lines)
        if (m := HEADING_RE.match(line))
    ]
    index = next((i for i, (_, v) in enumerate(starts) if v == version), None)
    if index is None:
        print(
            f"CHANGELOG.md has no `## [{version}]` section "
            f"(found: {', '.join(v for _, v in starts)}).\n"
            f"Every release needs its entry written before the tag is pushed.",
            file=sys.stderr,
        )
        return 1

    begin = starts[index][0] + 1
    end = starts[index + 1][0] if index + 1 < len(starts) else len(lines)
    body = "\n".join(lines[begin:end]).strip()
    if not body:
        print(
            f"CHANGELOG.md's `## [{version}]` section is empty; refusing to "
            f"publish a release with no notes.",
            file=sys.stderr,
        )
        return 1

    url = repo_url()
    footer = [f"**Full changelog:** {url}/blob/v{version}/CHANGELOG.md"]
    if index + 1 < len(starts):
        previous = starts[index + 1][1]
        footer.append(f"**Compare:** {url}/compare/v{previous}...v{version}")

    print(body)
    print("\n---\n")
    print("\n".join(footer))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
