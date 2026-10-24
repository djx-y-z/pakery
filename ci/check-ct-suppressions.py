#!/usr/bin/env python3
"""Check what each Valgrind suppression absorbed in one ct.yml run.

Valgrind commons errors up by the top four code addresses on their stack, so
a suppression can absorb errors its pattern never matched: a later error with
the same four addresses joins the first one's record, suppressed or not
(SECURITY_TESTING.md, "Constant-time verification"). `--quiet` hides the
counts. ct.yml therefore runs the harness with `-s`, which lists every
suppression used and the number of errors it absorbed, and this script fails
the run unless that list is exactly the one pakery-tests/valgrind-ct.expected
states for the build. It fails, rather than passes, on anything it cannot
account for:

  - no log, no Valgrind summary (Valgrind did not run, or ran without `-s`),
    output from more than one Valgrind process, or a summary or
    `used_suppression` line it cannot parse;
  - an unsuppressed error;
  - an expected entry that absorbed nothing, an entry the file does not list
    (Valgrind's default suppressions included), or a different count;
  - a summary total that is not the sum of the entries' counts;
  - an expectation naming no stanza of valgrind-ct.supp, or a stanza that no
    build expects;
  - a stanza that names crypto-bigint's `safegcd` inversion, which is never
    suppressed (valgrind-ct.supp's header says why).

Break-tested by ci/test-check-ct-suppressions.py.

usage: check-ct-suppressions.py <debug|release> <valgrind log>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SUPP = REPO / "pakery-tests" / "valgrind-ct.supp"
EXPECTED = REPO / "pakery-tests" / "valgrind-ct.expected"
PROFILES = ("debug", "release")

# `VG_(show_all_errors)` and `show_used_suppressions` in Valgrind's
# coregrind/m_errormgr.c print these at exit under `-s`.
SUMMARY = re.compile(
    r"^==(\d+)== ERROR SUMMARY: (\d+) errors from (\d+) contexts "
    r"\(suppressed: (\d+) from (\d+)\)\s*$"
)
USED = re.compile(r"^--(\d+)-- used_suppression:\s+(\d+) (\S+) \S+:\d+(?: .*)?$")


def stanza_names(supp_text: str) -> list[str]:
    """The name of every `{ ... }` stanza, in file order."""
    names = []
    expect_name = False
    for raw in supp_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "{":
            expect_name = True
        elif expect_name:
            names.append(line)
            expect_name = False
    return names


def load_expected(text: str, source: str) -> dict[str, dict[str, int]]:
    """`{profile: {suppression name: count}}` from the expectations file."""
    expected: dict[str, dict[str, int]] = {p: {} for p in PROFILES}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 3 or fields[0] not in PROFILES or not re.fullmatch(r"[0-9]+", fields[1]):
            raise ValueError(
                f"{source}:{lineno}: expected `<debug|release> <count> <name>`, got {raw!r}"
            )
        profile, count, name = fields[0], int(fields[1]), fields[2]
        if count == 0:
            raise ValueError(
                f"{source}:{lineno}: a count of 0 can never match, since Valgrind lists "
                f"only the entries that absorbed something; drop the line instead"
            )
        if name in expected[profile]:
            raise ValueError(f"{source}:{lineno}: `{name}` is listed twice for {profile}")
        expected[profile][name] = count
    return expected


# crypto-bigint's `safegcd` inversion is constant time by construction, so a
# report in it is a defect to take upstream, never a pattern to accept. Matched
# without regard to case on every line of a stanza, its name included: the
# mangled names spell it in the module path (`7safegcd`) and in the type
# (`15SafeGcdInverter`).
FORBIDDEN = re.compile(r"safegcd", re.IGNORECASE)


def check_forbidden(supp_text: str) -> list[str]:
    """No stanza of the supp file may name crypto-bigint's `safegcd`."""
    problems = []
    name = None
    in_stanza = expect_name = False
    for raw in supp_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "{":
            in_stanza = expect_name = True
            continue
        if line == "}":
            in_stanza = False
            continue
        if expect_name:
            name, expect_name = line, False
        if in_stanza and FORBIDDEN.search(line):
            problems.append(
                f"valgrind-ct.supp: `{name}` names crypto-bigint's `safegcd` inversion "
                f"({line}), which is reported upstream, never suppressed"
            )
    return problems


def check_registry(expected: dict[str, dict[str, int]], stanzas: list[str]) -> list[str]:
    """The expectations and the supp file must name the same entries."""
    problems = []
    listed = set().union(*(set(e) for e in expected.values()))
    for name in sorted(listed - set(stanzas)):
        problems.append(f"valgrind-ct.expected names `{name}`, which no stanza of valgrind-ct.supp has")
    for name in sorted(set(stanzas) - listed):
        problems.append(f"valgrind-ct.supp has `{name}`, which valgrind-ct.expected lists for no build")
    return problems


def check_log(log_text: str, expected: dict[str, int]) -> list[str]:
    """Compare one run's Valgrind summary with one build's expectations."""
    problems = []
    pids: set[str] = set()
    summaries: dict[str, set[tuple[int, int, int, int]]] = {}
    used: dict[str, int] = {}
    for raw in log_text.splitlines():
        line = raw.rstrip("\r")
        m = SUMMARY.match(line)
        if m:
            pids.add(m.group(1))
            summaries.setdefault(m.group(1), set()).add(
                (int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
            )
            continue
        m = USED.match(line)
        if m:
            pids.add(m.group(1))
            name, count = m.group(3), int(m.group(2))
            if name in used and used[name] != count:
                problems.append(f"`{name}` is listed twice, absorbing {used[name]} and {count}")
            used[name] = count
        elif "used_suppression:" in line or "ERROR SUMMARY:" in line:
            problems.append(f"cannot parse this Valgrind line: {line!r}")
    if not summaries:
        problems.append(
            "no Valgrind `ERROR SUMMARY` line: the harness did not run under Valgrind, "
            "or Valgrind ran without `-s`"
        )
        return problems
    if len(pids) != 1:
        problems.append(f"output from {len(pids)} Valgrind processes ({', '.join(sorted(pids))}), not one")
    for pid in sorted(summaries):
        if len(summaries[pid]) != 1:
            problems.append(f"process {pid} printed differing summaries: {sorted(summaries[pid])}")
        for errors, contexts, suppressed, _ in sorted(summaries[pid]):
            if errors:
                problems.append(f"{errors} unsuppressed errors from {contexts} contexts")
            if suppressed != sum(used.values()):
                problems.append(
                    f"the summary counts {suppressed} suppressed errors, "
                    f"the `used_suppression` lines {sum(used.values())}"
                )
    for name in sorted(expected.keys() | used.keys()):
        want, got = expected.get(name), used.get(name)
        if want is None:
            problems.append(f"`{name}` absorbed {got} errors, and no count is expected for it")
        elif got is None:
            problems.append(f"`{name}` is expected to absorb {want} errors and absorbed none")
        elif got != want:
            problems.append(f"`{name}` absorbed {got} errors, not the expected {want}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in PROFILES:
        print(f"usage: {argv[0]} <debug|release> <valgrind log>", file=sys.stderr)
        return 2
    profile, log = argv[1], Path(argv[2])
    if not log.is_file():
        print(f"FAIL: no log at {log}: the harness step did not run", file=sys.stderr)
        return 1
    try:
        expected = load_expected(EXPECTED.read_text(), str(EXPECTED.relative_to(REPO)))
    except ValueError as err:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1
    supp_text = SUPP.read_text()
    problems = check_registry(expected, stanza_names(supp_text))
    problems += check_forbidden(supp_text)
    problems += check_log(log.read_text(errors="replace"), expected[profile])
    print(f"Suppressions expected for the {profile} build (pakery-tests/valgrind-ct.expected):")
    for name, count in sorted(expected[profile].items()):
        print(f"  {count:6d} {name}")
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print("OK: Valgrind's `used_suppression` list matches exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
