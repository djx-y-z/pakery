#!/usr/bin/env python3
"""Break-tests for ci/check-ct-suppressions.py: prove each check can fail.

A gate nobody has seen fail is decoration, and this one guards a quiet
failure: a suppression that absorbs more than its pattern leaves ct.yml
green. Each case below feeds the checker a synthetic Valgrind log (or a
synthetic supp / expectations pair, or a log that does not exist) and asserts
the specific finding it must report, so a case cannot pass because some
*other* check happened to fire. The last cases run the real valgrind-ct.supp
and valgrind-ct.expected
through the parsers, so a malformed edit to either fails here before CI
spends a Valgrind run on it.

usage: test-check-ct-suppressions.py [--script <path to checker>]
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUPP_PATH = "/home/runner/work/pakery/pakery/pakery-tests/valgrind-ct.supp"


def load(path: Path):
    spec = importlib.util.spec_from_file_location("check_ct_suppressions", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def log(*lines: str) -> str:
    return "\n".join(lines) + "\n"


def summary(pid: int, errors: int, contexts: int, suppressed: int, supp_contexts: int) -> str:
    return (
        f"=={pid}== ERROR SUMMARY: {errors} errors from {contexts} contexts "
        f"(suppressed: {suppressed} from {supp_contexts})"
    )


def used(pid: int, count: int, name: str, line: int = 55) -> str:
    return f"--{pid}-- used_suppression: {count:6d} {name} {SUPP_PATH}:{line}"


TEST_RESULT = "test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
WANT = {"entry-a": 184}

# What `-s` prints at exit for a clean run: the summary, a blank line, the
# used suppressions, and the summary again.
CLEAN = log(
    TEST_RESULT,
    summary(4602, 0, 0, 184, 20),
    "--4602-- ",
    used(4602, 184, "entry-a"),
    "==4602== ",
    summary(4602, 0, 0, 184, 20),
)

# (label, log, expected for the build, substring the finding must contain)
LOG_CASES = [
    ("a clean run matches", CLEAN, WANT, None),
    ("no Valgrind output at all", log(TEST_RESULT), WANT, "no Valgrind `ERROR SUMMARY` line"),
    (
        "a summary without `-s`: no used_suppression lines",
        log(TEST_RESULT, summary(4602, 0, 0, 184, 20)),
        WANT,
        "is expected to absorb 184 errors and absorbed none",
    ),
    (
        "an entry absorbed more than expected",
        log(summary(1, 0, 0, 685, 3), used(1, 685, "entry-a"), summary(1, 0, 0, 685, 3)),
        WANT,
        "absorbed 685 errors, not the expected 184",
    ),
    (
        "an entry absorbed fewer than expected",
        log(summary(1, 0, 0, 92, 1), used(1, 92, "entry-a"), summary(1, 0, 0, 92, 1)),
        WANT,
        "absorbed 92 errors, not the expected 184",
    ),
    (
        "an entry the file does not list (a default suppression)",
        log(
            summary(1, 0, 0, 186, 21),
            used(1, 184, "entry-a"),
            used(1, 2, "glibc-default-entry"),
            summary(1, 0, 0, 186, 21),
        ),
        WANT,
        "`glibc-default-entry` absorbed 2 errors, and no count is expected for it",
    ),
    (
        "an unsuppressed error",
        log(summary(1, 3, 1, 184, 20), used(1, 184, "entry-a"), summary(1, 3, 1, 184, 20)),
        WANT,
        "3 unsuppressed errors from 1 contexts",
    ),
    (
        "output from two Valgrind processes",
        CLEAN + log(summary(4700, 0, 0, 0, 0)),
        WANT,
        "output from 2 Valgrind processes",
    ),
    (
        "a summary total that is not the entries' sum",
        log(summary(1, 0, 0, 190, 20), used(1, 184, "entry-a"), summary(1, 0, 0, 190, 20)),
        WANT,
        "the summary counts 190 suppressed errors",
    ),
    (
        "one entry listed twice with different counts",
        log(
            summary(1, 0, 0, 184, 20),
            used(1, 184, "entry-a"),
            used(1, 183, "entry-a"),
            summary(1, 0, 0, 184, 20),
        ),
        WANT,
        "`entry-a` is listed twice",
    ),
    (
        "differing summaries from one process",
        log(summary(1, 0, 0, 184, 20), used(1, 184, "entry-a"), summary(1, 0, 0, 184, 21)),
        WANT,
        "printed differing summaries",
    ),
    (
        "a used_suppression line it cannot parse (a name with a space)",
        log(
            summary(1, 0, 0, 184, 20),
            f"--1-- used_suppression:    184 entry a {SUPP_PATH}:55",
            summary(1, 0, 0, 184, 20),
        ),
        WANT,
        "cannot parse this Valgrind line",
    ),
    (
        "a summary line it cannot parse",
        log(
            "==1== ERROR SUMMARY: 0 errors from 0 contexts",
            used(1, 184, "entry-a"),
        ),
        WANT,
        "cannot parse this Valgrind line",
    ),
]

SUPP_TWO = "# comment\n{\n   entry-a\n   Memcheck:Cond\n   fun:a\n}\n{\n   entry-b\n   Memcheck:Cond\n   fun:b\n}\n"

# (label, expectations, supp text, substring the finding must contain)
REGISTRY_CASES = [
    ("the expectations and the supp file agree", {"debug": {"entry-b": 1}, "release": {"entry-a": 1}}, SUPP_TWO, None),
    (
        "an expectation names no stanza",
        {"debug": {"entry-b": 1, "entry-typo": 1}, "release": {"entry-a": 1}},
        SUPP_TWO,
        "names `entry-typo`, which no stanza",
    ),
    (
        "a stanza that no build expects",
        {"debug": {}, "release": {"entry-a": 1}},
        SUPP_TWO,
        "has `entry-b`, which valgrind-ct.expected lists for no build",
    ),
]

# (label, expectations text, substring the error must contain)
PARSE_CASES = [
    ("a line without a count", "release entry-a\n", "expected `<debug|release> <count> <name>`"),
    ("an unknown build", "test 184 entry-a\n", "expected `<debug|release> <count> <name>`"),
    ("one entry listed twice for a build", "debug 1 entry-a\ndebug 2 entry-a\n", "listed twice for debug"),
    ("a count of 0", "release 0 entry-a\n", "a count of 0 can never match"),
    ("a count in non-ASCII digits", "release ² entry-a\n", "expected `<debug|release> <count> <name>`"),
]


# (label, supp text, substring the finding must contain)
FORBIDDEN_CASES = [
    ("a supp file that names no safegcd frame", SUPP_TWO, None),
    (
        # Valgrind skips a comment line wherever it stands, inside a stanza too.
        "comments that mention safegcd, outside and inside a stanza",
        "# safegcd is never suppressed\n{\n   entry-a\n   # not safegcd\n   Memcheck:Cond\n   fun:a\n}\n",
        None,
    ),
    (
        "an entry anchored on safegcd's module path",
        "{\n   entry-c\n   Memcheck:Cond\n   fun:*13crypto_bigint*7modular*7safegcd*\n}\n",
        "`entry-c` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "an entry anchored on the inverter type",
        "{\n   entry-d\n   Memcheck:Cond\n   fun:*15SafeGcdInverter*\n   fun:*\n}\n",
        "`entry-d` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "an entry whose name gives it away",
        "{\n   safegcd-branch\n   Memcheck:Cond\n   fun:*invert*\n}\n",
        "`safegcd-branch` names crypto-bigint's `safegcd` inversion",
    ),
]


def run(checker) -> list[str]:
    failures = []
    for label, text, want, finding in LOG_CASES:
        problems = checker.check_log(text, want)
        if finding is None and problems:
            failures.append(f"{label}: expected no finding, got {problems}")
        elif finding is not None and not any(finding in p for p in problems):
            failures.append(f"{label}: NOT DETECTED (wanted {finding!r}, got {problems})")
    for label, expected, supp, finding in REGISTRY_CASES:
        problems = checker.check_registry(expected, checker.stanza_names(supp))
        if finding is None and problems:
            failures.append(f"{label}: expected no finding, got {problems}")
        elif finding is not None and not any(finding in p for p in problems):
            failures.append(f"{label}: NOT DETECTED (wanted {finding!r}, got {problems})")
    for label, text, finding in PARSE_CASES:
        try:
            checker.load_expected(text, "fixture")
        except ValueError as err:
            if finding not in str(err):
                failures.append(f"{label}: wrong error {err}")
        else:
            failures.append(f"{label}: NOT DETECTED (parsed without error)")
    for label, supp, finding in FORBIDDEN_CASES:
        problems = checker.check_forbidden(supp)
        if finding is None and problems:
            failures.append(f"{label}: expected no finding, got {problems}")
        elif finding is not None and not any(finding in p for p in problems):
            failures.append(f"{label}: NOT DETECTED (wanted {finding!r}, got {problems})")
    # A harness step that never ran leaves no log: a finding, not a traceback.
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        status = checker.main(["check-ct-suppressions.py", "release", "/nonexistent/ct.log"])
    if status != 1 or "no log at" not in stderr.getvalue():
        failures.append(f"a missing log: NOT DETECTED (status {status}, {stderr.getvalue()!r})")
    # main() applies the safegcd refusal: a clean log does not save a supp file
    # whose entry names it. The checker reads its files through module globals,
    # pointed here at fixtures and restored afterwards.
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Path(tmp)
        (fixture / "valgrind-ct.supp").write_text(
            "{\n   entry-a\n   Memcheck:Cond\n   fun:*7safegcd*\n}\n"
        )
        (fixture / "valgrind-ct.expected").write_text("debug 184 entry-a\nrelease 184 entry-a\n")
        (fixture / "ct.log").write_text(CLEAN)
        saved = checker.REPO, checker.SUPP, checker.EXPECTED
        checker.REPO = fixture
        checker.SUPP = fixture / "valgrind-ct.supp"
        checker.EXPECTED = fixture / "valgrind-ct.expected"
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                status = checker.main(["check-ct-suppressions.py", "release", str(fixture / "ct.log")])
        finally:
            checker.REPO, checker.SUPP, checker.EXPECTED = saved
    if status != 1 or "names crypto-bigint's `safegcd`" not in stderr.getvalue():
        failures.append(
            f"main() on a clean log with a safegcd entry: NOT DETECTED "
            f"(status {status}, {stderr.getvalue()!r})"
        )
    # The real files: they parse, they agree, every build expects something,
    # and no entry names `safegcd`.
    expected = checker.load_expected(checker.EXPECTED.read_text(), "valgrind-ct.expected")
    problems = checker.check_registry(expected, checker.stanza_names(checker.SUPP.read_text()))
    if problems:
        failures.append(f"the real valgrind-ct.supp and valgrind-ct.expected disagree: {problems}")
    problems = checker.check_forbidden(checker.SUPP.read_text())
    if problems:
        failures.append(f"the real valgrind-ct.supp names `safegcd`: {problems}")
    for profile in checker.PROFILES:
        if not expected[profile]:
            failures.append(f"the real valgrind-ct.expected expects nothing for {profile}")
    return failures


def main(argv: list[str]) -> int:
    script = HERE / "check-ct-suppressions.py"
    if len(argv) == 3 and argv[1] == "--script":
        script = Path(argv[2])
    elif len(argv) != 1:
        print(f"usage: {argv[0]} [--script <path to checker>]", file=sys.stderr)
        return 2
    failures = run(load(script))
    cases = len(LOG_CASES) + len(REGISTRY_CASES) + len(PARSE_CASES) + len(FORBIDDEN_CASES) + 3
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"OK: all {cases} cases behave as expected against {script.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
