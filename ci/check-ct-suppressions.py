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
  - a stanza that names crypto-bigint's `safegcd` inversion (its module, its
    types or any function it defines, by a name its frames carry or a glob
    of one), an inversion or `UnknownInlinedFun`, or that has a `...`,
    wildcards-only, nameless, `obj:` or `src:` frame: `safegcd` is never
    suppressed (valgrind-ct.supp's header says why).

With `--safegcd-names` it checks instead that its list of safegcd's
functions is exactly the locked crypto-bigint's, so a version that adds one
fails CT instead of leaving a stanza that names it unrefused.

Break-tested by ci/test-check-ct-suppressions.py.

usage: check-ct-suppressions.py <debug|release> <valgrind log>
       check-ct-suppressions.py --safegcd-names
"""

from __future__ import annotations

import json
import re
import subprocess
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


# crypto-bigint's `safegcd` inversion is written to be constant time, so a
# report in it is a defect to be taken upstream, never a pattern to accept.
# No stanza may name it:
#
#   - its module or its types, on any line of a stanza, its name included,
#     without regard to case (`safegcd`, which `SafeGcdInverter` contains,
#     and `SignedInt`);
#   - on a `fun:` frame, any function `src/modular/safegcd.rs` defines,
#     methods included (SAFEGCD_FUNCTIONS, which `--safegcd-names` holds to
#     the locked source), by a name its frames carry in pakery's builds:
#     bare, as an inlined frame prints it, with or without its generic
#     arguments, or mangled in the v0 or the legacy scheme. FORBIDDEN_FRAMES
#     holds those names in the shapes of real symbols. A frame is read as a
#     Valgrind glob (`*`, `?`, `\` escapes), its own crate hashes widened,
#     and matched against them, so a glob of such a name is refused too;
#   - an inversion, spelled or matched (`invert`, `inv?rt`): p256's field
#     and scalar inversions are how it is entered;
#   - `UnknownInlinedFun`, which Valgrind prints for an inlined frame it
#     cannot name, and which can be any of the above.
#
# A `...` frame, a frame of wildcards only, a frame that names no function
# (`*>`), and any `obj:` or `src:` frame are refused outright: pakery's
# entries anchor on functions, and each of those matches whatever is inlined
# at that depth, `safegcd` included. A glob broad enough to cover one of
# safegcd's names (`from_*`) is refused with it.
#
# What this cannot refuse: an entry anchored only on helpers the inversion
# calls or inlines (crypto-bigint's `select`, ctutils' `select_i64`, core's
# `wrapping_*`), and a glob written by hand to avoid every name above. Such
# an entry would also absorb the helper's reports from every other caller,
# which its justification would have to defend; the expected counts in
# valgrind-ct.expected and review are the backstop.
FORBIDDEN = re.compile(r"safegcd|signedint", re.IGNORECASE)
INVERSION = re.compile(r"invert", re.IGNORECASE)
SAFEGCD_FUNCTIONS = frozenset(
    {
        "conditional_negate_in_place_wide",
        "from_uint",
        "from_uint_sign",
        "gcd_odd",
        "invert",
        "invert_odd_mod",
        "invert_odd_mod_precomp",
        "invert_vartime",
        "is_negative",
        "is_nonzero",
        "is_zero_vartime",
        "iterations",
        "jump",
        "jump_step",
        "jump_step_vartime",
        "lincomb_int",
        "lincomb_int_reduce_shift",
        "lincomb_int_reduce_shift_mod",
        "lowest",
        "magnitude",
        "new_with_inverse",
        "norm",
        "shr_in_place_wide",
        "update_de",
        "update_fg",
    }
)
# Defined in safegcd.rs too, but so common a name that refusing it would
# refuse frames of every other type; the module and type names cover them.
GENERIC_NAMES = frozenset({"eq", "fmt", "new"})


def glob_regex(pattern: str) -> re.Pattern[str]:
    """A Valgrind frame glob as a regex: `*` any run, `?` one character,
    `\\` the next character literally."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("".join(out), re.DOTALL)


def frame_names(function: str) -> list[str]:
    """The names a frame of `function` carries in pakery's builds: bare, as an
    inlined frame prints it, with the generic arguments its instances take,
    and mangled, in the v0 and legacy schemes, as a free function (generic or
    not), a `SafeGcdInverter` method and a `SignedInt` method (generic or
    not). The shapes are those of the real symbols of a debug and a release
    build of p256 0.14 with crypto-bigint 0.7.9; the crate hashes in them are
    placeholders, since `frame_pattern` widens a pattern's own."""
    n = f"{len(function)}{function}"
    path = "NtNtCs0_13crypto_bigint7modular7safegcd"
    bare = [function] + [
        f"{function}<{args}>"
        for args in ("4", "1", "false", "true", "4, 1", "4, false", "4, true")
    ]
    # A v0 symbol ends with the crate it is instantiated in, with a
    # back-reference to a crate already named (`B6_`), or, compiled in
    # crypto-bigint itself, with nothing.
    v0 = [
        f"_RNv{path}{n}",
        f"_RINv{path}{n}Kj4_E",
        f"_RINv{path}{n}Kb0_E",
        f"_RINv{path}{n}Kj4_Kb0_E",
        f"_RINv{path}{n}Kj4_Kj1_E",
        f"_RNvM{path}INtB2_15SafeGcdInverterKj4_E{n}",
        f"_RNvMs_{path}INtB4_9SignedIntKj4_E{n}",
        f"_RINvMs_{path}INtB5_9SignedIntKj4_E{n}Kj1_E",
    ]
    return bare + [f"{sym}{tail}" for sym in v0 for tail in ("Cs0_4p256", "B0_", "")] + [
        f"_ZN13crypto_bigint7modular7safegcd{n}17h0123456789abcdefE",
        f"_ZN13crypto_bigint7modular7safegcd24SafeGcdInverter$LT$_$GT${n}17h0123456789abcdefE",
        f"_ZN13crypto_bigint7modular7safegcd18SignedInt$LT$_$GT${n}17h0123456789abcdefE",
    ]


FORBIDDEN_FRAMES = [
    (name, function)
    for function in sorted(SAFEGCD_FUNCTIONS)
    for name in frame_names(function)
] + [("UnknownInlinedFun", "UnknownInlinedFun")]

# Names an inversion's frame carries, bare and mangled: crypto-bigint's,
# primefield's and p256's for the field and the scalar, dalek's for
# ristretto255. `INVERSION` refuses a pattern that spells "invert"; these
# refuse one that matches an inversion without spelling it (`inv?rt`).
INVERSION_FRAMES = [
    "invert",
    "invert<4>",
    "invert<p256::arithmetic::field::FieldParams, 4>",
    "invert_vartime",
    "invert_vartime<4>",
    "batch_invert",
    "_RNvMNtNtCs0_4p25610arithmetic5fieldNtB2_12FieldElement6invertCs0_4p256",
    "_RNvMNtNtCs0_4p25610arithmetic6scalarNtB2_6Scalar6invertCs0_4p256",
    "_RNvMNtCs0_10primefield5montyINtB2_17MontyFieldElementNtNtCs0_4p25610arithmetic5field"
    "11FieldParamsKj4_E6invertCs0_4p256",
    "_RNvMNtCs0_16curve25519_dalek6scalarNtB2_6Scalar6invertCs0_13pakery_crypto",
]


def frame_pattern(pattern: str) -> re.Pattern[str]:
    """A `fun:` pattern as the regex `refused_by` matches names with: the
    pattern's own crate hashes and back-references (v0 `Cs…_` and `B…_`,
    legacy `17h…E`) are widened to wildcards first, so a pattern copied from another build's symbol matches
    the placeholder names above as it would that build's."""
    pattern = re.sub(r"Cs[0-9A-Za-z]*_", "Cs*_", pattern)
    pattern = re.sub(r"B[0-9A-Za-z]*_", "B*_", pattern)
    pattern = re.sub(r"17h[0-9a-f]*E", "17h*E", pattern)
    return glob_regex(pattern)


def refused_by(pattern: str) -> str | None:
    """The safegcd function (or `UnknownInlinedFun`) a `fun:` pattern can
    match, if any. A pattern with generic arguments is also matched without
    them, so an instance the names above do not list is still refused."""
    patterns = [pattern]
    if "<" in pattern:
        patterns.append(pattern.split("<", 1)[0])
    for p in patterns:
        regex = frame_pattern(p)
        for name, function in FORBIDDEN_FRAMES:
            if regex.fullmatch(name):
                return function
    return None


def names_inversion(pattern: str) -> bool:
    """Whether a `fun:` pattern spells "invert" or matches an inversion."""
    if INVERSION.search(pattern):
        return True
    regex = frame_pattern(pattern)
    return any(regex.fullmatch(name) for name in INVERSION_FRAMES)


def check_forbidden(supp_text: str) -> list[str]:
    """No stanza of the supp file may name crypto-bigint's `safegcd`, an
    inversion or an unresolved inlined frame, or reach beneath its own
    frames."""
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
        if not in_stanza:
            continue
        if FORBIDDEN.search(line):
            problems.append(
                f"valgrind-ct.supp: `{name}` names crypto-bigint's `safegcd` inversion "
                f"({line}), which is to be reported upstream, never suppressed"
            )
        if line == "...":
            problems.append(
                f"valgrind-ct.supp: `{name}` has a `...` frame, which matches whatever "
                f"is inlined beneath its pattern, `safegcd` included"
            )
            continue
        if line.startswith(("obj:", "src:")):
            problems.append(
                f"valgrind-ct.supp: `{name}` has an `obj:` or `src:` frame ({line}); "
                f"entries anchor on functions, and this matches `safegcd`'s too"
            )
            continue
        if not line.startswith("fun:"):
            continue
        pattern = line[4:]
        if not pattern.strip("*?"):
            problems.append(
                f"valgrind-ct.supp: `{name}` has a frame that is wildcards only ({line}), "
                f"which matches any function, `safegcd` included"
            )
            continue
        if not re.search(r"[A-Za-z_]", pattern):
            problems.append(
                f"valgrind-ct.supp: `{name}` has a frame that names no function ({line}), "
                f"which matches whatever its wildcards reach, `safegcd` included"
            )
            continue
        if names_inversion(pattern):
            problems.append(
                f"valgrind-ct.supp: `{name}` names an inversion ({line}), which runs "
                f"constant-time code, `safegcd` on P-256, and is never suppressed"
            )
        function = refused_by(pattern)
        if function == "UnknownInlinedFun":
            problems.append(
                f"valgrind-ct.supp: `{name}` has a frame matching `UnknownInlinedFun` "
                f"({line}), an inlined frame Valgrind could not name, `safegcd` included"
            )
        elif function is not None:
            problems.append(
                f"valgrind-ct.supp: `{name}` names crypto-bigint's `safegcd` inversion "
                f"({line} matches its function `{function}`), which is to be reported "
                f"upstream, never suppressed"
            )
    return problems


def safegcd_function_names(source: str) -> set[str]:
    """Every function crypto-bigint's `src/modular/safegcd.rs` defines,
    methods included, outside its test module."""
    cut = source.find("#[cfg(test)]\nmod tests")
    if cut >= 0:
        source = source[:cut]
    return set(re.findall(r"\bfn ([A-Za-z_][A-Za-z0-9_]*)", source))


def check_safegcd_names(defined: set[str]) -> list[str]:
    """SAFEGCD_FUNCTIONS must be exactly the functions the source defines,
    less GENERIC_NAMES."""
    problems = []
    for function in sorted(defined - SAFEGCD_FUNCTIONS - GENERIC_NAMES):
        problems.append(
            f"crypto-bigint's safegcd.rs defines `{function}`, which SAFEGCD_FUNCTIONS does "
            f"not list: add it, or a stanza naming it is not refused"
        )
    for function in sorted(SAFEGCD_FUNCTIONS - defined):
        problems.append(
            f"SAFEGCD_FUNCTIONS lists `{function}`, which crypto-bigint's safegcd.rs no "
            f"longer defines: drop it, and look for what replaced it"
        )
    return problems


def locked_safegcd_source() -> Path:
    """`src/modular/safegcd.rs` of the crypto-bigint that pakery-crypto's p256
    resolves to, by the dependency graph `cargo metadata` reports."""
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--all-features"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    meta = json.loads(out)
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

    def normal_deps(node_id: str) -> list[str]:
        return [
            dep["pkg"]
            for dep in nodes[node_id]["deps"]
            if any(kind["kind"] is None for kind in dep["dep_kinds"])
        ]

    crypto = [i for i in meta["workspace_members"] if packages[i]["name"] == "pakery-crypto"]
    if len(crypto) != 1:
        raise ValueError("cargo metadata lists no single pakery-crypto workspace member")
    p256 = [i for i in normal_deps(crypto[0]) if packages[i]["name"] == "p256"]
    if len(p256) != 1:
        raise ValueError("pakery-crypto does not resolve exactly one p256")
    found, seen, stack = set(), set(), list(p256)
    while stack:
        node_id = stack.pop()
        if node_id in seen:
            continue
        seen.add(node_id)
        if packages[node_id]["name"] == "crypto-bigint":
            found.add(node_id)
            continue
        stack.extend(normal_deps(node_id))
    if len(found) != 1:
        versions = sorted(packages[i]["version"] for i in found)
        raise ValueError(f"p256 resolves {len(found)} crypto-bigint versions, not one: {versions}")
    manifest = Path(packages[found.pop()]["manifest_path"])
    return manifest.parent / "src" / "modular" / "safegcd.rs"


def safegcd_names_main() -> int:
    try:
        source = locked_safegcd_source()
        problems = check_safegcd_names(safegcd_function_names(source.read_text()))
    except (OSError, ValueError, subprocess.CalledProcessError, KeyError) as err:
        print(f"FAIL: cannot read the locked crypto-bigint's safegcd.rs: {err}", file=sys.stderr)
        return 1
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(f"OK: SAFEGCD_FUNCTIONS is exactly the functions of {source}, less GENERIC_NAMES.")
    return 0


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
    if argv[1:] == ["--safegcd-names"]:
        return safegcd_names_main()
    if len(argv) != 3 or argv[1] not in PROFILES:
        print(
            f"usage: {argv[0]} <debug|release> <valgrind log>\n"
            f"       {argv[0]} --safegcd-names",
            file=sys.stderr,
        )
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
