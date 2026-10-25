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
import re
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
    (
        # What `--gen-suppressions=all` prints for a release-leg report in it:
        # the inlined frames carry the functions' bare names, not "safegcd".
        "a release-leg entry on safegcd's inlined frames",
        "{\n   entry-e\n   Memcheck:Cond\n   fun:UnknownInlinedFun\n   fun:update_de<4>\n"
        "   fun:jump_step\n   fun:*4p25610arithmetic5field12FieldElement6invert*\n}\n",
        "`entry-e` names crypto-bigint's `safegcd` inversion (fun:update_de<4>",
    ),
    (
        "a mangled glob on one of safegcd's functions, without its module",
        "{\n   entry-f\n   Memcheck:Cond\n   fun:*9jump_step*\n}\n",
        "`entry-f` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "an entry anchored on p256's field inversion",
        "{\n   entry-g\n   Memcheck:Cond\n   fun:*12FieldElement6invert*\n}\n",
        "`entry-g` names an inversion",
    ),
    (
        "an entry on an inlined inversion",
        "{\n   entry-h\n   Memcheck:Cond\n   fun:invert<*>\n}\n",
        "`entry-h` names an inversion",
    ),
    (
        "an entry that reaches beneath its pattern",
        "{\n   entry-i\n   Memcheck:Cond\n   ...\n   fun:*8OsswuMap5osswu*\n}\n",
        "`entry-i` has a `...` frame",
    ),
    (
        "an entry with a frame of wildcards only",
        "{\n   entry-j\n   Memcheck:Cond\n   fun:*\n   fun:*8OsswuMap5osswu*\n}\n",
        "`entry-j` has a frame that is wildcards only",
    ),
    (
        # A safegcd name inside a longer identifier is not that name, and the
        # real entries' own frames pass.
        "frames whose identifiers only contain a safegcd name",
        "{\n   entry-k\n   Memcheck:Cond\n   fun:*jumpstart*\n   fun:*update_defaults*\n"
        "   fun:unwrap<*FieldElement>\n   fun:*8OsswuMap5osswu*\n}\n",
        None,
    ),
    (
        # `SignedInt`'s methods do the bignum work inside it, inlined.
        "an entry on safegcd's SignedInt methods",
        "{\n   entry-l\n   Memcheck:Cond\n   fun:select<4>\n"
        "   fun:lincomb_int_reduce_shift_mod<4, 1>\n}\n",
        "`entry-l` names crypto-bigint's `safegcd` inversion (fun:lincomb_int_reduce_shift_mod",
    ),
    (
        "an entry anchored on the SignedInt type",
        "{\n   entry-m\n   Memcheck:Cond\n   fun:*12crypto_bigint*9SignedInt*11lincomb_int*\n}\n",
        "`entry-m` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "an entry on an inlined frame Valgrind could not name",
        "{\n   entry-n\n   Memcheck:Cond\n   fun:UnknownInlinedFun\n   fun:*8OsswuMap5osswu*\n}\n",
        "`entry-n` has a frame matching `UnknownInlinedFun`",
    ),
    (
        "a glob that matches safegcd's functions without spelling one",
        "{\n   entry-o\n   Memcheck:Cond\n   fun:update_*\n}\n",
        "`entry-o` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "a name split by a one-character wildcard",
        "{\n   entry-p\n   Memcheck:Cond\n   fun:jump_st?p\n}\n",
        "`entry-p` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "a legacy-mangled glob on one of safegcd's functions",
        "{\n   entry-q\n   Memcheck:Cond\n   fun:_ZN13crypto_bigint*9jump_step*\n}\n",
        "`entry-q` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "an inversion that no list names",
        "{\n   entry-r\n   Memcheck:Cond\n   fun:batch_invert<*>\n}\n",
        "`entry-r` names an inversion",
    ),
    (
        "an entry on an object file",
        "{\n   entry-s\n   Memcheck:Cond\n   obj:*\n}\n",
        "`entry-s` has an `obj:` or `src:` frame",
    ),
    (
        "an entry on a source location",
        "{\n   entry-t\n   Memcheck:Cond\n   src:*\n}\n",
        "`entry-t` has an `obj:` or `src:` frame",
    ),
    (
        # Valgrind reads `\_` as `_`: the escape does not hide the name.
        "a name with an escaped character",
        "{\n   entry-v\n   Memcheck:Cond\n   fun:update\\_de<4>\n}\n",
        "`entry-v` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "a frame of one-character wildcards only",
        "{\n   entry-u\n   Memcheck:Cond\n   fun:???\n}\n",
        "`entry-u` has a frame that is wildcards only",
    ),
    (
        # A hand-trimmed glob of a mangled name that drops the module's own
        # token, and the crate as a whole.
        "a trimmed glob of safegcd's mangled module path",
        "{\n   entry-w\n   Memcheck:Cond\n   fun:*13crypto_bigint7modular7saf*\n}\n",
        "`entry-w` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "a glob on a generic instance's v0 name",
        "{\n   entry-x\n   Memcheck:Cond\n   fun:*9update_deKj4_E*\n}\n",
        "`entry-x` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "a generic instance spelled with a one-character wildcard",
        "{\n   entry-y\n   Memcheck:Cond\n   fun:inv?rt_odd_mod_precomp?4, false>\n}\n",
        "`entry-y` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "a pattern that names no function",
        "{\n   entry-z\n   Memcheck:Cond\n   fun:*, 1>\n}\n",
        "`entry-z` has a frame that names no function",
    ),
    (
        "an inversion matched without spelling it",
        "{\n   entry-aa\n   Memcheck:Cond\n   fun:*12FieldElement6inv?rt*\n}\n",
        "`entry-aa` names an inversion",
    ),
    (
        "a mangled name copied from another build, its module trimmed",
        "{\n   entry-ab\n   Memcheck:Cond\n"
        "   fun:_RINvNtNtCs2BhEYyN17EY_13crypto_bigint7modular7saf*4jumpKb0_EB6_\n}\n",
        "`entry-ab` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "a legacy-mangled name with its own build's hash",
        "{\n   entry-ac\n   Memcheck:Cond\n"
        "   fun:_ZN13crypto_bigint7modular7saf*9jump_step17h1111111111111111E\n}\n",
        "`entry-ac` names crypto-bigint's `safegcd` inversion",
    ),
    (
        # Only the name without its generic arguments matches here.
        "a generic instance the reference names do not list",
        "{\n   entry-ad\n   Memcheck:Cond\n   fun:update_de<7>\n}\n",
        "`entry-ad` names crypto-bigint's `safegcd` inversion",
    ),
    (
        # Exactly as many characters as a free function's legacy name has.
        "a legacy-mangled free function, its module masked character by character",
        "{\n   entry-ae\n   Memcheck:Cond\n"
        "   fun:_ZN13crypto_bigint7modular7saf????9jump_step17h*E\n}\n",
        "`entry-ae` names crypto-bigint's `safegcd` inversion",
    ),
    (
        # The name line is matched too, whatever the frames say.
        "an entry whose name alone gives it away",
        "{\n   safegcd-quiet\n   Memcheck:Cond\n   fun:*8OsswuMap5osswu*\n}\n",
        "`safegcd-quiet` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "a legacy-mangled SafeGcdInverter method, its names masked",
        "{\n   entry-af\n   Memcheck:Cond\n"
        "   fun:_ZN13crypto_bigint7modular7saf????24???????Inverter$LT$_$GT$16new_with_inverse17h*E\n}\n",
        "`entry-af` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "a legacy-mangled SignedInt method, its names masked",
        "{\n   entry-ag\n   Memcheck:Cond\n"
        "   fun:_ZN13crypto_bigint7modular7saf????18Sig??dInt$LT$_$GT$4norm17h*E\n}\n",
        "`entry-ag` names crypto-bigint's `safegcd` inversion",
    ),
    (
        "a v0 name compiled in crypto-bigint itself, with no instantiating crate",
        "{\n   entry-ah\n   Memcheck:Cond\n   fun:_RNvNtNtCsab12CD_13crypto_bigint*9jump_step\n}\n",
        "`entry-ah` names crypto-bigint's `safegcd` inversion",
    ),
]

# A stand-in for crypto-bigint's safegcd.rs: two top-level functions, two
# methods (one on several lines, one generic), and a test helper, which must
# not count.
SAFEGCD_SOURCE = (
    "pub const fn invert_odd_mod<const LIMBS: usize>(a: u8) -> u8 {\n    a\n}\n"
    "const fn jump_step(a: u8) -> u8 {\n    a\n}\n"
    "impl Inverter {\n    pub const fn invert(&self) {}\n"
    "    pub(crate) const fn lincomb_int<const RHS: usize>(\n        a: u8,\n    ) {}\n}\n"
    "#[cfg(test)]\nmod tests {\n    fn helper() {}\n}\n"
)


# The outlined safegcd symbols of a debug and a release build of p256 0.14
# with crypto-bigint 0.7.9 (rustc 1.98, v0 mangling). Each, and each with
# its module token and hashes trimmed to wildcards, must be refused.
REAL_SAFEGCD_SYMBOLS = (
    "_RINvMs_NtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB5_9SignedIntKj4_E11lincomb_intKj1_ECsgO2HqeQNGto_4p256",
    "_RINvMs_NtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB5_9SignedIntKj4_E24lincomb_int_reduce_shiftKj1_ECsgO2HqeQNGto_4p256",
    "_RINvMs_NtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB5_9SignedIntKj4_E28lincomb_int_reduce_shift_modKj1_ECsgO2HqeQNGto_4p256",
    "_RINvMs_NtNtCsyz1A8zsUfX_13crypto_bigint7modular7safegcdINtB5_9SignedIntKj4_E11lincomb_intKj1_ECseMw7iCQ0IkG_4p256",
    "_RINvMs_NtNtCsyz1A8zsUfX_13crypto_bigint7modular7safegcdINtB5_9SignedIntKj4_E24lincomb_int_reduce_shiftKj1_ECseMw7iCQ0IkG_4p256",
    "_RINvMs_NtNtCsyz1A8zsUfX_13crypto_bigint7modular7safegcdINtB5_9SignedIntKj4_E28lincomb_int_reduce_shift_modKj1_ECseMw7iCQ0IkG_4p256",
    "_RINvNtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcd14invert_odd_modKj4_Kb0_ECsgO2HqeQNGto_4p256",
    "_RINvNtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcd17shr_in_place_wideKj4_Kj1_ECsgO2HqeQNGto_4p256",
    "_RINvNtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcd22invert_odd_mod_precompKj4_Kb0_ECsgO2HqeQNGto_4p256",
    "_RINvNtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcd32conditional_negate_in_place_wideKj4_Kj1_ECsgO2HqeQNGto_4p256",
    "_RINvNtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcd4jumpKb0_EB6_",
    "_RINvNtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcd9update_deKj4_ECsgO2HqeQNGto_4p256",
    "_RINvNtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcd9update_fgKj4_ECsgO2HqeQNGto_4p256",
    "_RINvNtNtCsyz1A8zsUfX_13crypto_bigint7modular7safegcd22invert_odd_mod_precompKj4_Kb0_ECseMw7iCQ0IkG_4p256",
    "_RNvMNtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB2_15SafeGcdInverterKj4_E16new_with_inverseCsgO2HqeQNGto_4p256",
    "_RNvMNtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB2_15SafeGcdInverterKj4_E6invertCsgO2HqeQNGto_4p256",
    "_RNvMs_NtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB4_9SignedIntKj4_E10is_nonzeroCsgO2HqeQNGto_4p256",
    "_RNvMs_NtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB4_9SignedIntKj4_E11is_negativeCsgO2HqeQNGto_4p256",
    "_RNvMs_NtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB4_9SignedIntKj4_E14from_uint_signCsgO2HqeQNGto_4p256",
    "_RNvMs_NtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB4_9SignedIntKj4_E4normCsgO2HqeQNGto_4p256",
    "_RNvMs_NtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB4_9SignedIntKj4_E6lowestCsgO2HqeQNGto_4p256",
    "_RNvMs_NtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcdINtB4_9SignedIntKj4_E9from_uintCsgO2HqeQNGto_4p256",
    "_RNvMs_NtNtCsyz1A8zsUfX_13crypto_bigint7modular7safegcdINtB4_9SignedIntKj4_E4normCseMw7iCQ0IkG_4p256",
    "_RNvNtNtCs2BhEYyN17EY_13crypto_bigint7modular7safegcd10iterationsCsgO2HqeQNGto_4p256",
)


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
    # Real symbols, and globs a hand might trim them to.
    for symbol in REAL_SAFEGCD_SYMBOLS:
        for frame in (
            symbol,
            symbol.replace("7safegcd", "7saf*").replace("SignedInt", "Sig*"),
            re.sub(r"Cs[0-9A-Za-z]+_", "Cs*_", symbol.replace("7safegcd", "7*")),
        ):
            stanza = "{\n   entry-real\n   Memcheck:Cond\n   fun:" + frame + "\n}\n"
            if not checker.check_forbidden(stanza):
                failures.append(f"a real safegcd symbol as a frame: NOT DETECTED ({frame})")
    # `--safegcd-names` reads every function outside the test module, methods
    # included, and reports a list that drifted from them in both directions,
    # the names every type has aside.
    names = checker.safegcd_function_names(SAFEGCD_SOURCE)
    if names != {"invert_odd_mod", "jump_step", "invert", "lincomb_int"}:
        failures.append(f"safegcd.rs's functions: wrong set {sorted(names)}")
    drifted = (checker.SAFEGCD_FUNCTIONS - {"jump"}) | {"jump_step2", "fmt"}
    problems = checker.check_safegcd_names(drifted)
    if not (
        any("defines `jump_step2`" in p for p in problems)
        and any("lists `jump`" in p for p in problems)
        and not any("`fmt`" in p for p in problems)
    ):
        failures.append(f"a safegcd list that drifted both ways: NOT DETECTED ({problems})")
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
    # and the safegcd refusal finds nothing in them.
    expected = checker.load_expected(checker.EXPECTED.read_text(), "valgrind-ct.expected")
    problems = checker.check_registry(expected, checker.stanza_names(checker.SUPP.read_text()))
    if problems:
        failures.append(f"the real valgrind-ct.supp and valgrind-ct.expected disagree: {problems}")
    problems = checker.check_forbidden(checker.SUPP.read_text())
    if problems:
        failures.append(f"the real valgrind-ct.supp is refused: {problems}")
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
    cases = len(LOG_CASES) + len(REGISTRY_CASES) + len(PARSE_CASES) + len(FORBIDDEN_CASES) + 6
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"OK: all {cases} cases behave as expected against {script.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
