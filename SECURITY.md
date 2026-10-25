# Security policy

pakery implements password-authenticated key exchange, so a flaw in it can
expose passwords or session keys. Please report a suspected vulnerability
privately, as described below.

## Reporting a vulnerability

Do not open a public issue, pull request or discussion for a suspected
vulnerability. Report it through GitHub's private vulnerability reporting
instead: the **Report a vulnerability** button on the repository's Security
tab, or directly at
<https://github.com/djx-y-z/pakery/security/advisories/new>.

On GitHub, a report is visible only to the maintainer and to you. The
maintainer may use AI-assisted tools to analyse a report and to prepare a fix,
so its contents can be processed by such a tool; it is not otherwise shared
without your consent.

### What to include

The more of this a report has, the sooner it can be confirmed:

- the affected crates and versions, the Cargo features enabled, and the
  ciphersuite (ristretto255 or P-256);
- where the problem is: a file and line, or the API involved;
- what an attacker gains, and what they must control to get it: protocol
  messages, the password, timing measurements, or something else;
- a way to reproduce it: a test, the inputs, or a proof of concept; for a
  timing or constant-time issue, the measurement or the Valgrind log;
- the root cause and when it was introduced, if you know them;
- whether any of it is public already, and who else you have told, such as
  the maintainers of a dependency;
- any deadline you are working to, and how you would like to be credited.

If you used AI tools to find the issue or to write the report, please say so,
and include a reproduction that you have run yourself.

### Proposing a fix

A fix is welcome but not required. Attach it to the report as a patch, or
start a temporary private fork from the report and push it there. CI does not
run in temporary private forks, so say which of the checks in
[CONTRIBUTING.md](CONTRIBUTING.md) you ran. Only the maintainer can merge from
the fork.

## What happens next

pakery has one maintainer, so these times are best effort:

1. **Acknowledgement** within 7 days.
2. **Assessment** within 30 days: reproducing the issue, deciding whether it is
   a vulnerability, and agreeing its severity with you.
3. **Fix**, developed privately and released as a new version of all six
   crates, which share one version number.
4. **Advisory**: a GitHub Security Advisory, with a CVE requested through
   GitHub, and an entry in the [RustSec Advisory Database](https://rustsec.org/),
   which `cargo audit` and `cargo deny` read. It is published on the date
   agreed with you and with the maintainers of any affected dependency,
   usually together with the fix but not necessarily.
5. **Credit** in the advisory, unless you prefer not to be named.

## Disclosure

pakery follows coordinated disclosure. Please allow up to 90 days from your
report before disclosing it publicly. An earlier date can be agreed once a fix
is released, and a later one if a fix needs it. When a dependency is involved,
the date is coordinated with its maintainers as well.

## Supported versions

Security fixes go into the latest release only. Earlier version lines get no
backports.

## Scope

In scope are the six published crates: `pakery-core`, `pakery-cpace`,
`pakery-opaque`, `pakery-spake2`, `pakery-spake2plus` and `pakery-crypto`. That
covers the protocol logic, the cryptographic trait implementations, input
validation, and the constant-time handling of secrets in pakery's own code, as
well as how pakery calls its dependencies: for example, passing secret data
to a function that is not constant time.

Report a defect inside a dependency, such as curve25519-dalek, the RustCrypto
crates, subtle, zeroize, rand_core or getrandom, to its maintainers directly.
If it also affects how pakery uses that dependency, tell us too, and say that
you have reported it upstream.

Not treated as vulnerabilities:

- **Missing zeroization.** Wiping secrets is best effort: the compiler can copy
  a value to places the code never sees. A secret left unwiped in pakery's own
  code is fixed in the open as hardening, so please open an ordinary issue.
- Physical side channels, such as power or electromagnetic emanation, and fault
  injection.
- The methods behind the `test-utils` feature, which take fixed scalars and
  seeds for test-vector replay only, and `hazmat` APIs used against their
  documented contract.
- The private `__ctgrind` feature, a hook for pakery's constant-time harness
  that no shipped build enables. An `--all-features` build turns it on, as
  pakery's own CI and test commands do.
- Argon2id's data-dependent memory access, which is part of its design
  (RFC 9106).
- Repository-only tooling: `pakery-tests`, `fuzz/`, `dudect/` and CI. Report a
  problem there publicly, unless it hides a vulnerability in the crates.

## How pakery is tested

[SECURITY_TESTING.md](SECURITY_TESTING.md) describes the test layers: RFC test
vectors, property tests, fuzzing, differential tests, constant-time checks
under Valgrind, and mutation testing.
