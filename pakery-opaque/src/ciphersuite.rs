//! OPAQUE ciphersuite trait.

use pakery_core::crypto::{DhGroup, Hash, Kdf, Ksf, Mac, Oprf};

/// Trait defining the cryptographic primitives for an OPAQUE ciphersuite.
///
/// Constants follow RFC 9807 naming: Nn (nonce), Nseed (seed), Noe (OPRF element),
/// Nok (OPRF key), Nm (MAC), Nh (hash), Npk (public key), Nsk (secret key), Nx (KDF extract).
///
/// # None of these lengths is a free parameter
///
/// RFC 9807 fixes `Nn` and `Nseed` at 32 for every configuration, and derives
/// the other seven from the primitives named above. They are declared here
/// only because Rust has no way to read them off the associated types
/// directly — not because a ciphersuite may choose them.
///
/// All nine are checked against the primitives at compile time from every
/// entry point that takes a ciphersuite, so a suite whose constants disagree
/// with its own primitives fails to build. `NH` is checked twice — against
/// `Hash::OUTPUT_SIZE` and against `Oprf::OUTPUT_LEN` — because both produce
/// `Nh` bytes and a hand-written suite can name a hash and an OPRF that
/// disagree. Before `0.5.0` nothing performed
/// this check: `NOK` and `NSK` were never read at all, and a wrong `NN` or
/// `NSEED` changed the bytes on the wire while every pakery-to-pakery test
/// still passed.
pub trait OpaqueCiphersuite: Sized + 'static {
    /// The hash function.
    type Hash: Hash;
    /// The key derivation function.
    type Kdf: Kdf;
    /// The message authentication code.
    type Mac: Mac;
    /// The Diffie-Hellman group.
    type Dh: DhGroup;
    /// The oblivious PRF.
    type Oprf: Oprf;
    /// The key stretching function.
    type Ksf: Ksf;

    /// Nonce length in bytes.
    ///
    /// RFC 9807 Section 2 fixes this at 32 for every configuration
    /// ("all random nonces and seeds ... are of length Nn and Nseed bytes,
    /// respectively, where Nn = Nseed = 32"), which is the default. Do not
    /// override it.
    const NN: usize = 32;
    /// Seed length in bytes.
    ///
    /// RFC 9807 Section 2 fixes this at 32 for every configuration, which is
    /// the default. Do not override it.
    const NSEED: usize = 32;
    /// OPRF serialized element length in bytes.
    const NOE: usize;
    /// OPRF scalar/key length in bytes.
    const NOK: usize;
    /// MAC output length in bytes.
    const NM: usize;
    /// Hash output length in bytes.
    const NH: usize;
    /// Public key length in bytes.
    const NPK: usize;
    /// Secret key length in bytes.
    const NSK: usize;
    /// KDF extract output length in bytes.
    const NX: usize;
}

/// Compile-time check that a ciphersuite's declared lengths agree with the
/// primitives it names and with the two values RFC 9807 fixes outright.
///
/// Called first by every exported function that takes no `self` and is
/// generic over a `C: OpaqueCiphersuite`: the protocol entry points
/// (`ServerSetup::new` and `new_with_key`, and the registration and login
/// `start` functions), and the building blocks the crate also exports (the
/// `oprf`, `envelope` and `key_derivation` functions, the message parsers
/// and the two `size` functions). So the check runs whenever a suite is
/// monomorphized through any of them, and `every_entry_point_asserts_lengths`
/// keeps it that way. A mismatch is a build error naming the offending
/// constant, not a silent change to the wire format.
///
/// These are post-monomorphization const evaluations, so they fire on
/// `cargo build` and `cargo test` — which is where CI catches them — but not
/// on `cargo check`, which stops before codegen. A downstream crate sees the
/// error when it builds its own call to any of these functions.
///
/// Returns the number of invariants checked. That return value is the only
/// thing about this function a runtime test can observe: for a *correct*
/// suite the assertions compile to nothing, and their sole effect is on which
/// *wrong* suites fail to build — of which a test binary contains none, by
/// construction. The count is therefore a tripwire on the body being intact,
/// not a proof of the assertions themselves; those are verified by
/// reintroducing each defect (see the `0.5.0` changelog).
pub(crate) fn assert_lengths<C: OpaqueCiphersuite>() -> usize {
    // Fixed by RFC 9807 Section 2 for every configuration.
    const {
        assert!(
            C::NN == 32,
            "OpaqueCiphersuite::NN must be 32 (RFC 9807 Section 2)"
        )
    };
    const {
        assert!(
            C::NSEED == 32,
            "OpaqueCiphersuite::NSEED must be 32 (RFC 9807 Section 2)"
        )
    };
    // Determined by the associated types.
    const {
        assert!(
            <C::Hash as Hash>::OUTPUT_SIZE == C::NH,
            "OpaqueCiphersuite::NH must equal Hash::OUTPUT_SIZE"
        )
    };
    const {
        assert!(
            <C::Mac as Mac>::OUTPUT_SIZE == C::NM,
            "OpaqueCiphersuite::NM must equal Mac::OUTPUT_SIZE"
        )
    };
    const {
        assert!(
            <C::Kdf as Kdf>::EXTRACT_SIZE == C::NX,
            "OpaqueCiphersuite::NX must equal Kdf::EXTRACT_SIZE"
        )
    };
    const {
        assert!(
            <C::Dh as DhGroup>::SK_LEN == C::NSK,
            "OpaqueCiphersuite::NSK must equal DhGroup::SK_LEN"
        )
    };
    const {
        assert!(
            <C::Dh as DhGroup>::PK_LEN == C::NPK,
            "OpaqueCiphersuite::NPK must equal DhGroup::PK_LEN"
        )
    };
    const {
        assert!(
            <C::Oprf as Oprf>::KEY_LEN == C::NOK,
            "OpaqueCiphersuite::NOK must equal Oprf::KEY_LEN"
        )
    };
    const {
        assert!(
            <C::Oprf as Oprf>::ELEMENT_LEN == C::NOE,
            "OpaqueCiphersuite::NOE must equal Oprf::ELEMENT_LEN"
        )
    };
    // `NH` is checked twice, against both primitives that produce `Nh` bytes.
    // `Hash::OUTPUT_SIZE` above covers the transcript hash; this covers the
    // OPRF output, which `derive_randomized_password` feeds to the KSF and
    // concatenates into the `Extract` input. Nothing else ties the two
    // together: `Oprf` names its own hash internally, and `finalize` returns
    // a `Vec<u8>`.
    const {
        assert!(
            <C::Oprf as Oprf>::OUTPUT_LEN == C::NH,
            "OpaqueCiphersuite::NH must equal Oprf::OUTPUT_LEN"
        )
    };
    10
}

#[cfg(test)]
mod tests {
    use super::assert_lengths;
    use crate::test_mocks::MockSuite;

    /// `assert_lengths` must still contain its ten checks.
    ///
    /// The assertions themselves are invisible to a runtime test — for a
    /// correct suite they compile to nothing. Without this, `cargo-mutants`
    /// replaces the whole body and every test still passes: measured on
    /// `21db5c5`, gutting the body left all 354 tests green *and* let a suite
    /// declaring `NH = 32` against a SHA-512 hash build cleanly. The returned
    /// count is what makes emptying the body observable.
    #[test]
    fn assert_lengths_checks_all_ten_invariants() {
        assert_eq!(assert_lengths::<MockSuite>(), 10);
    }

    /// Whether a parameter list, as written after its `(`, opens with a `self`
    /// receiver: `self`, `mut self`, `&self`, `&mut self`, `&'a self`, or any
    /// of them with a type (`self: Box<Self>`).
    #[cfg(feature = "std")]
    fn has_receiver(params: &str) -> bool {
        let mut p = params.trim_start();
        if let Some(rest) = p.strip_prefix('&') {
            p = rest.trim_start();
            if let Some(rest) = p.strip_prefix('\'') {
                p = rest
                    .trim_start_matches(|c: char| c.is_alphanumeric() || c == '_')
                    .trim_start();
            }
        }
        if let Some(rest) = p.strip_prefix("mut ") {
            p = rest.trim_start();
        }
        p.strip_prefix("self")
            .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
    }

    #[cfg(feature = "std")]
    #[test]
    fn has_receiver_reads_every_receiver_form() {
        for params in [
            "self) {",
            "mut self, ke3: &KE3) {",
            "&self) -> &[u8] {",
            "&mut self) {",
            "&'a self) {",
            "& 'a mut self) {",
            "self: Box<Self>) {",
        ] {
            assert!(has_receiver(params), "{params}");
        }
        for params in [
            "",
            ") -> usize {",
            "bytes: &[u8]) {",
            "selfish: u8) {",
            "self_key: &[u8]) {",
        ] {
            assert!(!has_receiver(params), "{params}");
        }
    }

    /// Every public function with no `self` receiver must call
    /// [`assert_lengths`] as its first statement, unless it is listed below as
    /// not generic over a ciphersuite.
    ///
    /// Each such function is an entry point in the sense that matters here: a
    /// downstream crate can call it with a suite of its own. The compile-time
    /// length checks only fire for a ciphersuite that is actually
    /// monomorphized through a function that calls them, so a function added
    /// later without the call would silently reopen the hole this module
    /// closes. Checking the source is crude, but it is the only thing that
    /// fails when someone forgets — a ciphersuite test cannot notice a call
    /// site that does not exist.
    ///
    /// It walks `src/` rather than naming three files. A hardcoded list is
    /// fail-open exactly where it matters: an entry point in a file added
    /// later is invisible, and because the missed site never increments the
    /// counter, the `checked` total below does not notice either.
    ///
    /// It finds entry points by shape, not by name. It used to look only for
    /// `pub fn new` and `pub fn start`, so an entry point under any other verb
    /// was invisible to it, and the `checked` total did not notice that
    /// either. Now every receiver-less `pub fn` either asserts or is a row of
    /// `NOT_GENERIC`, with the number of functions of that name in that file.
    /// A row is accepted only for a function that cannot be generic over a
    /// suite: a top-level `pub fn` (not in an `impl` block or a nested
    /// module) with no generic parameters, no `impl Trait` argument and no
    /// `OpaqueCiphersuite` in its signature. Anything else might take a
    /// suite, so it must call the checks. Until `0.6.2` the building blocks and the message parsers
    /// were rows too, and calling one directly skipped the checks. A new
    /// function fails here until it asserts or is listed; so does a table row
    /// that no longer matches. Methods are not scanned: they need a value,
    /// and the protocol states come only from entry points.
    #[cfg(feature = "std")]
    #[test]
    fn every_entry_point_asserts_lengths() {
        use crate::source_scan::rust_sources;
        use std::collections::BTreeMap;

        // Functions that take no ciphersuite, so have nothing to check:
        // (file, function, how many of that name the file has).
        const NOT_GENERIC: &[(&str, &str, usize)] = &[
            ("envelope.rs", "build_cleartext_credentials", 1),
            ("key_derivation.rs", "build_preamble", 1),
        ];

        let mut checked = 0;
        // (file, function) -> (how many do not assert, whether any of those
        // could be generic over a suite).
        let mut not_asserting: BTreeMap<(String, String), (usize, bool)> = BTreeMap::new();
        for (name, src) in rust_sources() {
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let Some(mut rest) = line.trim_start().strip_prefix("pub ") else {
                    continue;
                };
                while let Some(r) = ["const ", "async ", "unsafe "]
                    .iter()
                    .find_map(|q| rest.strip_prefix(q))
                {
                    rest = r;
                }
                let Some(rest) = rest.strip_prefix("fn ") else {
                    continue;
                };
                let func: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                // Collect the signature up to the line that opens the body.
                let mut j = i;
                let mut signature = String::new();
                while j < lines.len() {
                    signature.push_str(lines[j].trim());
                    signature.push(' ');
                    if lines[j].trim_end().ends_with('{') {
                        break;
                    }
                    j += 1;
                }
                let params = signature.split_once('(').map_or("", |(_, p)| p);
                if has_receiver(params) {
                    continue;
                }
                let first_stmt = lines.get(j + 1).map(|l| l.trim()).unwrap_or("");
                if first_stmt.contains("assert_lengths::<C>()") {
                    checked += 1;
                } else {
                    // Only a top-level function whose name is followed
                    // directly by its parameter list, and whose signature
                    // takes no `impl Trait` and names no suite, cannot be
                    // generic over one.
                    let exemptable = line.starts_with("pub ")
                        && rest[func.len()..].starts_with('(')
                        && !signature.contains("impl ")
                        && !signature.contains("OpaqueCiphersuite");
                    let entry = not_asserting
                        .entry((name.clone(), func))
                        .or_insert((0, false));
                    entry.0 += 1;
                    entry.1 |= !exemptable;
                }
            }
        }

        for ((file, func), (found, generic)) in &not_asserting {
            let row = NOT_GENERIC.iter().find(|(f, n, _)| f == file && n == func);
            let Some((_, _, listed)) = row else {
                panic!(
                    "{file}: `pub fn {func}` takes no `self` and does not call \
                     assert_lengths::<C>() as its first statement: make that its \
                     first statement, or list it in NOT_GENERIC if it takes no \
                     ciphersuite"
                );
            };
            assert!(
                !generic,
                "{file}: NOT_GENERIC lists `pub fn {func}`, but it is not a top-level \
                 function free of generics, so it could take a suite: it must call \
                 assert_lengths::<C>() first"
            );
            assert_eq!(
                found, listed,
                "{file}: NOT_GENERIC lists {listed} `pub fn {func}`, the file has \
                 {found} that do not assert: classify the difference"
            );
        }
        for (file, func, _) in NOT_GENERIC {
            assert!(
                not_asserting.contains_key(&(file.to_string(), func.to_string())),
                "NOT_GENERIC lists {file} `{func}`, which the file no longer has \
                 without the assert: drop the row"
            );
        }
        assert_eq!(checked, 30, "expected 30 entry points, found {checked}");
    }
}
