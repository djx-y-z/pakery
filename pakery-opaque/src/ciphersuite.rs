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
/// with its own primitives fails to build. Before `0.5.0` nothing performed
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
/// Called from every public entry point that takes a `C: OpaqueCiphersuite`,
/// so the check runs when the suite is monomorphized. A mismatch is a build
/// error naming the offending constant, not a silent change to the wire
/// format.
///
/// These are post-monomorphization const evaluations, so they fire on
/// `cargo build` and `cargo test` — which is where CI catches them — but not
/// on `cargo check`, which stops before codegen. A downstream crate sees the
/// error when it builds its own call to any entry point below.
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
    9
}

#[cfg(test)]
mod tests {
    use super::assert_lengths;
    use crate::test_mocks::MockSuite;

    /// `assert_lengths` must still contain its nine checks.
    ///
    /// The assertions themselves are invisible to a runtime test — for a
    /// correct suite they compile to nothing. Without this, `cargo-mutants`
    /// replaces the whole body and every test still passes: measured on
    /// `21db5c5`, gutting the body left all 354 tests green *and* let a suite
    /// declaring `NH = 32` against a SHA-512 hash build cleanly. The returned
    /// count is what makes emptying the body observable.
    #[test]
    fn assert_lengths_checks_all_nine_invariants() {
        assert_eq!(assert_lengths::<MockSuite>(), 9);
    }

    /// Every public constructor and `start` entry point must call
    /// [`assert_lengths`] as its first statement.
    ///
    /// The compile-time length checks only fire for a ciphersuite that is
    /// actually monomorphized through one of these functions, so an entry
    /// point added later without the call would silently reopen the hole this
    /// module closes. Checking the source is crude, but it is the only thing
    /// that fails when someone forgets — a ciphersuite test cannot notice a
    /// call site that does not exist.
    #[test]
    fn every_entry_point_asserts_lengths() {
        const SOURCES: [(&str, &str); 3] = [
            ("server_setup.rs", include_str!("server_setup.rs")),
            ("registration.rs", include_str!("registration.rs")),
            ("login.rs", include_str!("login.rs")),
        ];

        let mut checked = 0;
        for (name, src) in SOURCES {
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let sig = line.trim_start();
                if !(sig.starts_with("pub fn new") || sig.starts_with("pub fn start")) {
                    continue;
                }
                // Walk forward to the line that opens the body.
                let mut j = i;
                while j < lines.len() && !lines[j].trim_end().ends_with('{') {
                    j += 1;
                }
                let first_stmt = lines.get(j + 1).map(|l| l.trim()).unwrap_or("");
                assert!(
                    first_stmt.contains("assert_lengths::<C>()"),
                    "{name}: `{sig}` must call assert_lengths::<C>() as its first \
                     statement, found `{first_stmt}`"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 9, "expected 9 entry points, found {checked}");
    }
}
