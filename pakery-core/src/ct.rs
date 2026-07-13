//! Constant-time verification helpers (ctgrind pattern).
//!
//! These helpers wire secret material into Valgrind memcheck's definedness
//! tracking, following the classic ctgrind idea (as used by graviola, aws-lc,
//! and NSS): memory holding secrets is marked *undefined*, so any
//! secret-dependent branch or memory index in the compiled artifact surfaces
//! as a memcheck error when the test harness runs under
//! `valgrind --track-origins=yes --error-exitcode=99`.
//!
//! Without the private `__ctgrind` cargo feature every function here compiles
//! to a no-op; with it, they emit Valgrind client requests via [`crabgrind`]
//! (a safe API — compatible with `#![forbid(unsafe_code)]`). The feature is
//! internal to pakery's CI (`ct.yml`) and must never be enabled in production
//! builds — the double-underscore prefix marks it exempt from semver.
//!
//! # Marking policy
//!
//! Marked secret at their byte boundaries: passwords, scalar/private-key
//! bytes, DH outputs, OPRF outputs, PRKs and derived keys, envelope contents.
//!
//! Declassified (each call site carries a justification comment):
//! - public-key and key-share encodings before wire serialization — public
//!   by protocol design;
//! - MAC tags before wire output — public once sent;
//! - ciphertext (e.g. OPAQUE `masked_response`) before wire output;
//! - boolean accept/reject decisions after a `subtle::ct_eq` comparison
//!   ([`declassify_choice`]) — the abort/continue outcome is public;
//! - copies of secret-scalar encodings fed to `curve25519-dalek` /
//!   `p256` deserializers ([`declassify`] on a temporary copy): their
//!   canonicity checks branch on a `subtle::CtOption` discriminant, which
//!   memcheck would flag inside the dependency. Canonicity of an honestly
//!   generated key is public information, and constant-time verification of
//!   dependency-internal primitives is out of scope here (tracked upstream;
//!   see SECURITY_TESTING.md, "Constant-time verification"). Where a parse is laundered
//!   this way, the *result* of the following group operation is re-marked
//!   secret so taint stays end-to-end.

/// Whether the helpers emit real Valgrind client requests.
///
/// True only when the `__ctgrind` feature is on **and** crabgrind was built
/// against real Valgrind headers. Without headers (e.g. a `--all-features`
/// build on macOS or a runner without Valgrind installed) crabgrind falls
/// back to stub headers whose version is the sentinel `0xBEDABEDA`, and
/// every client request would panic at runtime — so the helpers downgrade
/// to no-ops instead. `ct.yml` asserts this returns true (via the harness's
/// `ct_harness_is_armed` test) to rule out a silently disarmed run.
#[inline(always)]
#[must_use]
pub fn is_active() -> bool {
    #[cfg(feature = "__ctgrind")]
    {
        crabgrind::VALGRIND_VERSION.0 != 0xBEDA_BEDA
    }
    #[cfg(not(feature = "__ctgrind"))]
    false
}

/// Mark `bytes` as secret: Valgrind memcheck treats them as undefined, so any
/// branch or memory index computed from them is reported as an error.
///
/// No-op unless the `__ctgrind` feature is enabled (and, at runtime, the
/// process runs under Valgrind).
#[inline(always)]
pub fn mark_secret(bytes: &[u8]) {
    #[cfg(feature = "__ctgrind")]
    if is_active() {
        let _ = crabgrind::memcheck::mark_memory(
            bytes.as_ptr().cast(),
            bytes.len(),
            crabgrind::memcheck::MemState::Undefined,
        );
    }
    #[cfg(not(feature = "__ctgrind"))]
    let _ = bytes;
}

/// Declassify `bytes`: mark them as defined (public) for Valgrind memcheck.
///
/// Use only at boundaries where the data is genuinely public (wire output,
/// public-key encodings, MAC tags being sent) — every call site must carry a
/// justification comment. No-op unless the `__ctgrind` feature is enabled.
#[inline(always)]
pub fn declassify(bytes: &[u8]) {
    #[cfg(feature = "__ctgrind")]
    if is_active() {
        let _ = crabgrind::memcheck::mark_memory(
            bytes.as_ptr().cast(),
            bytes.len(),
            crabgrind::memcheck::MemState::Defined,
        );
    }
    #[cfg(not(feature = "__ctgrind"))]
    let _ = bytes;
}

/// Declassify the boolean outcome of a constant-time comparison.
///
/// The accept/reject decision after a `ct_eq` (MAC verification,
/// identity-point rejection, shared-secret equality) is public: the protocol
/// visibly aborts or continues. Converting `Choice → bool` directly would
/// branch on secret-derived data (memcheck flags both the caller's `if` and
/// `subtle`'s internal `debug_assert!`), so the decision byte is copied to
/// the stack, declassified, and only then read.
#[inline(always)]
pub fn declassify_choice(choice: subtle::Choice) -> bool {
    let mut byte = [choice.unwrap_u8()];
    declassify(&byte);
    // In release builds LLVM may keep the pre-declassify value in a register
    // (`declassify` only takes a shared reference, so the memory is assumed
    // unmodified across the call) and branch on that still-tainted copy.
    // Routing the array through an opaque identity forces the branch below
    // to re-read the now-defined memory.
    let byte = core::hint::black_box(&mut byte);
    byte[0] != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Outside Valgrind these are behavioral no-ops; the tests pin that the
    // helpers never alter values or crash, with and without `__ctgrind`.
    #[test]
    fn helpers_preserve_values() {
        let data = [1u8, 2, 3];
        mark_secret(&data);
        declassify(&data);
        assert_eq!(data, [1, 2, 3]);

        assert!(declassify_choice(subtle::Choice::from(1)));
        assert!(!declassify_choice(subtle::Choice::from(0)));
    }

    #[test]
    fn helpers_accept_empty_slices() {
        mark_secret(&[]);
        declassify(&[]);
    }
}
