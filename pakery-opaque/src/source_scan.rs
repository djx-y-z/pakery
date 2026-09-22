//! Test-only helper for the two structural guards in this crate.
//!
//! `every_entry_point_asserts_lengths` and
//! `the_only_ksf_stretch_call_is_followed_by_the_length_check` both assert a
//! property of *where* something is written rather than of what it computes,
//! so both have to read the crate's own source. Both previously did it with a
//! hardcoded list of `include_str!` calls, which is fail-open in the one
//! direction that matters: a file added later is not on the list, so a call
//! site inside it is invisible and the guard still passes.
//!
//! The walk **recurses**. A non-recursive `read_dir` reproduces the same
//! fail-open one level up — a call site in `src/<subdir>/<file>.rs` is
//! invisible, and a file-count assertion does not notice, because the number
//! of `.rs` files directly under `src/` is unchanged. That was measured, not
//! reasoned about: the guard reported `ok` on a tree containing a second
//! unguarded stretch call in a subdirectory. `pakery-core/src/crypto/` shows
//! the shape is one this workspace already uses.
//!
//! This needs `std`, which `cargo test` has by default. Under
//! `--no-default-features` the guards compile out; CI only ever runs
//! `cargo check` there, which does not build `#[cfg(test)]` code at all, so
//! nothing is lost that was previously covered.
//!
//! # What this cannot catch
//!
//! Matching source text is a backstop, not the control. The guards look for a
//! literal call spelled a particular way, so a local alias — `type K =
//! C::Ksf;` and then a call through `K` — is invisible to them, and no amount
//! of normalizing fixes that in general. The control is the runtime check in
//! `derive_randomized_password`, which is tied to the bytes and cannot be
//! spelled around; these guards exist to catch the ordinary way the property
//! gets lost, which is someone adding a second call site without the check.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Every `.rs` file under this crate's `src/`, at any depth, as
/// `(path relative to src/, contents)`.
///
/// Panics rather than returning an error: a test that cannot read the source
/// it is supposed to be guarding has failed, not been skipped.
pub(crate) fn rust_sources() -> Vec<(String, String)> {
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut out = Vec::new();
    let mut dirs = Vec::new();
    dirs.push(root.to_path_buf());

    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("every directory under src/ must be readable") {
            let path = entry.expect("readable directory entry").path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // Relative to `src/`, so a nested file is reported as
            // `sub/file.rs` and cannot be confused with a top-level namesake.
            let name = path
                .strip_prefix(root)
                .expect("walked from root")
                .to_string_lossy()
                .to_string();
            let src = std::fs::read_to_string(&path).expect("readable source file");
            out.push((name, src));
        }
    }

    // Sorted so a failure message names the same file run to run.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(
        out.len() >= 11,
        "expected to scan the whole crate, saw {} file(s) at any depth",
        out.len()
    );
    out
}

/// `line` with all whitespace removed.
///
/// The guards match on a literal substring naming a trait method call, which
/// an extra space before the parenthesis or around the `::` would otherwise
/// slip past — verified: both variants were invisible to the first matcher
/// written for this.
pub(crate) fn squash(line: &str) -> String {
    line.chars().filter(|c| !c.is_whitespace()).collect()
}
