//! Test-only helper for the two structural guards in this crate.
//!
//! `every_entry_point_asserts_lengths` and
//! `the_only_ksf_stretch_call_is_followed_by_the_length_check` both assert a
//! property of *where* something is written rather than of what it computes,
//! so both have to read the crate's own source. Both previously did it with a
//! hardcoded list of `include_str!` calls, which is fail-open in the one
//! direction that matters: a file added later is not on the list, so a call
//! site inside it is invisible and the guard still passes. Walking `src/`
//! cannot rot that way.
//!
//! This needs `std`, which `cargo test` has by default. Under
//! `--no-default-features` the guards compile out; CI only ever runs
//! `cargo check` there, which does not build `#[cfg(test)]` code at all, so
//! nothing is lost that was previously covered.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Every `.rs` file directly under this crate's `src/`, as `(name, contents)`.
///
/// Panics rather than returning an error: a test that cannot read the source
/// it is supposed to be guarding has failed, not been skipped.
pub(crate) fn rust_sources() -> Vec<(String, String)> {
    let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("src/ must be readable") {
        let path = entry.expect("readable directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .expect("a directory entry has a file name")
            .to_string_lossy()
            .to_string();
        let src = std::fs::read_to_string(&path).expect("readable source file");
        out.push((name, src));
    }
    assert!(
        out.len() >= 11,
        "expected to scan the whole crate, saw {} file(s)",
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
