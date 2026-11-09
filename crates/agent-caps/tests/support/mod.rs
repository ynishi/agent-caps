//! What the integration tests of this crate share: where the workspace is, and reading a file of it.
//!
//! Each file in `tests/` is a crate of its own, so only what every one of them uses belongs here;
//! an item that one of them leaves unused would fail the build as dead code.

use std::fs;
use std::path::{Path, PathBuf};

/// The workspace root: two levels above this crate's manifest.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits at crates/<name> under the workspace root")
        .to_path_buf()
}

/// The text of a file, which must be readable.
pub fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("{} is readable: {e}", path.display()))
}
