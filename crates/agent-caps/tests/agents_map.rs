//! The map in `AGENTS.md` reaches every root document in one step, and points at nothing that is
//! not there.
//!
//! An agent reads only what it can reach from the entry it read first, and a map stays right only
//! while whoever adds a document remembers to add it. This test does the remembering: it fails
//! when a relative link of the map names a file that does not exist, and when a document at the
//! root (a `*.md` file, the `Justfile`, `arch-lint.toml`) is not linked from the map. It checks
//! where links lead, not how the documents are written.

mod support;

use std::collections::BTreeSet;
use std::fs;

use support::{read, root};

/// The targets of the Markdown links `[text](target)` in `text`, without their `#anchor`.
fn link_targets(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("](") {
        let after = &rest[start + 2..];
        let Some(end) = after.find(')') else { break };
        let target = &after[..end];
        let path = target.split('#').next().unwrap_or_default();
        if !path.is_empty() {
            targets.push(path.to_owned());
        }
        rest = &after[end..];
    }
    targets
}

/// Whether a link target is a file of this repository rather than a page elsewhere.
fn is_local(target: &str) -> bool {
    !target.contains("://") && !target.starts_with("mailto:")
}

#[test]
fn every_link_of_the_map_points_at_a_file_that_exists() {
    let root = root();
    let map = read(&root.join("AGENTS.md"));
    let broken: Vec<String> = link_targets(&map)
        .into_iter()
        .filter(|t| is_local(t))
        .filter(|t| !root.join(t).exists())
        .collect();
    assert!(
        broken.is_empty(),
        "AGENTS.md links to missing files: {broken:?}"
    );
}

#[test]
fn every_root_document_is_on_the_map() {
    let root = root();
    let map = read(&root.join("AGENTS.md"));
    let linked: BTreeSet<String> = link_targets(&map)
        .into_iter()
        .filter(|t| is_local(t))
        .collect();
    let documents: BTreeSet<String> = fs::read_dir(&root)
        .expect("the workspace root is readable")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name != "AGENTS.md")
        .filter(|name| {
            name.ends_with(".md") && !name.starts_with("CLAUDE")
                || name == "Justfile"
                || name == "arch-lint.toml"
        })
        .collect();
    let missing: Vec<&String> = documents.difference(&linked).collect();
    assert!(
        missing.is_empty(),
        "AGENTS.md does not link to: {missing:?}"
    );
}

#[test]
fn links_are_read_with_their_anchor_cut_off() {
    let text = "a [x](A.md) b [y](B.md#part) c [z](https://example.org/x) [w](#local)";
    assert_eq!(
        link_targets(text),
        vec!["A.md", "B.md", "https://example.org/x"]
    );
    assert!(!is_local("https://example.org/x"));
}
