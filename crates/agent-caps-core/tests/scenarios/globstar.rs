//! Scenario: a path pattern that reaches any depth. A `**` that is a whole segment matches zero or
//! more directories (`**/`) or the rest of the path (a `**` that ends the pattern), so one rule
//! covers a tree whatever its depth. A `**` inside a segment is not a pattern: it is refused when
//! the pattern is made, so a rule never means silently less than it reads.
//!
//! The domain has no file system; a path is the text the caller gives, and a pattern is read once
//! when it is made.

use agent_caps_core::domain::judge::Verdict;
use agent_caps_core::domain::name::{GlobPattern, NameError};
use agent_caps_core::domain::policy::{DefLayer, Expect, Level, Polarity, PolicyDef, Rule};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred};
use agent_caps_core::domain::schema::{EventKind, Field};

use super::common::{
    GUARD, Written, catalog, edit, fixture, id, the_user, verdict, violated, written,
};

/// Force: no edit of a path that `pattern` matches.
fn no_edit_of(pattern: &str) -> Written {
    let def = PolicyDef {
        id: id(GUARD),
        name: "no-edit-there".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: Some(Pred::Now(Cond::Eq(
            Field::Tool,
            Lit::Text("Edit".to_owned()),
        ))),
        rule: Rule::Structural(Pred::Not(Box::new(Pred::Now(Cond::Glob(
            Field::Path,
            GlobPattern::new(pattern).unwrap(),
        ))))),
        polarity: Polarity::Guard,
        fixtures: vec![
            fixture(
                "an edit of a path it matches",
                vec![edit("a/b/c.md")],
                Expect::Violated,
            ),
            fixture(
                "an edit of a path it does not",
                vec![edit("z.md")],
                Expect::Satisfied,
            ),
        ],
        author: the_user(),
    };
    written(def, Level::Force)
}

/// FR58: a `**` that is a whole segment reaches any depth: `a/**/c.md` covers `a/c.md` and every
/// deeper path under `a/`, and `a/**` everything under `a/`.
#[test]
fn a_whole_segment_of_two_stars_reaches_any_depth() {
    let between = catalog(vec![no_edit_of("a/**/c.md")], vec![]);
    for path in ["a/c.md", "a/b/c.md", "a/b/x/y/c.md"] {
        assert_eq!(verdict(&between, &[edit(path)]), violated(), "{path}");
    }
    for path in ["a/c.mdx", "b/c.md", "a/b/d.md"] {
        assert_eq!(verdict(&between, &[edit(path)]), Verdict::Allow, "{path}");
    }

    let under = catalog(vec![no_edit_of("a/**")], vec![]);
    for path in ["a/c.md", "a/b/c.md", "a/b/x/y/c.md"] {
        assert_eq!(verdict(&under, &[edit(path)]), violated(), "{path}");
    }
    for path in ["a", "ab/c.md", "b/a/c.md"] {
        assert_eq!(verdict(&under, &[edit(path)]), Verdict::Allow, "{path}");
    }
}

/// FR58: a `**` inside a segment is refused when the pattern is made, with the pattern and the byte
/// where the `**` starts; it is not read as a `*`.
#[test]
fn two_stars_inside_a_segment_are_refused() {
    for (text, at) in [("a**b", 1), ("**.rs", 0), ("src/**x", 4), ("***", 0)] {
        assert_eq!(
            GlobPattern::new(text),
            Err(NameError::Glob {
                text: text.to_owned(),
                at,
            }),
            "{text}"
        );
    }
    let error = GlobPattern::new("a**b").unwrap_err();
    assert_eq!(
        error.to_string(),
        "`a**b`: a `**` must be a whole segment (byte 1)"
    );
}
