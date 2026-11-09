//! The values with a rule of their own that the rest of the domain refers to: the id and name of a
//! policy, a mode, the words of a command, a shell pattern and the reason of an exemption.
//!
//! Each is made only through its constructor, so a value of the type always keeps its rule.

use std::fmt;
use std::str::FromStr;

/// Why a text could not be read as one of the values of this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// A policy id that is not a UUID in its hyphenated form.
    PolicyId(String),
    /// A name (of a policy or a mode) that is empty or has a character other than an ASCII
    /// letter, a digit, `-` or `_`.
    Name(String),
    /// Command words that are none, or that have an empty word.
    Words,
    /// A reason that is empty or only white space.
    Reason,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyId(text) => write!(f, "`{text}` is not a hyphenated UUID"),
            Self::Name(text) => write!(
                f,
                "`{text}` is not a name: one or more ASCII letters, digits, `-` or `_`"
            ),
            Self::Words => f.write_str("command words need at least one word and no empty word"),
            Self::Reason => f.write_str("a reason cannot be empty"),
        }
    }
}

impl std::error::Error for NameError {}

/// The surrogate key of a policy. The policy graph that defines a policy gives it; the domain
/// never makes one, so it holds no source of randomness or time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyId(u128);

impl FromStr for PolicyId {
    type Err = NameError;

    /// Reads the hyphenated form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, in either case.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bad = || NameError::PolicyId(text.to_owned());
        let groups: Vec<&str> = text.split('-').collect();
        let fits = groups.len() == 5
            && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, len)| {
                group.len() == len && group.chars().all(|c| c.is_ascii_hexdigit())
            });
        if !fits {
            return Err(bad());
        }
        let hex: String = groups.concat();
        u128::from_str_radix(&hex, 16).map(Self).map_err(|_| bad())
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = format!("{:032x}", self.0);
        let part = |range: std::ops::Range<usize>| hex.get(range).unwrap_or_default();
        write!(
            f,
            "{}-{}-{}-{}-{}",
            part(0..8),
            part(8..12),
            part(12..16),
            part(16..20),
            part(20..32)
        )
    }
}

/// Whether `text` is a name: one or more ASCII letters, digits, `-` or `_`.
fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// The name of a policy, for the people who read a verdict. Two policies of a catalog never
/// share one; the id, not the name, is what other values refer to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyName(String);

impl FromStr for PolicyName {
    type Err = NameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if is_name(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(NameError::Name(text.to_owned()))
        }
    }
}

impl fmt::Display for PolicyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A way of working (`bug-fix`, `explore`, `modeling`). One mode is in effect at a time; its
/// overrides change the level of the policies, or turn them on or off.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mode(String);

impl FromStr for Mode {
    type Err = NameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if is_name(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(NameError::Name(text.to_owned()))
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A command as its words, the program first. A command is compared word by word, never as one
/// string, so quoting and spacing cannot make one command look like another.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandWords(Vec<String>);

impl CommandWords {
    /// The words, when there is at least one and none is empty.
    pub fn new(words: Vec<String>) -> Result<Self, NameError> {
        if words.is_empty() || words.iter().any(String::is_empty) {
            return Err(NameError::Words);
        }
        Ok(Self(words))
    }

    /// The words, the program first.
    pub fn words(&self) -> &[String] {
        &self.0
    }

    /// Whether `self` starts with all of `prefix`'s words, in order: `cargo test -p a` starts
    /// with `cargo test`.
    pub fn starts_with(&self, prefix: &CommandWords) -> bool {
        self.0.starts_with(&prefix.0)
    }
}

/// A shell pattern of the three characters of a plain shell (`*`, `?`, a `[...]` class). It
/// matches a text as a whole, and no part of it takes a `/`, so `src/*.rs` does not match
/// `src/a/b.rs`. Any text is a pattern: a `[` with no `]` stands for itself, as in the shell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlobPattern(String);

impl GlobPattern {
    /// The pattern of `text`.
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// Whether the pattern matches all of `text`.
    pub fn matches(&self, text: &str) -> bool {
        super::glob::matches(&self.0, text)
    }
}

/// Why someone made an exemption. It is required, so the exemptions of a guard can be counted
/// by their reason and a guard that is too strong can be told from one that was overlooked.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reason(String);

impl FromStr for Reason {
    type Err = NameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.trim().is_empty() {
            Err(NameError::Reason)
        } else {
            Ok(Self(text.to_owned()))
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_id_reads_and_writes_the_hyphenated_form() {
        let text = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let id: PolicyId = text.parse().unwrap();
        assert_eq!(id.to_string(), text);
        let upper: PolicyId = text.to_uppercase().parse().unwrap();
        assert_eq!(upper, id);
        for bad in [
            "",
            "0190a1b2c3d47e5f8a9b0c1d2e3f4a5b",
            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5",
            "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5g",
            "+190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
        ] {
            assert!(bad.parse::<PolicyId>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_name_is_letters_digits_dash_and_underscore() {
        for good in ["bug-fix", "a_b", "Modeling2"] {
            assert!(good.parse::<Mode>().is_ok(), "{good}");
            assert!(good.parse::<PolicyName>().is_ok(), "{good}");
        }
        for bad in ["", "a b", "a.b", "日本"] {
            assert!(bad.parse::<Mode>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn command_words_compare_word_by_word() {
        let words = |text: &str| {
            CommandWords::new(text.split_whitespace().map(str::to_owned).collect()).unwrap()
        };
        assert!(words("cargo test -p a").starts_with(&words("cargo test")));
        assert!(!words("cargo testing").starts_with(&words("cargo test")));
        assert!(!words("cargo").starts_with(&words("cargo test")));
        assert!(CommandWords::new(vec![]).is_err());
        assert!(CommandWords::new(vec!["a".to_owned(), String::new()]).is_err());
    }

    #[test]
    fn a_reason_is_not_blank() {
        assert!("too strong here".parse::<Reason>().is_ok());
        assert!(" ".parse::<Reason>().is_err());
    }
}
