//! The values with a rule of their own that the rest of the domain refers to: the id and name of a
//! policy, the id of a binding and of a temporary adjustment, a mode, a meter, the name of a
//! classifier, the words of a command, a shell pattern and the reason of an adjustment.
//!
//! Each is made only through its constructor, so a value of the type always keeps its rule.

use std::fmt;
use std::str::FromStr;

/// Why a text could not be read as one of the values of this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// A policy id that is not a UUID in its hyphenated form.
    PolicyId(String),
    /// A binding id that is not a UUID in its hyphenated form.
    BindingId(String),
    /// An adjustment id that is not a UUID in its hyphenated form.
    AdjustmentId(String),
    /// A set id that is not a UUID in its hyphenated form.
    SetId(String),
    /// A name (of a policy, a mode, a meter or a set of policies) that is empty or has a character
    /// other than an ASCII letter, a digit, `-` or `_`.
    Name(String),
    /// A classifier name that is empty or has a character other than an ASCII letter, a digit,
    /// `-`, `_` or `@`.
    Classifier(String),
    /// Command words that are none, or that have an empty word.
    Words,
    /// A reason that is empty or only white space.
    Reason,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyId(text)
            | Self::BindingId(text)
            | Self::AdjustmentId(text)
            | Self::SetId(text) => {
                write!(f, "`{text}` is not a hyphenated UUID")
            }
            Self::Name(text) => write!(
                f,
                "`{text}` is not a name: one or more ASCII letters, digits, `-` or `_`"
            ),
            Self::Classifier(text) => write!(
                f,
                "`{text}` is not a classifier name: one or more ASCII letters, digits, `-`, `_` or `@`"
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
        parse_uuid(text)
            .map(Self)
            .ok_or_else(|| NameError::PolicyId(text.to_owned()))
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_uuid(f, self.0)
    }
}

/// The surrogate key of a binding, unique in a catalog. The policy graph gives it, as it gives the
/// id of a policy, so a change of a catalog can tell a binding kept from one removed or new. It is
/// no handle to replace a binding by: two sets of policies with a binding of one id hold the same
/// binding or conflict ([`super::set`]), and a binding of one set is changed only by a new version
/// of that set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingId(u128);

impl FromStr for BindingId {
    type Err = NameError;

    /// Reads the hyphenated form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, in either case.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_uuid(text)
            .map(Self)
            .ok_or_else(|| NameError::BindingId(text.to_owned()))
    }
}

impl fmt::Display for BindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_uuid(f, self.0)
    }
}

/// The surrogate key of a temporary adjustment, unique among the adjustments in effect. The one who
/// makes the adjustment gives it, so a later claim can cancel that adjustment and no other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdjustmentId(u128);

impl FromStr for AdjustmentId {
    type Err = NameError;

    /// Reads the hyphenated form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, in either case.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_uuid(text)
            .map(Self)
            .ok_or_else(|| NameError::AdjustmentId(text.to_owned()))
    }
}

impl fmt::Display for AdjustmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_uuid(f, self.0)
    }
}

/// The value of the hyphenated form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, in either case. The
/// one form of every surrogate key, the id of a set of policies ([`super::set::SetId`]) included.
pub(super) fn parse_uuid(text: &str) -> Option<u128> {
    let groups: Vec<&str> = text.split('-').collect();
    let fits = groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.chars().all(|c| c.is_ascii_hexdigit()));
    if !fits {
        return None;
    }
    u128::from_str_radix(&groups.concat(), 16).ok()
}

/// Writes `value` in the hyphenated form, in lower case.
pub(super) fn write_uuid(f: &mut fmt::Formatter<'_>, value: u128) -> fmt::Result {
    let hex = format!("{value:032x}");
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

/// Whether `text` is a name: one or more ASCII letters, digits, `-` or `_`. The one rule of a name,
/// read by the id of a set of policies ([`super::set::SetId`]) too.
pub(super) fn is_name(text: &str) -> bool {
    !text.is_empty() && text.chars().all(is_name_char)
}

/// A character a name may hold: an ASCII letter, a digit, `-` or `_`.
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_')
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

/// A way of working (`bug-fix`, `explore`, `modeling`). One mode is in effect at a time; a
/// binding may hold only inside a mode, or only outside some, so the mode decides which bindings
/// take effect.
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

/// What a platform measures as used (`tokens`, `cost-usd`): the meter of a
/// [`Body::Used`](super::event::Body::Used) and of a
/// [`Pred::Spent`](super::predicate::Pred::Spent). A rule reads it as text
/// ([`Field::Meter`](super::schema::Field::Meter)), the same text it holds, so whether two meters
/// are the same is one comparison of that text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Meter(String);

impl Meter {
    /// The name as text: what [`Field::Meter`](super::schema::Field::Meter) reads.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Meter {
    type Err = NameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if is_name(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(NameError::Name(text.to_owned()))
        }
    }
}

impl fmt::Display for Meter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of a classifier, with its version in the text (`commit-why@3`): the judge of a rule that
/// code cannot express ([`Classifier`](super::policy::Classifier)). A new version of the judge is
/// another name, so another classifier, declared and calibrated on its own. A rule reads it as
/// text ([`Field::Classifier`](super::schema::Field::Classifier)), the same text it holds, so
/// whether two names are the same is one comparison of that text.
///
/// It is a name (ASCII letters, digits, `-` and `_`) that may also hold `@`, which sets the version
/// apart by convention and carries no meaning of its own.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassifierName(String);

impl ClassifierName {
    /// The name as text: what [`Field::Classifier`](super::schema::Field::Classifier) reads.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ClassifierName {
    type Err = NameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if !text.is_empty() && text.chars().all(|c| is_name_char(c) || c == '@') {
            Ok(Self(text.to_owned()))
        } else {
            Err(NameError::Classifier(text.to_owned()))
        }
    }
}

impl fmt::Display for ClassifierName {
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
            assert!(bad.parse::<Meter>().is_err(), "{bad:?}");
        }
        let tokens: Meter = "tokens".parse().unwrap();
        assert_eq!(tokens.as_str(), "tokens");
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
