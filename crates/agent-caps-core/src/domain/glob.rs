//! The matcher behind [`super::name::GlobPattern`].
//!
//! The characters of a plain shell are read: `*` (any run of characters), `?` (any one character)
//! and a `[...]` class (`[!...]` or `[^...]` negates it). None of them takes a `/`, so a pattern
//! of a path matches part by part. A `**` that is a whole segment is the one way to reach across
//! parts: `**/` stands for zero or more directories and a `**` that ends the pattern for the rest
//! of the path; a `**` inside a segment is not a pattern, and [`Compiled::parse`] refuses it with
//! the byte where it starts. Case is kept: `Readme.md` is not `readme.md`. A `[` with no `]` to
//! close it is the character itself, as the shell takes it. There is no regex: a pattern is read
//! once into [`Compiled`], and matching is linear in the pattern times the text, with no
//! backtracking.

/// One element of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Star,
    Any,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
    Char(char),
    /// A `**/`: zero or more directories, the `/` after it taken with it.
    AnyDirs,
    /// A `**` that ends the pattern: the rest of the text, whatever it holds.
    Rest,
}

/// The class that starts after the `[` at the head of `rest`, and what follows it. `None` when
/// there is no `]` to close it.
fn class(rest: &[char]) -> Option<(Token, &[char])> {
    let (negated, body) = match rest.first() {
        Some('!' | '^') => (true, rest.get(1..)?),
        _ => (false, rest),
    };
    // A `]` right after the opening is a member, not the end.
    let close = body
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, c)| **c == ']')
        .map(|(at, _)| at)?;
    let members = body.get(..close)?;
    let mut ranges = Vec::new();
    let mut at = 0;
    while let Some(&low) = members.get(at) {
        match (members.get(at + 1), members.get(at + 2)) {
            (Some('-'), Some(&high)) => {
                ranges.push((low, high));
                at += 3;
            }
            _ => {
                ranges.push((low, low));
                at += 1;
            }
        }
    }
    Some((Token::Class { negated, ranges }, body.get(close + 1..)?))
}

/// The tokens of `pattern`, each with the byte where it starts. A `**` is still two `Star`s here.
fn tokens(pattern: &str) -> Vec<(usize, Token)> {
    let chars: Vec<char> = pattern.chars().collect();
    let starts: Vec<usize> = pattern.char_indices().map(|(at, _)| at).collect();
    let mut rest = chars.as_slice();
    let mut out = Vec::new();
    while let Some((&head, tail)) = rest.split_first() {
        let start = starts
            .get(chars.len() - rest.len())
            .copied()
            .unwrap_or_default();
        rest = tail;
        let token = match head {
            '*' => Token::Star,
            '?' => Token::Any,
            '[' => match class(tail) {
                Some((token, after)) => {
                    rest = after;
                    token
                }
                None => Token::Char('['),
            },
            other => Token::Char(other),
        };
        out.push((start, token));
    }
    out
}

/// A pattern read once, ready to match any number of texts.
#[derive(Debug, Clone)]
pub(super) struct Compiled(Vec<Token>);

impl Compiled {
    /// Reads `pattern`. A run of two `*` is a `**` when it is a whole segment (after the start or a
    /// `/`, before the end or a `/`); any other run of two or more is refused, as the byte where
    /// its first `*` stands. The `/` before a run is read on the tokens as they were read, so one
    /// taken by an earlier `**/` still counts: `a/**/**/b` is a pattern.
    pub(super) fn parse(pattern: &str) -> Result<Self, usize> {
        let read = tokens(pattern);
        let mut out = Vec::new();
        let mut at = 0;
        while let Some((start, token)) = read.get(at) {
            if *token != Token::Star {
                out.push(token.clone());
                at += 1;
                continue;
            }
            let mut end = at;
            while read.get(end).is_some_and(|(_, t)| *t == Token::Star) {
                end += 1;
            }
            if end - at == 1 {
                out.push(Token::Star);
            } else {
                let before_ok = at
                    .checked_sub(1)
                    .and_then(|prev| read.get(prev))
                    .is_none_or(|(_, t)| *t == Token::Char('/'));
                match (end - at, before_ok, read.get(end)) {
                    (2, true, None) => out.push(Token::Rest),
                    (2, true, Some((_, Token::Char('/')))) => {
                        out.push(Token::AnyDirs);
                        end += 1;
                    }
                    _ => return Err(*start),
                }
            }
            at = end;
        }
        Ok(Self(out))
    }

    /// Whether the pattern matches all of `text`.
    pub(super) fn matches(&self, text: &str) -> bool {
        let text: Vec<char> = text.chars().collect();
        // `reach[i]`: the tokens so far can have matched the first `i` characters of the text.
        let mut reach = vec![false; text.len() + 1];
        if let Some(start) = reach.first_mut() {
            *start = true;
        }
        // Two rows, swapped after each token, so a match allocates them once.
        let mut next = vec![false; text.len() + 1];
        for token in &self.0 {
            next.fill(false);
            match token {
                Token::Star => {
                    // A run of characters that are not `/`, the empty run too.
                    let mut open = false;
                    for (at, slot) in next.iter_mut().enumerate() {
                        let here = reach.get(at).copied().unwrap_or(false);
                        let carried = open && at > 0 && text.get(at - 1).is_some_and(|c| *c != '/');
                        open = here || carried;
                        *slot = open;
                    }
                }
                Token::AnyDirs => {
                    // From a reached position: that position, and every later one just after a `/`.
                    let mut open = false;
                    for (at, slot) in next.iter_mut().enumerate() {
                        let here = reach.get(at).copied().unwrap_or(false);
                        open = open || here;
                        let after_slash = at > 0 && text.get(at - 1).is_some_and(|c| *c == '/');
                        *slot = here || (open && after_slash);
                    }
                }
                Token::Rest => {
                    // From the first reached position: that position and everything after it.
                    let mut open = false;
                    for (at, slot) in next.iter_mut().enumerate() {
                        open = open || reach.get(at).copied().unwrap_or(false);
                        *slot = open;
                    }
                }
                _ => {
                    for (at, c) in text.iter().enumerate() {
                        if reach.get(at).copied().unwrap_or(false)
                            && token.takes(*c)
                            && let Some(slot) = next.get_mut(at + 1)
                        {
                            *slot = true;
                        }
                    }
                }
            }
            std::mem::swap(&mut reach, &mut next);
        }
        reach.last().copied().unwrap_or(false)
    }
}

impl Token {
    /// Whether the token takes the character `c`. Only a literal `/` takes a `/`.
    fn takes(&self, c: char) -> bool {
        match self {
            Self::Char(want) => *want == c,
            // Both are walked by `Compiled::matches` itself and take no one character.
            Self::AnyDirs | Self::Rest => false,
            _ if c == '/' => false,
            Self::Star | Self::Any => true,
            Self::Class { negated, ranges } => {
                let inside = ranges.iter().any(|(low, high)| (*low..=*high).contains(&c));
                inside != *negated
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Compiled, Token};

    fn matches(pattern: &str, text: &str) -> bool {
        Compiled::parse(pattern).unwrap().matches(text)
    }

    fn refused_at(pattern: &str) -> usize {
        Compiled::parse(pattern).unwrap_err()
    }

    #[test]
    fn a_pattern_matches_a_whole_text() {
        for (pattern, text) in [
            ("decided", "decided"),
            ("dec*", "decided"),
            ("*", "decided"),
            ("*", ""),
            ("*ed", "decided"),
            ("d*d", "decided"),
            ("d?cided", "decided"),
            ("[a-e]ecided", "decided"),
            ("[!x]ecided", "decided"),
            ("[^x]ecided", "decided"),
            ("[]]x", "]x"),
            ("a[b", "a[b"),
        ] {
            assert!(matches(pattern, text), "{pattern} / {text}");
        }
        for (pattern, text) in [
            ("dec", "decided"),
            ("dec?", "decided"),
            ("*.txt", "decided"),
            ("[x]ecided", "decided"),
            ("[!d]ecided", "decided"),
            ("d*x", "decided"),
            ("?", ""),
            ("Decided", "decided"),
        ] {
            assert!(!matches(pattern, text), "{pattern} / {text}");
        }
    }

    #[test]
    fn nothing_but_a_slash_takes_a_slash() {
        assert!(matches("src/*.rs", "src/main.rs"));
        assert!(!matches("src/*.rs", "src/a/b.rs"));
        assert!(!matches("src*", "src/main.rs"));
        assert!(!matches("a?b", "a/b"));
        assert!(!matches("a[!x]b", "a/b"));
        assert!(matches("*/*/c.md", "a/b/c.md"));
        assert!(matches("a/**/c.md", "a/b/x/c.md"));
        assert!(matches("a/**/c.md", "a/b/c.md"));
    }

    #[test]
    fn a_whole_segment_of_two_stars_is_a_pattern() {
        for pattern in [
            "**",
            "**/",
            "/**",
            "a/**",
            "**/a",
            "a/**/b",
            "a/**/**/b",
            "[**]",
        ] {
            assert!(Compiled::parse(pattern).is_ok(), "{pattern}");
        }
        // `a/**/**/b`: the second `**` still has a `/` before it, the one the first took.
        assert_eq!(
            Compiled::parse("a/**/**/b").unwrap().0,
            vec![
                Token::Char('a'),
                Token::Char('/'),
                Token::AnyDirs,
                Token::AnyDirs,
                Token::Char('b'),
            ]
        );
        // A class with a `*` in it is a class, not a run of stars.
        assert!(matches("[**]", "*"));
        assert!(!matches("[**]", "a"));
    }

    #[test]
    fn two_stars_inside_a_segment_are_refused_where_they_start() {
        assert_eq!(refused_at("***"), 0);
        assert_eq!(refused_at("a/**b"), 2);
        assert_eq!(refused_at("**a"), 0);
        assert_eq!(refused_at("a**"), 1);
        assert_eq!(refused_at("dec**ed"), 3);
        assert_eq!(refused_at("a/***/b"), 2);
        assert_eq!(refused_at("x/a**b/**/c"), 3);
        // The byte, not the character: `é` is two bytes.
        assert_eq!(refused_at("é**"), 2);
    }

    #[test]
    fn a_two_star_directory_reaches_any_depth() {
        for text in ["a/b", "a/x/b", "a/x/y/b"] {
            assert!(matches("a/**/b", text), "{text}");
        }
        for text in ["ab", "a/xb", "a/x/y", "b"] {
            assert!(!matches("a/**/b", text), "{text}");
        }
        for text in ["b", "x/b", "x/y/b"] {
            assert!(matches("**/b", text), "{text}");
        }
        assert!(!matches("**/b", "xb"));
        assert!(!matches("**/b", "x/yb"));
        // Two in a row mean what one does.
        assert!(matches("a/**/**/b", "a/b"));
        assert!(matches("a/**/**/b", "a/x/y/b"));
        // Ending in `**/`, the pattern ends on zero or more directories.
        assert!(matches("**/", ""));
        assert!(matches("**/", "x/"));
        assert!(!matches("**/", "x"));
    }

    #[test]
    fn a_two_star_ending_takes_the_rest() {
        for text in ["a/", "a/x", "a/x/y", "a/.hidden"] {
            assert!(matches("a/**", text), "{text}");
        }
        for text in ["a", "b/x", "ab/x"] {
            assert!(!matches("a/**", text), "{text}");
        }
        for text in ["", "x/y", "x"] {
            assert!(matches("**", text), "{text}");
        }
        assert!(matches("/**", "/x/y"));
        assert!(!matches("/**", "x/y"));
    }

    #[test]
    fn a_long_run_of_directories_does_not_back_off() {
        // Many `**/` over a text that cannot match must finish at once, not combine.
        let pattern = format!("{}b", "**/".repeat(40));
        let text = "a/".repeat(2000);
        assert!(!matches(&pattern, &text));
        assert!(matches(&pattern, &format!("{text}b")));
    }
}
