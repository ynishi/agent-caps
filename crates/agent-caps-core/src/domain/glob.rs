//! The matcher behind [`super::name::GlobPattern`].
//!
//! Only the three characters of a plain shell are read: `*` (any run of characters), `?` (any
//! one character) and a `[...]` class (`[!...]` or `[^...]` negates it). No token takes a `/`, so
//! a pattern of a path matches part by part, and there is no `**`. Case is kept: `Readme.md` is
//! not `readme.md`. A `[` with no `]` to close it is the character itself, as the shell takes it.
//! There is no regex: matching is linear in the pattern times the text, with no backtracking.

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

fn tokens(pattern: &str) -> Vec<Token> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut rest = chars.as_slice();
    let mut out = Vec::new();
    while let Some((&head, tail)) = rest.split_first() {
        rest = tail;
        out.push(match head {
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
        });
    }
    out
}

impl Token {
    /// Whether the token takes the character `c`. Only a literal `/` takes a `/`.
    fn takes(&self, c: char) -> bool {
        match self {
            Self::Char(want) => *want == c,
            _ if c == '/' => false,
            Self::Star | Self::Any => true,
            Self::Class { negated, ranges } => {
                let inside = ranges.iter().any(|(low, high)| (*low..=*high).contains(&c));
                inside != *negated
            }
        }
    }
}

/// Whether `pattern` matches all of `text`.
pub(super) fn matches(pattern: &str, text: &str) -> bool {
    let text: Vec<char> = text.chars().collect();
    // `reach[i]`: the tokens so far can have matched the first `i` characters of the text.
    let mut reach = vec![false; text.len() + 1];
    if let Some(start) = reach.first_mut() {
        *start = true;
    }
    for token in tokens(pattern) {
        let mut next = vec![false; text.len() + 1];
        if token == Token::Star {
            // A run of characters that are not `/`, the empty run too.
            let mut open = false;
            for (at, slot) in next.iter_mut().enumerate() {
                let here = reach.get(at).copied().unwrap_or(false);
                let carried = open && at > 0 && text.get(at - 1).is_some_and(|c| *c != '/');
                open = here || carried;
                *slot = open;
            }
        } else {
            for (at, c) in text.iter().enumerate() {
                if reach.get(at).copied().unwrap_or(false)
                    && token.takes(*c)
                    && let Some(slot) = next.get_mut(at + 1)
                {
                    *slot = true;
                }
            }
        }
        reach = next;
    }
    reach.last().copied().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::matches;

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
            ("dec**ed", "decided"),
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
        assert!(!matches("a/**/c.md", "a/b/x/c.md"));
        assert!(matches("a/**/c.md", "a/b/c.md"));
    }
}
