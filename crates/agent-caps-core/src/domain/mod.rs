//! The model of caps: policies, the events they judge, and the state folded from those events.
//!
//! Pure: nothing here touches the file system, a process, the environment, the network, the
//! clock or a random source. Times and ids come in as values; the transcript and the evidence
//! come in as [`event::Event`] values that a platform adapter and the caller have read.
//!
//! ```text
//! PolicyGraph ─ Catalog::accept ─▶ Catalog    (type check, slots, fixtures)
//! events ─ Catalog::fold / apply ─▶ State      (mode, one slot per temporal operator, exemptions)
//! Catalog::effective(mode) ─▶ Effective        (every policy On(level) or Off, Degraded)
//! judge(&Catalog, &State, &Event) ─▶ Outcome   (Verdict, Recognitions, Degraded; reads Effective)
//! Outcome::evidence ─▶ Judged events           (appended by the caller, folded like any other)
//! ```
//!
//! Dependencies between the modules run one way: `name`, `schema` and `authority` ◀ `predicate`
//! ◀ `exempt` ◀ `event` ◀ `state` ◀ `policy` ◀ `catalog` ◀ `judge` and `change`. `authority`
//! knows nothing of the others, and `arch-lint.toml` keeps it so.
//!
//! # Glossary
//!
//! - Policy: the one part of a catalog. A guard says what must hold, a reward what is
//!   recommended within a guard, each at a [`policy::Level`].
//! - Catalog: the accepted set of policies with their layers ([`catalog`]).
//! - Principal and authority: who wrote a policy, and the hierarchy that says whose work whom
//!   may loosen ([`authority`]); a change of a catalog is judged by it ([`change`]).
//! - Evidence: what caps appends (judgments, mode switches, exemptions, scores). With the
//!   platform's transcript, it is what the state is folded from.
//! - Slot: what one temporal operator (`once`, `count`, `last`) remembers between events.
//! - Unknown: what could not be seen. A stopping guard that cannot tell denies.

pub mod authority;
pub mod catalog;
pub mod change;
pub mod event;
pub mod exempt;
mod glob;
pub mod judge;
pub mod name;
pub mod policy;
pub mod predicate;
pub mod schema;
pub mod state;

#[cfg(test)]
mod tests;
