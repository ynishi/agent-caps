//! The model of caps: policies, the events they judge, and the state folded from those events.
//!
//! Pure: nothing here touches the file system, a process, the environment, the network, the
//! clock or a random source. Times and ids come in as values; the transcript and the evidence
//! come in as [`event::Event`] values that a platform adapter and the caller have read, each by
//! a [`authority::Principal`].
//!
//! ```text
//! PolicyGraph ─ Catalog::accept ─▶ Catalog    (structure, what each policy reads, fixtures)
//! events ─ Catalog::fold / apply ─▶ State      (an act is folded; a claim is a transaction)
//! Catalog::effective(mode) ─▶ Effective        (every policy On(level) or Off, Degraded)
//! judge(&Catalog, &State, &Event) ─▶ Outcome   (Verdict, Recognitions, Degraded; reads Effective)
//! Outcome::evidence ─▶ Judged events           (by each judged policy's author, folded as claims)
//! ```
//!
//! Dependencies between the modules run one way: `name`, `schema` and `authority` ◀ `predicate`
//! ◀ `exempt` ◀ `event` ◀ `state` ◀ `policy` ◀ `catalog` ◀ `judge`, `change` and `tx`. `event`
//! reads `authority` for the principal an event is by. `authority` knows nothing of the others,
//! and `arch-lint.toml` keeps it so. `catalog` does not use `tx`: the transaction is built on the
//! catalog, and [`catalog::Catalog::accept`], which folds the fixtures with it, lives in `tx`.
//!
//! The domain holds no roles. Who an event or a policy comes from is a principal, and where it
//! sits is the [`authority::Authority`] the caller gives; nothing here treats one principal
//! differently from another except by that hierarchy.
//!
//! # Glossary
//!
//! - Policy: the one part of a catalog. A guard says what must hold, a reward what is
//!   recommended within a guard, each at a [`policy::Level`].
//! - Catalog: the accepted set of policies with their layers ([`catalog`]).
//! - Principal and authority: who wrote a policy or made an event, and the hierarchy that says
//!   whose work whom may loosen ([`authority`]); a change of a catalog is judged by it
//!   ([`change`]), and so is a claim ([`tx`]).
//! - Act and claim: the two natures of an event ([`schema::Nature`]). An act (a tool use, the end
//!   of a turn) is observed on the platform, and is what rules judge. A claim (an exemption, a
//!   mode switch, a record of a judgment or a score) is stated by someone, and may change how
//!   the rules take effect.
//! - Transaction: how a claim takes effect ([`tx`]): applied to a copy of the state, judged by
//!   the difference from each point of view (a check), and kept as a whole or not at all. A
//!   loosening one takes effect only from one who covers the authors of what it loosens.
//! - Evidence: what the caller appends (records of judgments, mode switches, exemptions,
//!   scores). With the platform's transcript, it is what the state is folded from.
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
pub mod tx;
