//! The model of caps: policies, the events they judge, and the state folded from those events.
//!
//! Pure: nothing here touches the file system, a process, the environment, the network, the
//! clock or a random source. Times and ids come in as values; the transcript and the evidence
//! come in as [`event::Event`] values that a platform adapter and the caller have read, each by
//! a [`authority::Principal`].
//!
//! ```text
//! policies, bindings ─ PolicyGraph::parse ─▶ PolicyGraph
//!                                              (keyed by id: no id twice; one order, by id)
//! Source { id, name, owner, graph } … ─ Sources::new ─▶ Sources
//!                                              (the sets of policies, by id: no id twice)
//! Sources, Lineage ─ Catalog::accept ─▶ Catalog
//!                                             (each item within its set's owner; Sources::compose,
//!                                               only adding merges; then structure, what each
//!                                               policy reads, fixtures; generation 0 of the lineage)
//! Catalog::change(Sources, by) ─▶ Catalog     (sets added, removed or swapped, judged as one
//!                                               change by its result; the next generation)
//! events ─ Catalog::fold / apply ─▶ State      (an act is folded; a claim is a transaction; a state
//!                                               is the catalog's generation's, Catalog::owns)
//! Catalog::effective(mode) ─▶ Effective        (as written: every policy On(the strongest level of
//!                                               its bindings that hold) or Off, Degraded)
//! Catalog::effective_in(&State) ─▶ Result<Effective, StaleState>
//!                                              (the same with the state's temporary adjustments:
//!                                               bindings added and suspended for a while)
//! Catalog::enforced(mode, &Capabilities) ─▶ Enforced
//!                                              (as the platform holds it: levels capped, Lowering)
//! judge(&Catalog, &State, &Judgeable, &Capabilities) ─▶ Result<Outcome, StaleState>
//!                                              (Verdict, Recognitions, Degraded, Lowering)
//! Outcome::evidence ─▶ Judged events           (by each judged policy's author, folded as claims;
//!                                               with the written and the enforced level)
//! ```
//!
//! `judge` and `Catalog::enforced` lower a written strength to the platform's capabilities, as
//! stated at [`catalog::Catalog::enforced`]. A change of the rules and the transaction of a claim
//! read the written strength only, which does not depend on the platform.
//!
//! Dependencies between the modules run one way: `name`, `schema` and `authority` ◀ `predicate`
//! ◀ `adjust` ◀ `event` ◀ `state` ◀ `policy` ◀ `set` ◀ `catalog` ◀ `judge`, `change` and `tx`.
//! `set` composes graphs through the one insert of `policy`, which knows nothing of sets; both
//! are kept so by `arch-lint.toml`. `event`
//! reads `authority` for the principal an event is by, and `adjust` reads it for whether the maker
//! of a temporary binding is within its policy's author's work. `authority` knows nothing of the others,
//! and `arch-lint.toml` keeps it so. Behind the `serde` feature, `encoding` is as low as `authority`
//! (the error of a value of several parts, the form of a number that is not finite), kept so the
//! same way, and each module that holds a type with a private field keeps the encoded form of
//! that type beside it. `catalog` does not use `tx`: the transaction is built on the
//! catalog, and [`catalog::Catalog::accept`], which folds the fixtures with it, lives in `tx`.
//! `change` reads `tx` too: a change of the catalog and a claim are judged by the one function of
//! how the rules move (`tx::checks`).
//!
//! The domain holds no roles. Who an event or a policy comes from is a principal, and where it
//! sits is the [`authority::Authority`] the caller gives; nothing here treats one principal
//! differently from another except by that hierarchy. A rule for a role is a condition on the
//! acting principal ([`predicate::Pred::ActorUnder`]), with the role a principal of the
//! hierarchy, not a kind of event.
//!
//! # Glossary
//!
//! - Policy: the one part of a catalog. A guard says what must hold, a reward what is
//!   recommended within a guard. A policy holds no strength of its own.
//! - Binding: one author's statement that a policy takes effect at a [`policy::Level`] where its
//!   mode scope holds ([`policy::Binding`]). A policy takes effect at the strongest level of its
//!   bindings that hold, and is off with none, so adding a binding never lowers a policy.
//! - Catalog: the accepted set of policies with their bindings ([`catalog`]).
//! - Lineage and generation: the name the caller gives a catalog accepted from nothing, and the
//!   version of a catalog in it, which each change raises by one ([`state::Generation`]). A state
//!   is used only with the generation that made it ([`catalog::Catalog::owns`]).
//! - Set of policies: a graph with an id and an owner ([`set::Source`]), such as a shared set of
//!   best practices or a project's own. A catalog is accepted from its sets and keeps them; they
//!   compose by adding only, and a change adds, removes or swaps sets ([`set`]).
//! - Temporary adjustment: a claim that changes how the rules take effect for a lifetime
//!   ([`adjust`]): an exemption, which keeps a guard from judging the events it covers, or
//!   bindings added and bindings of the catalog suspended. It is seen in the state
//!   ([`state::State::adjustments`]), ends with its lifetime or a cancel, and is judged by its
//!   result, as a cancel is.
//! - Capabilities: the highest level a platform can enforce, given as data in the words of an
//!   event filter and supplied with each judgment ([`catalog::Capabilities`]). A policy written
//!   above it is enforced at it, and each judgment records both levels ([`event::Body::Judged`]).
//! - Principal and authority: who wrote a policy or made an event, and the hierarchy that says
//!   whose work whom may loosen ([`authority`]); a change of a catalog is judged by it
//!   ([`change`]), and so is a claim ([`tx`]).
//! - Actor and spawn: who acts is the event's principal, and where it sits is read from the
//!   hierarchy of actors, which is the [`authority::Authority`] plus the leaves that spawns add
//!   ([`state`]). A rule reads it with [`predicate::Pred::ActorUnder`]. The two hierarchies stay
//!   apart: only the authority's says whose rules one may loosen. A spawn
//!   ([`event::Body::Spawn`]) is a claim: where it places its child is judged as a transaction
//!   ([`tx`]).
//! - Act and claim: the two natures of an event ([`schema::Nature`]). An act (a tool use, the end
//!   of a turn) is observed on the platform, and is what rules judge. A claim (a temporary
//!   adjustment or its cancel, a mode switch, a spawn, a record of a judgment or a score) is
//!   stated by someone, and may change how the rules take effect.
//! - Transaction: how a claim takes effect ([`tx`]): applied to a copy of the state, judged by
//!   the difference from each point of view (a check), and kept as a whole or not at all. A
//!   loosening one takes effect only from one who covers the authors of what it loosens.
//! - Evidence: what the caller appends (records of judgments, mode switches, temporary
//!   adjustments and their cancels, scores). With the platform's transcript, it is what the state is folded from.
//! - Slot: what one temporal operator (`once`, `count`, `last`, `spent`) remembers between
//!   events.
//! - Meter and amount: what a platform measures as used, such as tokens, carried by an act
//!   ([`event::Body::Used`]) and summed within a scope by [`predicate::Pred::Spent`].
//! - Unknown: what could not be seen. A stopping guard that cannot tell denies.

pub mod adjust;
pub mod authority;
pub mod catalog;
pub mod change;
#[cfg(feature = "serde")]
pub mod encoding;
pub mod event;
mod glob;
pub mod judge;
pub mod name;
pub mod policy;
pub mod predicate;
pub mod schema;
pub mod set;
pub mod state;
pub mod tx;
