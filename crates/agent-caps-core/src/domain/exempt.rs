//! A user's exemption from a guard: which events it covers, and for how long.
//!
//! An exemption has two axes and no list of grains: the events it covers (a condition on the
//! judged event, such as one path) and how long it lasts ([`Lifetime`]). Every exemption ends;
//! one that should outlive the session is not an exemption but an override in the project layer
//! of the catalog, so a lasting exception is always a visible change to the rules.
//!
//! It takes effect only when its event comes from the user (see [`super::state::State`]), never
//! for a guard of the meta layer, and only while its lifetime lasts.

use super::name::{PolicyId, Reason};
use super::predicate::Cond;
use super::schema::{At, Scope};

/// How long an exemption lasts.
#[derive(Debug, Clone, PartialEq)]
pub enum Lifetime {
    /// The next judgment it covers, and no more: the [`super::schema::Judgment::Exempted`] that
    /// caps records for it uses it up.
    Next,
    /// Until the scope starts again.
    Within(Scope),
    /// Until the instant, compared with the time of the judged event.
    Until(At),
}

/// A user's exemption from one guard.
#[derive(Debug, Clone, PartialEq)]
pub struct Exempt {
    /// The guard it exempts from.
    pub guard: PolicyId,
    /// The events it covers, read on the judged event; `None` covers every event the guard
    /// judges. A target that reads as unknown does not cover the event.
    pub target: Option<Cond>,
    /// How long it lasts.
    pub lifetime: Lifetime,
    /// Why the user made it.
    pub reason: Reason,
}
