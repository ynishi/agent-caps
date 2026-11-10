//! An exemption from a guard: which events it covers, and for how long.
//!
//! An exemption has two axes and no list of grains: the events it covers (a condition on the
//! judged event, such as one path) and how long it lasts ([`Lifetime`]). Every exemption ends;
//! one that should outlive the session is not an exemption but an override in the project layer
//! of the catalog, so a lasting exception is always a visible change to the rules.
//!
//! An exemption is a claim, and it loosens its guard: it takes effect only from one who covers
//! the guard's author ([`super::tx`]), never for a guard of the meta layer, and only while its
//! lifetime lasts.

use super::name::{PolicyId, Reason};
use super::predicate::{Cond, PredError, Scope};
use super::schema::{At, EventKind};

/// How long an exemption lasts.
#[derive(Debug, Clone, PartialEq)]
pub enum Lifetime {
    /// The next judgment it covers, and no more: the record of the
    /// [`super::schema::Judgment::Exempted`] judgment uses it up.
    Next,
    /// Until the scope starts again. Within [`Scope::Since`], until the event after the one the
    /// filter matched: that event is judged with the exemption still in effect.
    Within(Scope),
    /// Until the instant, compared with the time of the judged event.
    Until(At),
}

impl Lifetime {
    /// Whether the lifetime has not run out by the time of an event at `at`. Only `Until` ends by
    /// time; `Next` ends when it is used and `Within` when its scope starts again, both in the
    /// fold of the state.
    pub(super) fn lasts_at(&self, at: At) -> bool {
        match self {
            Self::Until(until) => at < *until,
            Self::Next | Self::Within(_) => true,
        }
    }
}

/// An exemption from one guard.
#[derive(Debug, Clone, PartialEq)]
pub struct Exempt {
    /// The guard it exempts from.
    pub guard: PolicyId,
    /// The events it covers, read on the judged event; `None` covers every event the guard
    /// judges. A target that reads as unknown does not cover the event.
    pub target: Option<Cond>,
    /// How long it lasts.
    pub lifetime: Lifetime,
    /// Why it was made.
    pub reason: Reason,
}

impl Exempt {
    /// What is wrong with the exemption when its guard judges a `subject` event: the target is
    /// read from the subject, and the filter of a `Within(Since(..))` from its own kind. An
    /// exemption with any error takes no effect.
    pub fn check(&self, subject: EventKind) -> Vec<PredError> {
        let mut errors = self
            .target
            .as_ref()
            .map_or_else(Vec::new, |target| target.check(subject));
        if let Lifetime::Within(Scope::Since(filter)) = &self.lifetime {
            errors.extend(filter.check());
        }
        errors
    }
}
