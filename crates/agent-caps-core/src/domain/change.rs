//! Changing an accepted catalog: whether the one who changes it may, judged by the difference
//! between the rules before and after and by the hierarchy of the catalog.
//!
//! ```text
//! Catalog::change(&self, after, by)
//!   1. accept `after` with the catalog's Authority      invariants, types, fixtures, references
//!   2. any difference in a Meta policy: rejected, whoever `by` is
//!   3. `by` must be a principal of the hierarchy
//!   4. for what `by` does not cover (authored by neither `by` nor anyone below it):
//!      (a) no policy removed, and every difference only tightens (an override by what its
//!          policy comes to); what is new is authored by `by` or below
//!      (b) under every compared mode, each policy of `after` takes effect
//!          at least as strongly as in `after` narrowed to what `by` does not cover
//!      one miss rejects the whole change
//!   what `by` covers is free to add, remove and change
//! ```
//!
//! A change is judged as a whole by the difference it makes, so one loosening difference makes
//! the whole change a loosening one, however much else tightens; a change that mixes the two is
//! rejected, and the one who made it splits it. Nobody is asked who is behind `by`: that the
//! change really comes from `by` is for whoever calls (an approval, the store); a catalog
//! trusts the graph it accepts.
//!
//! Whether `by` may loosen an item is [`Authority::may_loosen`](super::authority::Authority::may_loosen)'s
//! answer, and whether a policy's effect goes down is [`lowered`]'s: the same two that judge a
//! claim at run time ([`super::tx`]).
//!
//! # What is compared
//!
//! - (a) looks at each item `by` does not cover, one difference at a time ([`classify`]): a
//!   policy is removed or changed, an override of one is removed, changed or added. A policy
//!   changed in a way whose direction cannot be told (its rule, its condition, its subject, its
//!   layer, what binds it, its author, its examples) is taken to loosen. An override is judged by the effective
//!   value of the policy it targets before and after, under every compared mode.
//! - (b) catches what (a) cannot see: an item of `by` that works against an item `by` does not
//!   cover. It compares `after` with `after` narrowed by [`PolicyGraph::not_covered_by`], which
//!   is what the rules are with nothing of `by`'s in them. A policy of `by` that lowers a guard
//!   of the one above, by an override of its own, falls below that floor and is rejected; one
//!   that raises it does not. When `by` removes its own override of the one above's guard, the
//!   guard returns to the value the narrowed graph gives, and the change is accepted.
//! - The compared modes are no mode, and every mode that an override of the catalog before, or
//!   of `after`, names. A mode that neither names behaves as no mode, so it adds nothing. An
//!   unknown mode is not compared: [`Catalog::effective`] gives it the strictest effect of these
//!   modes for each policy, so a change that holds under each holds under it.
//!
//! # Limits that are chosen
//!
//! - Rejecting is conservative. (b) is measured against `after` narrowed, not against `before`,
//!   so a change that tightens can still be rejected: when `by` removes an override of the one
//!   above that turns a guard off, and places an override of its own on the same guard at
//!   Inform, the guard is stricter than before but below what it is with none of `by`'s work,
//!   and the change is rejected. Removing the override alone is accepted.
//! - The hierarchy belongs to the catalog. [`Catalog::change`] cannot be given another; to
//!   change the hierarchy, accept the graph again with the new one. Whether that loosens
//!   anything is for whoever keeps the hierarchy to ask, and is not judged here.
//! - The code allows several roots, and two roots do not cover each other, so neither's work
//!   is changed by the other. The requirements ledger describes the placement of one user with
//!   the agents below; that several roots are allowed is wider than it.
//! - What the agent adds for a task and the end of the task, when its policies are removed, are
//!   the application's: this module judges a change, and does not make one.

use std::fmt;

use super::authority::{NotCovered, Principal};
use super::catalog::{Catalog, Effect, Effective, Rejected, Target, effective_in, lowered};
use super::name::{Mode, PolicyId};
use super::policy::{DefLayer, Override, Polarity, Policy, PolicyDef, PolicyGraph};
use super::state::Known;

/// Which way one difference moves a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// The rule holds more, or as much and something more.
    Tightens,
    /// The rule holds the same.
    Neutral,
    /// The rule holds less, or the direction cannot be told.
    Loosens,
}

impl Direction {
    /// The direction of two differences together: one loosening makes the whole loosen, else one
    /// tightening makes it tighten.
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Loosens, _) | (_, Self::Loosens) => Self::Loosens,
            (Self::Tightens, _) | (_, Self::Tightens) => Self::Tightens,
            (Self::Neutral, Self::Neutral) => Self::Neutral,
        }
    }

    /// The direction of `after` against `before`, by the order of the values.
    fn of_order<T: Ord>(before: &T, after: &T) -> Self {
        match after.cmp(before) {
            std::cmp::Ordering::Greater => Self::Tightens,
            std::cmp::Ordering::Equal => Self::Neutral,
            std::cmp::Ordering::Less => Self::Loosens,
        }
    }
}

/// The direction of the difference between one policy `before` and the same policy `after`.
///
/// Every field of [`PolicyDef`] is read, so a field added to it stops this from compiling until
/// its direction is decided. A level or an on and off state is compared as it is; a change of
/// the rule, the condition, the subject, the layer, the policy that binds a reward, or the
/// author cannot be read as stricter and loosens. So does any change to the examples, a
/// `known_gap` mark included: they are the evidence for the rule, and one below must not weaken
/// them. Only a name is neutral.
pub fn classify(before: &PolicyDef, after: &PolicyDef) -> Direction {
    let PolicyDef {
        id: before_id,
        name: _,
        layer: before_layer,
        subject: before_subject,
        when: before_when,
        rule: before_rule,
        polarity: before_polarity,
        enabled: before_enabled,
        fixtures: before_fixtures,
        author: before_author,
    } = before;
    let PolicyDef {
        id: after_id,
        name: _,
        layer: after_layer,
        subject: after_subject,
        when: after_when,
        rule: after_rule,
        polarity: after_polarity,
        enabled: after_enabled,
        fixtures: after_fixtures,
        author: after_author,
    } = after;
    let same = before_id == after_id
        && before_layer == after_layer
        && before_subject == after_subject
        && before_when == after_when
        && before_rule == after_rule
        && before_fixtures == after_fixtures
        && before_author == after_author;
    let fixed = if same {
        Direction::Neutral
    } else {
        Direction::Loosens
    };
    let polarity = match (before_polarity, after_polarity) {
        (Polarity::Guard { level: before }, Polarity::Guard { level: after }) => {
            Direction::of_order(before, after)
        }
        (
            Polarity::Reward {
                level: before,
                bound_by: before_guard,
            },
            Polarity::Reward {
                level: after,
                bound_by: after_guard,
            },
        ) if before_guard == after_guard => Direction::of_order(before, after),
        _ => Direction::Loosens,
    };
    // Off is below on.
    let enabled = Direction::of_order(before_enabled, after_enabled);
    fixed.and(polarity).and(enabled)
}

/// One way a change loosens what `by` does not cover.
#[derive(Debug, Clone, PartialEq)]
pub enum Loosening {
    /// An item `by` does not cover is removed, loosened or changed in a way that cannot be read
    /// as stricter, or a new one is authored by one `by` does not cover.
    Uncovered {
        /// The item.
        target: Target,
    },
    /// Under the mode, the policy takes effect less strongly than it would with nothing of
    /// `by`'s in the graph: `by`'s own work works against what `by` does not cover.
    BelowUncovered {
        /// The policy.
        policy: PolicyId,
        /// The mode compared (`None` for no mode).
        mode: Option<Mode>,
        /// What the policy comes to with only what `by` does not cover.
        before: Effect,
        /// What it comes to in the changed graph.
        after: Effect,
    },
}

impl fmt::Display for Loosening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uncovered { target } => write!(f, "{target} is removed, loosened or new"),
            Self::BelowUncovered {
                policy,
                mode,
                before,
                after,
            } => {
                let mode = match mode {
                    None => "no mode".to_owned(),
                    Some(m) => format!("mode {m}"),
                };
                write!(
                    f,
                    "policy {policy} under {mode} comes to {after:?}, below {before:?}, what it \
                     is without the changer's own work"
                )
            }
        }
    }
}

/// Why a change was not accepted.
#[derive(Debug, Clone, PartialEq)]
pub enum ChangeRejected {
    /// The changed graph is not accepted as a catalog.
    Invalid(Rejected),
    /// A meta policy differs, added, removed or changed. Nobody changes one.
    Meta(Vec<PolicyId>),
    /// The one who changes is not a principal of the catalog's hierarchy.
    UnknownPrincipal,
    /// The change loosens what the one who changes does not cover; every way is listed.
    Loosens(Vec<Loosening>),
}

impl fmt::Display for ChangeRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(rejected) => write!(f, "{rejected}"),
            Self::Meta(ids) => {
                f.write_str("a meta policy cannot be changed:")?;
                ids.iter().try_for_each(|id| write!(f, " {id}"))
            }
            Self::UnknownPrincipal => f.write_str("the changer is not in the hierarchy"),
            Self::Loosens(loosenings) => {
                f.write_str("the change loosens what the changer does not cover:")?;
                loosenings
                    .iter()
                    .try_for_each(|loosening| write!(f, "\n- {loosening}"))
            }
        }
    }
}

impl std::error::Error for ChangeRejected {}

impl Catalog {
    /// The catalog of `after`, when `by` may make the change from this catalog to it: see the
    /// module doc for the rule. The hierarchy is the catalog's own.
    pub fn change(&self, after: PolicyGraph, by: &Principal) -> Result<Catalog, ChangeRejected> {
        let authority = self.authority();
        let next = Catalog::accept(after, authority.clone()).map_err(ChangeRejected::Invalid)?;
        let meta = meta_differences(self, &next);
        if !meta.is_empty() {
            return Err(ChangeRejected::Meta(meta));
        }
        if let Err(NotCovered::UnknownPrincipal(_)) = authority.may_loosen(by, []) {
            return Err(ChangeRejected::UnknownPrincipal);
        }
        let uncovered = |author: &Principal| authority.may_loosen(by, [author]).is_err();
        let modes = compared_modes(self, &next);
        let before_effects = effects(self, &modes);
        let after_effects = effects(&next, &modes);
        let mut loosenings = Vec::new();

        // (a) What `by` does not cover is only tightened, and nothing new is made of it.
        for old in self.policies().iter().filter(|p| uncovered(p.author())) {
            let loosens = next
                .policy(old.id())
                .is_none_or(|new| classify(old.def(), new.def()) == Direction::Loosens);
            if loosens {
                loosenings.push(Loosening::Uncovered {
                    target: Target::Policy(old.id()),
                });
            }
        }
        for new in next.policies().iter().filter(|p| uncovered(p.author())) {
            let was_uncovered = self
                .policy(new.id())
                .is_some_and(|old| uncovered(old.author()));
            if !was_uncovered {
                loosenings.push(Loosening::Uncovered {
                    target: Target::Policy(new.id()),
                });
            }
        }
        let same_key = |a: &Override, b: &Override| a.layer == b.layer && a.policy == b.policy;
        for old in self.overrides().iter().filter(|o| uncovered(&o.author)) {
            let new = next.overrides().iter().find(|n| same_key(n, old));
            let loosens = match new {
                Some(new) if new.author != old.author => true,
                Some(new) if new.change == old.change => false,
                _ => {
                    // Removed or changed: by what the policy comes to, under any compared mode.
                    before_effects
                        .iter()
                        .zip(&after_effects)
                        .any(|(b, a)| lowered(b, a).iter().any(|l| l.policy == old.policy))
                }
            };
            if loosens {
                loosenings.push(Loosening::Uncovered {
                    target: Target::Override(old.layer.clone(), old.policy),
                });
            }
        }
        for new in next.overrides().iter().filter(|o| uncovered(&o.author)) {
            let was_uncovered = self
                .overrides()
                .iter()
                .any(|old| same_key(old, new) && uncovered(&old.author));
            if !was_uncovered {
                loosenings.push(Loosening::Uncovered {
                    target: Target::Override(new.layer.clone(), new.policy),
                });
            }
        }

        // (b) Nothing of `by`'s puts a policy below what it is without all of `by`'s work.
        // The narrowed graph is never made a catalog: only its effects are read.
        let narrowed = next.graph().not_covered_by(authority, by);
        let narrowed_policies: Vec<Policy> =
            narrowed.policies.into_iter().map(Policy::new).collect();
        for (mode, after_of) in modes.iter().zip(&after_effects) {
            let known = Known::Known(mode.clone());
            let floor = effective_in(&narrowed_policies, &narrowed.overrides, &known);
            for below in lowered(&floor, after_of) {
                loosenings.push(Loosening::BelowUncovered {
                    policy: below.policy,
                    mode: mode.clone(),
                    before: below.before,
                    after: below.after,
                });
            }
        }

        if loosenings.is_empty() {
            Ok(next)
        } else {
            Err(ChangeRejected::Loosens(loosenings))
        }
    }
}

/// The ids of the meta policies that differ between the two catalogs: one that is added,
/// removed, or changed in any field, or that changes its layer.
fn meta_differences(before: &Catalog, after: &Catalog) -> Vec<PolicyId> {
    let differs = |from: &Catalog, to: &Catalog| {
        from.policies()
            .iter()
            .filter(|p| p.layer() == DefLayer::Meta)
            .filter(|p| to.policy(p.id()).map(|q| q.def()) != Some(p.def()))
            .map(|p| p.id())
            .collect::<Vec<_>>()
    };
    let mut ids = differs(before, after);
    for id in differs(after, before) {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// The modes two catalogs are compared under: no mode, then each mode either names. An unknown
/// mode is not compared: it is the strictest of these, so it follows from them.
fn compared_modes(before: &Catalog, after: &Catalog) -> Vec<Option<Mode>> {
    let mut modes = vec![None];
    for mode in before.modes().into_iter().chain(after.modes()) {
        let mode = Some(mode.clone());
        if !modes.contains(&mode) {
            modes.push(mode);
        }
    }
    modes
}

/// What the catalog comes to under each mode, in the order of `modes`. A policy missing from
/// the other catalog is not compared by [`lowered`]; its removal is judged as the removal of a
/// policy.
fn effects<'a>(catalog: &'a Catalog, modes: &[Option<Mode>]) -> Vec<Effective<'a>> {
    modes
        .iter()
        .map(|mode| catalog.effective(&Known::Known(mode.clone())))
        .collect()
}
