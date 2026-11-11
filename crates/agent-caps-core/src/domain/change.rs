//! Changing an accepted catalog: whether the one who changes it may, judged by the difference
//! between the rules before and after and by the hierarchy of the catalog.
//!
//! ```text
//! Catalog::change(&self, after: Sources, by)
//!   1. accept `after` with the catalog's Authority      owners, composition, invariants, types,
//!                                                       fixtures, references
//!   2. any difference in a Meta policy or its binding, or in the sets that hold them: rejected,
//!      whoever `by` is
//!   3. `by` must be a principal of the hierarchy
//!   4. what is written, in the composed graphs and the sets: for what `by` does not cover
//!      (authored, or owned, by neither `by` nor anyone below it), no policy removed, none
//!      changed in a way that cannot be read as stricter (classify), no binding removed, lowered
//!      or rescoped, no set removed or changed in its graph, name or owner, and nothing new in its
//!      name, a policy, a binding or a set
//!   5. what takes effect: under every compared mode, how the rules move from before to after
//!      (rule_moves, with the readers of a moved policy's judgments in both catalogs); every
//!      author a loosening asks must be covered by `by` (Authority::may_loosen)
//!   one miss rejects the whole change; what `by` covers is free to add, remove and change
//! ```
//!
//! A change is judged as a whole by the difference it makes, so one loosening difference makes
//! the whole change a loosening one, however much else tightens; a change that mixes the two is
//! rejected, and the one who made it splits it. Nobody is asked who is behind `by`: that the
//! change really comes from `by` is for whoever calls (an approval, the store); a catalog
//! trusts the graph it accepts.
//!
//! Whether `by` may loosen what an author wrote is
//! [`Authority::may_loosen`](super::authority::Authority::may_loosen)'s answer, and how the rules
//! move, with whose authors, is the one function a claim is judged by at run time
//! ([`super::tx::checks`]): a change and a claim cannot disagree on which way the strength of a
//! policy goes.
//!
//! # What is compared
//!
//! - Step 4 looks at each policy `by` does not cover, one difference at a time ([`classify`]): a
//!   policy changed in a way whose direction cannot be told (its rule, its condition, its
//!   subject, its layer, whether it forbids or recommends and what binds it, its author, its
//!   examples) is taken to loosen, and so is one removed. A binding in the name of an author `by`
//!   does not cover is kept: one removed, lowered, given another scope or taken over loosens,
//!   though its policy keeps its strength, since an equal binding of `by`'s own beside it would
//!   hide the loss now and leave the strength to a binding `by` may drop later; one raised at its
//!   scope tightens. One that goes with its policy is the policy's removal. A new one in such a
//!   name is refused, so nobody writes in another's name; a binding kept with its id, its author
//!   and its policy is not new.
//! - Step 4 looks at each classifier `by` does not cover too, as it looks at a policy
//!   ([`classify_classifier`], [`Target::Classifier`]): one
//!   removed, or changed in its bound or its calibration record, is taken to loosen (a record
//!   that suffices is what lets a guard stop, and a bound is what it is held to, so neither can
//!   be read as stricter), and one new in the name of an author `by` does not cover is refused.
//!   What the guards that read it come to is step 5's, from the strength they take effect at.
//! - Step 4 looks at each set too ([`super::set`]), as an item whose author is its owner, with
//!   the same question of who is covered: a set whose owner `by` does not cover is added,
//!   removed, given another graph, renamed or given another owner only as a loosening
//!   ([`Target::Set`]), since whatever the set holds and is called is its owner's to say. A set
//!   is the one with its id ([`SetId`]), so a renamed set is changed, not
//!   removed and added. A set and an item of it that both loosen are
//!   both reported; a difference is reported once per item. A set of another owner is a value
//!   that owner keeps: a change of it in any way, one that only tightens included, asks for the
//!   owner's cover, and one who wants to tighten adds to a set of its own, which loses nothing.
//!   A swap of a set ([`Sources::replaced`](super::set::Sources::replaced)), a new version
//!   included, is one change and one difference: a version by one who covers the set's owner
//!   that only tightens is judged by what it tightens, not as the removal of the old one and the
//!   addition of the new.
//! - Step 5 compares what takes effect. The strongest binding wins, so the strength of a policy
//!   that `by` does not cover goes down only when a binding that carried it is removed, weakened
//!   or stops holding, or when a guard at Force comes to read a classifier whose record no longer
//!   meets its bound ([`Degraded::Uncalibrated`](super::catalog::Degraded::Uncalibrated)), and
//!   the authors asked are those of the bindings that carried it, read from the catalog before. Adding a binding never lowers a policy. A policy that moves, either way, moves every
//!   other policy that reads its judgments, so their authors are asked too.
//! - The compared modes are no mode, and every mode a binding's scope names in the catalog
//!   before or in `after`. A mode that neither names behaves as no mode, so it adds nothing. An
//!   unknown mode is not compared: [`Catalog::effective`] takes every binding that may hold to
//!   hold, and each holds under one of the compared modes, so a guard that goes down under an
//!   unknown mode goes down under one of them.
//! - A rule of one below that reads the judgments of one above is not accepted
//!   ([`AcceptError::ReferencesBelow`](super::catalog::AcceptError::ReferencesBelow)), so what
//!   `by` writes cannot work against what `by` does not cover through what it reads.
//!
//! # Limits that are chosen
//!
//! - The hierarchy belongs to the catalog. [`Catalog::change`] cannot be given another; to
//!   change the hierarchy, accept the sources again with the new one. Whether that loosens
//!   anything is for whoever keeps the hierarchy to ask, and is not judged here.
//! - The code allows several roots, and two roots do not cover each other, so neither's work
//!   is changed by the other. The requirements ledger describes the placement of one user with
//!   the agents below; that several roots are allowed is wider than it.
//! - Sets are composed by the core, by adding only ([`Sources::compose`]): a project's set adds
//!   to a shared one and never replaces or lowers what it holds, and weakening a shared rule for
//!   one project is a version of the shared set that its owner gives it. The owner of a set,
//!   like `by`, is the caller's to guarantee; a catalog checks that it agrees with the authors
//!   of what the set holds ([`super::set`]).
//! - A set that holds a meta policy enters only when a catalog is accepted: a change that adds,
//!   removes or changes it differs in a meta policy, and step 2 refuses it whoever `by` is.
//! - What the agent adds for a task and the end of the task, when its policies are removed, are
//!   the application's: this module judges a change, and does not make one.

use std::fmt;

use super::authority::{NotCovered, Principal};
use super::catalog::{Catalog, Rejected, Target, compared_modes};
use super::name::{Mode, PolicyId};
use super::policy::{Binding, Classifier, DefLayer, PolicyDef};
use super::set::{SetId, Sources};
use super::state::Known;
use super::tx::checks::{Point, rule_moves, rules_verdict};
use super::tx::{FindingDetail, Verdict};

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

/// The direction of the difference between one policy `before` and the same policy `after`.
///
/// Every field of [`PolicyDef`] is read, so a field added to it stops this from compiling until
/// its direction is decided. A policy holds no strength (its bindings do), so a change of any
/// field but the name cannot be read as stricter and loosens: the rule, the condition, the
/// subject, the layer, whether it forbids or recommends and the guard that binds a reward, the
/// author, and any change to the examples, a `known_gap` mark included (they are the evidence for
/// the rule, and one below must not weaken them). Only a name is neutral.
pub fn classify(before: &PolicyDef, after: &PolicyDef) -> Direction {
    let PolicyDef {
        id: before_id,
        name: _,
        layer: before_layer,
        subject: before_subject,
        when: before_when,
        rule: before_rule,
        polarity: before_polarity,
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
        fixtures: after_fixtures,
        author: after_author,
    } = after;
    let same = before_id == after_id
        && before_layer == after_layer
        && before_subject == after_subject
        && before_when == after_when
        && before_rule == after_rule
        && before_polarity == after_polarity
        && before_fixtures == after_fixtures
        && before_author == after_author;
    if same {
        Direction::Neutral
    } else {
        Direction::Loosens
    }
}

/// The direction of the difference between the declaration of a classifier `before` and `after`,
/// either of which is `None` when the classifier is not declared then: the classifier's side of
/// [`classify`].
///
/// A declaration added tightens: until a guard reads it, nothing takes effect differently. One
/// removed loosens, and so does one changed in any field but its name, the key it is found by: a
/// bound or a calibration record decides whether a guard may stop ([`Calibration::admit`]), so a
/// change of either cannot be read as stricter, and the author is the one who may say so. Every
/// field of [`Classifier`] is read, so a field added to it stops this from compiling until its
/// direction is decided.
///
/// A new declaration in the name of an author `by` does not cover is refused by
/// [`Catalog::change`], as a new policy is, whatever this says.
///
/// [`Calibration::admit`]: super::policy::Calibration::admit
pub fn classify_classifier(before: Option<&Classifier>, after: Option<&Classifier>) -> Direction {
    match (before, after) {
        (None, None) => Direction::Neutral,
        (None, Some(_)) => Direction::Tightens,
        (Some(_), None) => Direction::Loosens,
        (Some(before), Some(after)) => {
            let Classifier {
                name: _,
                author: before_author,
                bound: before_bound,
                record: before_record,
            } = before;
            let Classifier {
                name: _,
                author: after_author,
                bound: after_bound,
                record: after_record,
            } = after;
            if before_author == after_author
                && before_bound == after_bound
                && before_record == after_record
            {
                Direction::Neutral
            } else {
                Direction::Loosens
            }
        }
    }
}

/// One way a change loosens what `by` does not cover.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub enum Loosening {
    /// A policy `by` does not cover is removed or changed in a way that cannot be read as
    /// stricter, a binding `by` does not cover is removed, lowered, rescoped or taken over, a
    /// classifier declaration `by` does not cover is removed or changed, a set whose owner `by`
    /// does not cover is removed or given another graph, name or owner, or a new policy,
    /// binding, classifier or set is in the name of one `by` does not cover.
    Uncovered {
        /// The item.
        target: Target,
    },
    /// Under the mode, the rules move in a way that loosens the work of authors `by` does not
    /// cover: a policy takes effect less strongly, or a policy that reads the judgments of one
    /// that moves is moved by that.
    Moves {
        /// The mode compared (`None` for no mode).
        #[cfg_attr(feature = "serde", serde(deserialize_with = "Option::deserialize"))]
        mode: Option<Mode>,
        /// Every author the loosening asks, those `by` covers included.
        authors: Vec<Principal>,
        /// How the rules move.
        detail: FindingDetail,
    },
}

impl fmt::Display for Loosening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uncovered { target } => write!(f, "{target} is removed, loosened or new"),
            Self::Moves {
                mode,
                authors,
                detail,
            } => {
                let mode = match mode {
                    None => "no mode".to_owned(),
                    Some(m) => format!("mode {m}"),
                };
                f.write_str("under ")?;
                f.write_str(&mode)?;
                f.write_str(" the rules of")?;
                authors.iter().try_for_each(|a| write!(f, " {a}"))?;
                write!(f, " are loosened: {detail:?}")
            }
        }
    }
}

/// Why a change was not accepted.
#[derive(Debug, Clone, PartialEq)]
pub enum ChangeRejected {
    /// The changed graph is not accepted as a catalog.
    Invalid(Rejected),
    /// A meta policy or its binding differs, added, removed or changed. Nobody changes one.
    Meta(Vec<PolicyId>),
    /// The one who changes is not a principal of the catalog's hierarchy.
    UnknownPrincipal,
    /// The change loosens what the one who changes does not cover; every way is listed.
    Loosens(Vec<Loosening>),
    /// The catalog's generation number is spent, so the change has no next generation
    /// ([`Catalog::generation`]). Accept the sources again under a new lineage.
    GenerationsExhausted,
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
            Self::GenerationsExhausted => {
                f.write_str("the catalog has no next generation: its number is spent")
            }
        }
    }
}

impl std::error::Error for ChangeRejected {}

impl Catalog {
    /// The catalog of the sets `after`, when `by` may make the change from this catalog to it:
    /// see the module doc for the rule. Adding, removing and replacing a set are changes of the
    /// sources ([`Sources::with`](super::set::Sources::with),
    /// [`Sources::without`](super::set::Sources::without),
    /// [`Sources::replaced`](super::set::Sources::replaced) of [`Catalog::sources`]), each judged
    /// as one change. The hierarchy is the catalog's own.
    pub fn change(&self, after: Sources, by: &Principal) -> Result<Catalog, ChangeRejected> {
        let authority = self.authority();
        let generation = self
            .generation()
            .next()
            .ok_or(ChangeRejected::GenerationsExhausted)?;
        let next = Catalog::accept_as(after, authority.clone(), generation)
            .map_err(ChangeRejected::Invalid)?;
        let meta = meta_differences(self, &next);
        if !meta.is_empty() {
            return Err(ChangeRejected::Meta(meta));
        }
        if let Err(NotCovered::UnknownPrincipal(_)) = authority.may_loosen(by, []) {
            return Err(ChangeRejected::UnknownPrincipal);
        }
        let uncovered = |author: &Principal| authority.may_loosen(by, [author]).is_err();
        let mut loosenings = Vec::new();

        // What is written: what `by` does not cover is kept, and nothing new is in its name.
        let removed_or_loosened = self.policies().iter().filter(|old| {
            uncovered(old.author())
                && next
                    .policy(old.id())
                    .is_none_or(|new| classify(old.def(), new.def()) == Direction::Loosens)
        });
        let new_policies = next.policies().iter().filter(|new| {
            uncovered(new.author())
                && !self
                    .policy(new.id())
                    .is_some_and(|old| uncovered(old.author()))
        });
        let policies = removed_or_loosened
            .chain(new_policies)
            .map(|p| Target::Policy(p.id()));
        // A binding in the name of one `by` does not cover is kept, at its level or above, under
        // the same scope: an equal binding of `by`'s own beside it would hide its removal or its
        // weakening from what takes effect, and leave the strength to a binding `by` may drop.
        // One that goes with its policy is the removal of the policy, reported as that.
        let same_item =
            |a: &Binding, b: &Binding| a.id == b.id && a.policy == b.policy && a.author == b.author;
        let unkept = self.bindings().filter(|old| {
            uncovered(&old.author)
                && next.policy(old.policy).is_some()
                && !next.bindings().any(|new| {
                    same_item(old, new) && new.mode == old.mode && new.level >= old.level
                })
        });
        let new_in_another_name = next.bindings().filter(|new| {
            uncovered(&new.author) && !self.bindings().any(|old| same_item(old, new))
        });
        let bindings = unkept
            .chain(new_in_another_name)
            .map(|b| Target::Binding(b.id));
        // A classifier declaration in the name of one `by` does not cover is kept as it is, and
        // none is new in such a name: policies' rule, with the direction `classify_classifier` says.
        let unkept_classifiers = self.graph().classifiers().filter(|old| {
            uncovered(&old.author)
                && classify_classifier(Some(old), next.graph().classifier(&old.name))
                    == Direction::Loosens
        });
        let new_classifiers = next.graph().classifiers().filter(|new| {
            uncovered(&new.author)
                && !self
                    .graph()
                    .classifier(&new.name)
                    .is_some_and(|old| uncovered(&old.author))
        });
        let classifiers = unkept_classifiers
            .chain(new_classifiers)
            .map(|c| Target::Classifier(c.name.clone()));
        // A set is an item whose author is its owner: one in the name of an owner `by` does not
        // cover is kept as it is, its graph, name and owner, and none is new in such a name. Its
        // items are judged as well, each by its own author, and both are reported: they say what
        // else loosens.
        let unkept_sets = self
            .sources()
            .iter()
            .filter(|old| uncovered(&old.owner) && next.sources().get(&old.id) != Some(*old));
        let new_sets = next.sources().iter().filter(|new| {
            uncovered(&new.owner)
                && !self
                    .sources()
                    .get(&new.id)
                    .is_some_and(|old| uncovered(&old.owner))
        });
        let sets = unkept_sets.chain(new_sets).map(|s| Target::Set(s.id));
        for target in policies.chain(bindings).chain(classifiers).chain(sets) {
            if !loosenings
                .iter()
                .any(|l| matches!(l, Loosening::Uncovered { target: t } if *t == target))
            {
                loosenings.push(Loosening::Uncovered { target });
            }
        }

        // What takes effect: the same moves, with the same authors, as a claim's.
        for mode in compared_modes([self, &next]) {
            let known = Known::Known(mode.clone());
            let point = |catalog| Point::Catalog {
                catalog,
                mode: &known,
            };
            let moves = rule_moves(&point(self), &point(&next));
            if let Verdict::Loosens { authors, detail } = rules_verdict(&[self, &next], moves)
                && authority.may_loosen(by, &authors).is_err()
            {
                loosenings.push(Loosening::Moves {
                    mode,
                    authors,
                    detail,
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
/// removed, or changed in any field, that changes its layer, or whose binding differs in any
/// field (its id, level, scope or author), or that enters or leaves a set.
fn meta_differences(before: &Catalog, after: &Catalog) -> Vec<PolicyId> {
    let bindings_of = |catalog: &Catalog, id: PolicyId| -> Vec<Binding> {
        catalog
            .bindings()
            .filter(|b| b.policy == id)
            .cloned()
            .collect()
    };
    let differs = |from: &Catalog, to: &Catalog| {
        from.policies()
            .iter()
            .filter(|p| p.layer() == DefLayer::Meta)
            .filter(|p| {
                to.policy(p.id()).map(|q| q.def()) != Some(p.def())
                    || bindings_of(from, p.id()) != bindings_of(to, p.id())
            })
            .map(|p| p.id())
            .collect::<Vec<_>>()
    };
    let mut ids = differs(before, after);
    for id in differs(after, before) {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    // A set that holds a meta policy enters only when a catalog is accepted, so a meta policy, or
    // a binding of one, that enters or leaves a set differs too, even when another set holds the
    // same item and the composed graphs agree.
    let metas = [before, after].into_iter().flat_map(|catalog| {
        catalog
            .policies()
            .iter()
            .filter(|p| p.layer() == DefLayer::Meta)
            .map(|p| p.id())
    });
    let sets = || {
        before
            .sources()
            .iter()
            .chain(after.sources().iter())
            .map(|s| s.id)
    };
    for id in metas {
        let moved = sets().any(|set| held(before, set, id) != held(after, set, id));
        if moved && !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// The policy `id` and its bindings as the set `set` of the catalog holds them: nothing when the
/// catalog has no such set.
fn held(catalog: &Catalog, set: SetId, id: PolicyId) -> (Option<&PolicyDef>, Vec<&Binding>) {
    catalog
        .sources()
        .get(&set)
        .map(|s| {
            let bindings = s.graph.bindings().filter(|b| b.policy == id).collect();
            (s.graph.policy(id), bindings)
        })
        .unwrap_or_default()
}
