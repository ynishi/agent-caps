//! The one part of a catalog: a policy, the bindings that put it into effect, and the policy graph
//! both are written in.
//!
//! A policy says, for one kind of event, what must hold (a guard) or what is recommended (a
//! reward). It holds no strength of its own. A [`Binding`] is one author's statement that a policy
//! takes effect at a [`Level`] where its [`ModeScope`] holds; a policy takes effect at the
//! strongest level of its bindings that hold, and with none it is off. Adding a binding therefore
//! never lowers a policy. Knowledge, procedures and roles are not parts of their own: each is a set
//! of policies seen another way.
//!
//! ```text
//! PolicyDef   what must hold or is recommended    (when, rule, subject, fixtures, author)
//! Binding     that policy, at a level, under a mode scope, by an author
//!   effect of a policy = the strongest level of its bindings that hold, or Off
//! ```
//!
//! A level is how much the one who acts is trusted with a rule, not when the rule is checked:
//!
//! ```text
//! Level       Guard (must not)          Reward (should)
//! Force       stop (unknown stops too)  -  (a reward cannot have it)
//! Advise      warn                      recommend
//! Inform      tell                      tell
//! ```
//!
//! When a check happens follows from the event the policy judges (its `subject`): a tool use is
//! judged as it comes, the end of a turn when the turn ends. Which mechanism of a platform stops
//! it is the adapter's to choose; the policy holds no such value.
//!
//! # Invariants
//!
//! - A reward is bound by one guard: the guard is the line not to cross, the reward the way to
//!   go within it. A reward takes effect no stronger than its guard, and no binding of a reward
//!   is Force (see [`super::catalog`]).
//! - A policy and a binding each have an author, a [`Principal`]. What may refer to what, and
//!   who may change whose, follows the [`Authority`] the catalog keeps (see
//!   [`super::catalog`] and [`super::change`]).
//! - A [`ModeSet`] is not empty and holds no mode twice: [`ModeSet::new`] refuses otherwise.
//! - A [`Policy`] is made only by [`super::catalog::Catalog::accept`], which checks the graph as a
//!   whole (see there). The [`PolicyDef`] it is made from is plain data with no rule of its own.
//! - A [`Policy`] keeps its [`PolicyDef`] as written, and the predicates the catalog uses. The
//!   two differ only in a filter of judgments that narrows to no policy: the catalog's predicate
//!   counts the judgments of the policies its author may count (see [`super::catalog`]). The
//!   written def is what a graph and a difference between graphs are read from; the compiled
//!   predicates are what is evaluated and what the slots are made of.

use std::fmt;

use super::authority::{Authority, Principal};
use super::event::Event;
use super::name::{BindingId, Mode, PolicyId, PolicyName};
use super::predicate::{Cond, EventFilter, Lit, Pred, Scope, Selector, Truth, reads_unnarrowed};
use super::schema::{EventKind, Field};
use super::state::{Known, SlotTable, State};

// `Level` is defined in `schema` so that a record of a judgment (`event`), which carries the
// levels it was written and enforced at, does not depend on this module; it is read from here.
pub use super::schema::Level;

/// Whether a policy forbids or recommends. How strongly is its bindings' to say.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Polarity {
    /// What must hold. Failing it gives a warning or a denial.
    Guard,
    /// What is recommended. Following it is a hit; not following it is no failure.
    Reward {
        /// The guard it works within.
        bound_by: PolicyId,
    },
}

/// Why a [`ModeSet`] could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeSetError {
    /// No mode was given.
    Empty,
    /// The mode was given twice.
    Duplicate(Mode),
}

impl fmt::Display for ModeSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a set of modes needs at least one mode"),
            Self::Duplicate(mode) => write!(f, "the mode {mode} is given twice"),
        }
    }
}

impl std::error::Error for ModeSetError {}

/// Modes, at least one, none twice, kept in their order. Made only by [`ModeSet::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModeSet(Vec<Mode>);

impl ModeSet {
    /// The set of `modes`, when there is at least one and none is given twice.
    pub fn new(modes: Vec<Mode>) -> Result<Self, ModeSetError> {
        if modes.is_empty() {
            return Err(ModeSetError::Empty);
        }
        for (at, mode) in modes.iter().enumerate() {
            if modes[..at].contains(mode) {
                return Err(ModeSetError::Duplicate(mode.clone()));
            }
        }
        Ok(Self(modes))
    }

    /// The modes, in the order given.
    pub fn modes(&self) -> &[Mode] {
        &self.0
    }
}

/// Where a binding takes effect, as to the mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ModeScope {
    /// Under every mode, and under none.
    Any,
    /// Only while this mode is in effect.
    In(Mode),
    /// Only while none of these modes is in effect (no mode at all included).
    Outside(ModeSet),
}

impl ModeScope {
    /// Whether it holds under `mode`; [`Truth::Unknown`] when the mode is not known and the scope
    /// depends on it. The one answer to "does a binding hold under a mode", and to "is the mode
    /// `m`" (`In(m)`).
    pub fn holds(&self, mode: &Known<Option<Mode>>) -> Truth {
        match (self, mode) {
            (Self::Any, _) => Truth::True,
            (Self::In(_) | Self::Outside(_), Known::Unknown) => Truth::Unknown,
            (Self::In(m), Known::Known(now)) => Truth::of(now.as_ref() == Some(m)),
            (Self::Outside(set), Known::Known(now)) => {
                Truth::of(now.as_ref().is_none_or(|now| !set.modes().contains(now)))
            }
        }
    }

    /// The modes it names.
    pub fn modes(&self) -> &[Mode] {
        match self {
            Self::Any => &[],
            Self::In(mode) => std::slice::from_ref(mode),
            Self::Outside(set) => set.modes(),
        }
    }
}

/// One author's statement that a policy takes effect at a level, where its scope holds. A policy
/// takes effect at the strongest level of its bindings that hold.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Binding {
    /// Its id, unique in the graph.
    pub id: BindingId,
    /// The policy it puts into effect.
    pub policy: PolicyId,
    /// How strongly.
    pub level: Level,
    /// Where, as to the mode.
    pub mode: ModeScope,
    /// Who wrote it: the policy's author or one below it.
    pub author: Principal,
}

/// How a policy judges. New ways (a classifier's answer) are added as the model grows.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Rule {
    /// A predicate, judged the same way every time from the same events.
    Structural(Pred),
}

/// The layer a policy is defined in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefLayer {
    /// Fixed: it has exactly one binding, by its author, under every mode, and no exemption
    /// covers it.
    Meta,
    /// Its author's own: its author and those below may bind it, at a level and under a mode.
    Base,
}

/// What a fixture expects a policy to find on its last event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expect {
    /// The guard fails, or the reward is not followed.
    Violated,
    /// The guard holds, or the reward is followed.
    Satisfied,
    /// The policy does not judge the event.
    NotApplicable,
    /// The policy cannot tell, because something it reads was not seen.
    Unknown,
}

/// One example of a policy at work: events, and what the policy should find on the last one.
/// Fixtures live in the policy, so a change of the policy and of its examples is one change.
#[derive(Debug, Clone, PartialEq)]
pub struct Fixture {
    /// What the example shows, for the people who read a failure.
    pub name: String,
    /// The events, folded in order; the last is the one judged.
    pub events: Vec<Event>,
    /// What the policy should find.
    pub expect: Expect,
    /// The policy is known to get this example wrong: a failure of it does not reject the
    /// catalog, and it is kept to show the gap.
    pub known_gap: bool,
}

/// A policy as written in a policy graph: plain data, checked when a catalog accepts it.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDef {
    /// Its id.
    pub id: PolicyId,
    /// Its name.
    pub name: PolicyName,
    /// The layer it is defined in.
    pub layer: DefLayer,
    /// The kind of event it judges.
    pub subject: EventKind,
    /// When it applies; `None` applies to every event of its subject.
    pub when: Option<Pred>,
    /// What it says.
    pub rule: Rule,
    /// Whether it forbids or recommends.
    pub polarity: Polarity,
    /// Its examples.
    pub fixtures: Vec<Fixture>,
    /// Who wrote it. The graph is trusted as written; the catalog checks that the author is a
    /// principal of its [`Authority`], that a meta policy's author is a root, and that the
    /// policy refers only to policies of its own author or of one above.
    pub author: Principal,
}

/// What a catalog is accepted from: the policies, and the bindings that put them into effect.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PolicyGraph {
    /// The policies.
    pub policies: Vec<PolicyDef>,
    /// The bindings.
    pub bindings: Vec<Binding>,
}

/// What a policy found on one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Finding {
    /// The guard fails, or the reward is not followed.
    Violated,
    /// The guard holds, or the reward is followed.
    Satisfied,
    /// The policy does not judge the event: another kind, or its `when` does not hold.
    NotApplicable,
    /// The guard does not judge the event because an exemption in effect covers it.
    Exempted,
    /// Something the policy reads was not seen.
    Unknown,
}

/// A policy of an accepted catalog. Only [`super::catalog::Catalog::accept`] makes one.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    /// As written.
    def: PolicyDef,
    /// What the catalog evaluates and makes its slots of.
    compiled: Compiled,
}

/// The predicates of a policy as the catalog uses them: its `when` and its `rule`.
#[derive(Debug, Clone, PartialEq)]
struct Compiled {
    when: Option<Pred>,
    rule: Rule,
}

impl Policy {
    /// The policy with its predicates as written. Made only where the catalog has decided that
    /// nothing is narrowed: a meta policy, which reads no judgment unnarrowed, and a policy
    /// whose author is not of the hierarchy, which is not accepted.
    pub(super) fn new(def: PolicyDef) -> Self {
        let compiled = Compiled {
            when: def.when.clone(),
            rule: def.rule.clone(),
        };
        Self { def, compiled }
    }

    /// The policy whose filters of judgments that narrow to no policy count only the judgments of
    /// `visible`, the policies its author may count. A filter that narrows to policies is kept as
    /// written, and so is everything else. With no such filter the compiled predicates are the
    /// written ones.
    pub(super) fn scoped(def: PolicyDef, visible: &[PolicyId]) -> Self {
        let visible = Cond::In(
            Field::Policy,
            visible.iter().map(|id| Lit::Text(id.to_string())).collect(),
        );
        let Rule::Structural(rule) = &def.rule;
        let compiled = Compiled {
            when: def.when.as_ref().map(|when| scope_pred(when, &visible)),
            rule: Rule::Structural(scope_pred(rule, &visible)),
        };
        Self { def, compiled }
    }

    /// As written.
    pub(super) fn def(&self) -> &PolicyDef {
        &self.def
    }

    /// Its id.
    pub fn id(&self) -> PolicyId {
        self.def.id
    }

    /// Who wrote it.
    pub fn author(&self) -> &Principal {
        &self.def.author
    }

    /// Its name.
    pub fn name(&self) -> &PolicyName {
        &self.def.name
    }

    /// The layer it is defined in.
    pub fn layer(&self) -> DefLayer {
        self.def.layer
    }

    /// The kind of event it judges.
    pub fn subject(&self) -> EventKind {
        self.def.subject
    }

    /// Whether it forbids or recommends.
    pub fn polarity(&self) -> &Polarity {
        &self.def.polarity
    }

    /// Its examples.
    pub fn fixtures(&self) -> &[Fixture] {
        &self.def.fixtures
    }

    /// Whether it is a guard.
    pub fn is_guard(&self) -> bool {
        matches!(self.def.polarity, Polarity::Guard)
    }

    /// Every predicate it holds, as the catalog uses it.
    pub(super) fn preds(&self) -> impl Iterator<Item = &Pred> {
        self.when().into_iter().chain(std::iter::once(self.rule()))
    }

    /// The `when` predicate as the catalog uses it, when there is one.
    pub(super) fn when(&self) -> Option<&Pred> {
        self.compiled.when.as_ref()
    }

    /// The `rule` predicate as the catalog uses it.
    pub(super) fn rule(&self) -> &Pred {
        let Rule::Structural(rule) = &self.compiled.rule;
        rule
    }

    /// What the policy finds on `event`, with `state` already folded over it. `authority` is the
    /// hierarchy of the catalog, which the actor of the event is read in.
    pub(super) fn evaluate(
        &self,
        slots: &SlotTable,
        authority: &Authority,
        state: &State,
        event: &Event,
    ) -> Finding {
        if event.body.kind() != self.def.subject {
            return Finding::NotApplicable;
        }
        if let Some(when) = &self.compiled.when {
            match state.holds(slots, authority, when, event) {
                Truth::False => return Finding::NotApplicable,
                Truth::Unknown => return Finding::Unknown,
                Truth::True => {}
            }
        }
        if self.is_guard() && self.def.layer != DefLayer::Meta && state.exempts(self.def.id, event)
        {
            return Finding::Exempted;
        }
        let Rule::Structural(rule) = &self.compiled.rule;
        match state.holds(slots, authority, rule, event) {
            Truth::True => Finding::Satisfied,
            Truth::False => Finding::Violated,
            Truth::Unknown => Finding::Unknown,
        }
    }
}

/// `pred` with each filter of judgments that narrows to no policy limited to the policies in
/// `visible`.
fn scope_pred(pred: &Pred, visible: &Cond) -> Pred {
    let selector = |selector: &Selector| Selector {
        filter: scope_filter(&selector.filter, visible),
        by: selector.by.clone(),
    };
    let scoped = |scope: &Scope| match scope {
        Scope::Since(since) => Scope::Since(selector(since)),
        other => other.clone(),
    };
    match pred {
        Pred::Now(_) | Pred::ModeIs(_) | Pred::ActorUnder(_) => pred.clone(),
        Pred::Once { select, scope } => Pred::Once {
            select: selector(select),
            scope: scoped(scope),
        },
        Pred::Count {
            select,
            scope,
            cmp,
            n,
        } => Pred::Count {
            select: selector(select),
            scope: scoped(scope),
            cmp: *cmp,
            n: *n,
        },
        Pred::Last {
            select,
            scope,
            test,
        } => Pred::Last {
            select: selector(select),
            scope: scoped(scope),
            test: test.clone(),
        },
        // It sums `Used` events, never judgments: only its scope may read them.
        Pred::Spent {
            meter,
            by,
            scope,
            order,
            n,
        } => Pred::Spent {
            meter: meter.clone(),
            by: by.clone(),
            scope: scoped(scope),
            order: *order,
            n: *n,
        },
        Pred::All(preds) => Pred::All(preds.iter().map(|p| scope_pred(p, visible)).collect()),
        Pred::Any(preds) => Pred::Any(preds.iter().map(|p| scope_pred(p, visible)).collect()),
        Pred::Not(inner) => Pred::Not(Box::new(scope_pred(inner, visible))),
    }
}

/// `filter`, limited to the judgments of `visible` when it looks for judgments and narrows to no
/// policy. What narrows a filter is the one answer of the predicate module
/// ([`reads_unnarrowed`]).
fn scope_filter(filter: &EventFilter, visible: &Cond) -> EventFilter {
    if !reads_unnarrowed(filter) {
        return filter.clone();
    }
    let cond = match &filter.cond {
        None => visible.clone(),
        Some(cond) => Cond::All(vec![visible.clone(), cond.clone()]),
    };
    EventFilter {
        kind: filter.kind,
        cond: Some(cond),
    }
}
