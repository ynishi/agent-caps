//! The one part of a catalog: a policy, the bindings that put it into effect, and the policy graph
//! both are written in.
//!
//! A policy says, for one kind of event, what must hold (a guard) or what is recommended (a
//! reward). It holds no strength of its own. A [`Binding`] is one author's statement that a policy
//! takes effect at a [`Level`] where its [`ModeScope`] holds; a policy takes effect at the
//! strongest level of its bindings that hold, and with none it is off. Adding a binding therefore
//! never lowers a policy. Procedures and roles are not parts of their own: each is a set of
//! policies seen another way. Knowledge, a document meant for the agent's context, is no part of
//! the domain: it is not a rule, and putting it into a context is the platform's. What can be
//! observed of it, such as an edit without the read, is an ordinary policy.
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
//! - A [`PolicyGraph`] holds its policies and bindings by id, no id twice and no policy name
//!   twice: [`PolicyGraph::parse`] refuses otherwise ([`Clash`]), through one insert, and so does
//!   the composition of sets ([`super::set`]), which takes an equal item of two sets once. Its
//!   order is by id, the one order of everything a catalog lists.
//! - A [`Policy`] is made only by [`super::catalog::Catalog::accept`], which checks the graph as a
//!   whole (see there). The [`PolicyDef`] it is made from is plain data with no rule of its own.
//! - A [`Policy`] keeps its [`PolicyDef`] as written, and the predicates the catalog uses. The
//!   two differ only in a filter of judgments that narrows to no policy: the catalog's predicate
//!   counts the judgments of the policies its author may count (see [`super::catalog`]). The
//!   written def is what a graph and a difference between graphs are read from; the compiled
//!   predicates are what is evaluated and what the slots are made of.

use std::collections::btree_map::{self, BTreeMap, Entry};
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A policy as written in a policy graph: plain data, checked when a catalog accepts it. Its
/// equality is total: a policy equals itself, whatever its conditions and examples hold.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// What a catalog is accepted from: the policies, and the bindings that put them into effect,
/// each keyed by its id. No two policies share an id or a name, and no two bindings share an id:
/// [`PolicyGraph::parse`] and [`super::set::Sources::compose`] are the only ways to make one with
/// items, both through one insert, so a graph that exists cannot hold a duplicate, and code that
/// reads a graph does not check for one again.
///
/// The graph has one order, by id, whatever order the items were given in: its policies and its
/// bindings are read in it, and so is every list a catalog makes of them (see
/// [`super::catalog`]). Two graphs with the same items are equal, and a policy equals itself,
/// since every value in it has an equality that is total ([`super::predicate::Number`]).
///
/// What the items say of each other (a binding names a policy that exists, a reward a guard) is
/// checked when a catalog accepts the graph, with everything else that needs the hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyGraph {
    policies: BTreeMap<PolicyId, PolicyDef>,
    bindings: BTreeMap<BindingId, Binding>,
    /// Each policy's name, with its id: kept by the one insert beside `policies`, and the names
    /// of exactly its policies in every graph `parse` returns.
    names: BTreeMap<PolicyName, PolicyId>,
}

/// One item that may enter a graph, given to the one insert.
pub(super) enum Item {
    // Boxed: a policy is several times the size of a binding.
    Policy(Box<PolicyDef>),
    Binding(Binding),
}

/// Where an item given to the one insert comes from, as against the items already there: what
/// decides whether an equal item with an id already there is a clash or the same item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Origin {
    /// The same graph as written ([`PolicyGraph::parse`]): a second item with an id already
    /// there is a clash even when the two are equal, since it is a slip of the one who wrote it.
    Written,
    /// Another set of policies than the items there ([`super::set::Sources::compose`]): an equal
    /// item is the same item, held by both, and enters once.
    Joined,
}

/// Why an item cannot enter a graph: the graph already has one with its id, or a policy with its
/// name. A second item with an id already there is a clash, unless it is equal and comes from
/// another set ([`super::set::Sources::compose`]); in one graph it is a slip of the one who wrote
/// it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Clash {
    /// A second policy has the id.
    Policy(PolicyId),
    /// A second binding has the id.
    Binding(BindingId),
    /// A second policy has the name.
    Name(PolicyName),
}

impl fmt::Display for Clash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(id) => write!(f, "two policies have the id {id}"),
            Self::Binding(id) => write!(f, "two bindings have the id {id}"),
            Self::Name(name) => write!(f, "two policies have the name {name}"),
        }
    }
}

/// One reason a graph could not be made of the items given ([`PolicyGraph::parse`]): the
/// [`Clash`]. It is a type of its own, not the clash alone, so that it can say later where the
/// item came from without a change to what it says now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphError {
    clash: Clash,
}

impl GraphError {
    /// The clash.
    pub fn clash(&self) -> &Clash {
        &self.clash
    }
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.clash.fmt(f)
    }
}

impl std::error::Error for GraphError {}

impl PolicyGraph {
    /// The graph of `policies` and `bindings`, when no two policies share an id or a name and no
    /// two bindings share an id. Otherwise every clash found, each once, in the order of
    /// [`Clash`]: the policies' ids, then the bindings' ids, each by id, then the names.
    ///
    /// An id given twice is a clash of the id, and a name given with two different ids a clash
    /// of the name, so what is found does not depend on the order the items were given in. The
    /// name of a policy is checked whether or not its id clashed; an equal policy given twice has
    /// its name under one id, and clashes by its id alone.
    pub fn parse(
        policies: Vec<PolicyDef>,
        bindings: Vec<Binding>,
    ) -> Result<Self, Vec<GraphError>> {
        let mut graph = Self::default();
        let items = policies
            .into_iter()
            .map(|def| Item::Policy(Box::new(def)))
            .chain(bindings.into_iter().map(Item::Binding));
        let mut clashes: Vec<Clash> = items
            .flat_map(|item| {
                graph
                    .insert(item, Origin::Written)
                    .err()
                    .unwrap_or_default()
            })
            .collect();
        if clashes.is_empty() {
            return Ok(graph);
        }
        clashes.sort();
        clashes.dedup();
        Err(clashes
            .into_iter()
            .map(|clash| GraphError { clash })
            .collect())
    }

    /// Puts `item` in the graph, unless an item with its id is there already, or, for a policy,
    /// a policy of another id has its name: the one place that decides whether an item may enter
    /// a graph. An item with an id already there is the same item, and enters once, only when it
    /// is equal and comes from another set (`origin`, [`Origin::Joined`]). The id and the name of
    /// a policy are checked apart, and every clash is returned.
    ///
    /// A key that is free is taken even when the item clashes on the other, so a later item is
    /// compared with every id and name given before it. A graph with a clash is never returned
    /// ([`PolicyGraph::parse`], [`super::set::Sources::compose`]), so this leaves no graph that
    /// holds one.
    pub(super) fn insert(&mut self, item: Item, origin: Origin) -> Result<(), Vec<Clash>> {
        let mut clashes = Vec::new();
        match item {
            Item::Policy(def) => {
                match self.names.entry(def.name.clone()) {
                    Entry::Occupied(owner) if *owner.get() != def.id => {
                        clashes.push(Clash::Name(def.name.clone()));
                    }
                    Entry::Occupied(_) => {}
                    Entry::Vacant(slot) => {
                        slot.insert(def.id);
                    }
                }
                match self.policies.entry(def.id) {
                    Entry::Occupied(there) if origin == Origin::Joined && *there.get() == *def => {}
                    Entry::Occupied(_) => clashes.push(Clash::Policy(def.id)),
                    Entry::Vacant(slot) => {
                        slot.insert(*def);
                    }
                }
            }
            Item::Binding(binding) => match self.bindings.entry(binding.id) {
                Entry::Occupied(there) if origin == Origin::Joined && *there.get() == binding => {}
                Entry::Occupied(_) => clashes.push(Clash::Binding(binding.id)),
                Entry::Vacant(slot) => {
                    slot.insert(binding);
                }
            },
        }
        if clashes.is_empty() {
            Ok(())
        } else {
            Err(clashes)
        }
    }

    /// The policies, by id.
    pub fn policies(&self) -> btree_map::Values<'_, PolicyId, PolicyDef> {
        self.policies.values()
    }

    /// The bindings, by id.
    pub fn bindings(&self) -> btree_map::Values<'_, BindingId, Binding> {
        self.bindings.values()
    }

    /// The policy with the id.
    pub fn policy(&self, id: PolicyId) -> Option<&PolicyDef> {
        self.policies.get(&id)
    }

    /// The binding with the id.
    pub fn binding(&self, id: BindingId) -> Option<&Binding> {
        self.bindings.get(&id)
    }

    /// Every item, the policies by id, then the bindings by id: what the one insert takes, for a
    /// graph composed of several ([`super::set::Sources::compose`]).
    pub(super) fn items(&self) -> impl Iterator<Item = Item> + '_ {
        self.policies
            .values()
            .map(|def| Item::Policy(Box::new(def.clone())))
            .chain(self.bindings.values().cloned().map(Item::Binding))
    }

    /// Whether the graph holds an item where `clash` is, without copying it ([`Self::item_at`]).
    pub(super) fn holds(&self, clash: &Clash) -> bool {
        match clash {
            Clash::Policy(id) => self.policies.contains_key(id),
            Clash::Name(name) => self.names.contains_key(name),
            Clash::Binding(id) => self.bindings.contains_key(id),
        }
    }

    /// The item the graph holds where `clash` is: the policy with the id or the name, or the
    /// binding with the id.
    pub(super) fn item_at(&self, clash: &Clash) -> Option<Item> {
        let policy = |id: &PolicyId| self.policies.get(id);
        let def = match clash {
            Clash::Policy(id) => policy(id),
            Clash::Name(name) => self.names.get(name).and_then(policy),
            Clash::Binding(id) => {
                return self.bindings.get(id).cloned().map(Item::Binding);
            }
        };
        def.map(|def| Item::Policy(Box::new(def.clone())))
    }

    /// The policies and the bindings, each by id: what [`PolicyGraph::parse`] takes, for a caller
    /// that makes another graph from this one.
    pub fn into_parts(self) -> (Vec<PolicyDef>, Vec<Binding>) {
        (
            self.policies.into_values().collect(),
            self.bindings.into_values().collect(),
        )
    }
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
