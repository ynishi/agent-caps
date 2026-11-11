//! The records the application writes: the catalog's (a genesis, a change, a proposal and how it
//! was settled) and a worktree's (an act, a claim with whether it took effect, a record that
//! could not be read back, and a request to write).
//!
//! Each record's fields are private and each is made through a constructor that checks what its
//! kind allows, so a record that could not have been written cannot be held: an act that is a
//! claim, a claim without its decision, a record of a judgment that came from the platform. A
//! store decodes a record through the same constructors.

use std::fmt;

use crate::domain::authority::{Authority, Principal};
use crate::domain::change::Loosening;
use crate::domain::event::{Body, Event};
use crate::domain::schema::{At, EventKind, KindSet, Nature};
use crate::domain::set::Sources;
use crate::domain::state::{Generation, Lineage};
use crate::domain::tx::TxDecision;

use super::port::{BaseId, EntryId};

/// A copy of the domain's generation of a catalog, for a record to keep: the domain's
/// [`Generation`] is made only by a catalog, so a record that says which generation it was
/// judged under holds this instead. It is read from a catalog ([`GenerationMark::of`]) and
/// compared with one ([`GenerationMark::is`]); the application never counts generations itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenerationMark {
    /// The lineage.
    pub lineage: Lineage,
    /// The place in the lineage.
    pub n: u64,
}

impl GenerationMark {
    /// The mark of `generation`.
    pub fn of(generation: &Generation) -> Self {
        Self {
            lineage: generation.lineage().clone(),
            n: generation.n(),
        }
    }

    /// Whether this is the mark of `generation`.
    pub fn is(&self, generation: &Generation) -> bool {
        &self.lineage == generation.lineage() && self.n == generation.n()
    }
}

impl fmt::Display for GenerationMark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.lineage, self.n)
    }
}

/// The version of agent-caps-core that wrote a record. A catalog that cannot be replayed is
/// reported with the version that wrote the record it stops at and the running one
/// ([`Unreplayable`](super::load::Unreplayable)), which is what tells a user to start a new
/// lineage. It is the version of the core that wrote the record, not a version of the form a
/// store keeps it in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoreVersion(String);

impl CoreVersion {
    /// The running version, fixed when the crate was compiled: `env!` reads no environment at
    /// run time.
    pub fn running() -> Self {
        Self(env!("CARGO_PKG_VERSION").to_owned())
    }

    /// The version `text`, as a store reads it back, when it is not empty.
    pub fn new(text: &str) -> Result<Self, EmptyVersion> {
        if text.is_empty() {
            Err(EmptyVersion)
        } else {
            Ok(Self(text.to_owned()))
        }
    }

    /// The text of the version.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CoreVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A version that is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyVersion;

impl fmt::Display for EmptyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a version cannot be empty")
    }
}

impl std::error::Error for EmptyVersion {}

/// Which principals of the hierarchy the platform's actors are: the user who types the prompts,
/// and the main agent. Given when a lineage starts, and kept in its genesis.
///
/// The agent is what a prompt the platform cannot show the user typed is judged as: the weakest
/// one who could have written it. Named apart from the domain's hierarchy of actors, which is
/// another thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformActors {
    user: Principal,
    agent: Principal,
}

impl PlatformActors {
    /// The actors, when both are principals of `authority`, the user is one of its roots, and
    /// the two are not one principal.
    pub fn new(
        user: Principal,
        agent: Principal,
        authority: &Authority,
    ) -> Result<Self, ActorsError> {
        for principal in [&user, &agent] {
            if !authority.contains(principal) {
                return Err(ActorsError::NotInHierarchy(principal.clone()));
            }
        }
        if !authority.is_root(&user) {
            return Err(ActorsError::UserNotRoot(user));
        }
        if user == agent {
            return Err(ActorsError::Same(user));
        }
        Ok(Self { user, agent })
    }

    /// The user.
    pub fn user(&self) -> &Principal {
        &self.user
    }

    /// The main agent.
    pub fn agent(&self) -> &Principal {
        &self.agent
    }
}

/// Why the platform's actors were not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorsError {
    /// The principal is not in the hierarchy.
    NotInHierarchy(Principal),
    /// The user is not a root of the hierarchy.
    UserNotRoot(Principal),
    /// The user and the agent are one principal.
    Same(Principal),
}

impl fmt::Display for ActorsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInHierarchy(p) => write!(f, "{p} is not in the hierarchy"),
            Self::UserNotRoot(p) => write!(f, "the user {p} is not a root of the hierarchy"),
            Self::Same(p) => write!(f, "{p} cannot be both the user and the agent"),
        }
    }
}

impl std::error::Error for ActorsError {}

/// A record of the catalog's stream. The generation of a catalog and whether a genesis started
/// the stream or a new lineage are not kept in it: both follow from where the record is in the
/// stream, and keeping them would make a second source of what the domain decides.
#[derive(Debug, Clone, PartialEq)]
pub enum CatalogRecord {
    /// A lineage started: from an empty stream (init), or over a catalog (rebase).
    Genesis(Genesis),
    /// A change took effect.
    Changed(Changed),
    /// A change that loosens what its maker does not cover, kept until it is settled.
    Proposed(Proposed),
    /// A proposal was approved, and took effect.
    Approved(Approved),
    /// A proposal was rejected.
    Declined(Declined),
}

/// The start of a lineage: the sets, the hierarchy, the platform's actors and the lineage's name.
#[derive(Debug, Clone, PartialEq)]
pub struct Genesis {
    sources: Sources,
    authority: Authority,
    actors: PlatformActors,
    lineage: Lineage,
    by: Principal,
    at: At,
    core: CoreVersion,
}

impl Genesis {
    /// The genesis, when the actors are in `authority` as [`PlatformActors::new`] says.
    pub fn new(
        sources: Sources,
        authority: Authority,
        actors: PlatformActors,
        lineage: Lineage,
        by: Principal,
        at: At,
        core: CoreVersion,
    ) -> Result<Self, ActorsError> {
        let actors = PlatformActors::new(actors.user, actors.agent, &authority)?;
        Ok(Self::founded(
            sources, authority, actors, lineage, by, at, core,
        ))
    }

    /// The genesis of actors already checked against `authority`: a
    /// [`Founding`](super::run::Founding) holds only such.
    pub(super) fn founded(
        sources: Sources,
        authority: Authority,
        actors: PlatformActors,
        lineage: Lineage,
        by: Principal,
        at: At,
        core: CoreVersion,
    ) -> Self {
        Self {
            sources,
            authority,
            actors,
            lineage,
            by,
            at,
            core,
        }
    }

    /// The sets.
    pub fn sources(&self) -> &Sources {
        &self.sources
    }

    /// The hierarchy.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// The platform's actors.
    pub fn actors(&self) -> &PlatformActors {
        &self.actors
    }

    /// The name of the lineage.
    pub fn lineage(&self) -> &Lineage {
        &self.lineage
    }

    /// Who started it.
    pub fn by(&self) -> &Principal {
        &self.by
    }

    /// When.
    pub fn at(&self) -> At {
        self.at
    }

    /// The version that wrote it.
    pub fn core(&self) -> &CoreVersion {
        &self.core
    }
}

/// A change that took effect: the sets after it. `by` is the principal it was judged as, which
/// replaying judges it as again; for a prompt the platform cannot show the user typed, that is
/// the agent.
#[derive(Debug, Clone, PartialEq)]
pub struct Changed {
    after: Sources,
    by: Principal,
    at: At,
    core: CoreVersion,
}

impl Changed {
    /// The change.
    pub fn new(after: Sources, by: Principal, at: At, core: CoreVersion) -> Self {
        Self {
            after,
            by,
            at,
            core,
        }
    }

    /// The sets after it.
    pub fn after(&self) -> &Sources {
        &self.after
    }

    /// The principal it was judged as.
    pub fn by(&self) -> &Principal {
        &self.by
    }

    /// When.
    pub fn at(&self) -> At {
        self.at
    }

    /// The version that wrote it.
    pub fn core(&self) -> &CoreVersion {
        &self.core
    }
}

/// A change kept as a proposal: the generation it was made from, the sets after it, and every
/// way it loosens, as the domain judged it when it was written. The loosenings are not judged
/// again when the proposal is read.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposed {
    base: GenerationMark,
    after: Sources,
    loosens: Vec<Loosening>,
    by: Principal,
    at: At,
    core: CoreVersion,
}

impl Proposed {
    /// The proposal.
    pub fn new(
        base: GenerationMark,
        after: Sources,
        loosens: Vec<Loosening>,
        by: Principal,
        at: At,
        core: CoreVersion,
    ) -> Self {
        Self {
            base,
            after,
            loosens,
            by,
            at,
            core,
        }
    }

    /// The generation it was made from: it is approved only from that one.
    pub fn base(&self) -> &GenerationMark {
        &self.base
    }

    /// The sets after it.
    pub fn after(&self) -> &Sources {
        &self.after
    }

    /// How it loosens.
    pub fn loosens(&self) -> &[Loosening] {
        &self.loosens
    }

    /// Who proposed it.
    pub fn by(&self) -> &Principal {
        &self.by
    }

    /// When.
    pub fn at(&self) -> At {
        self.at
    }

    /// The version that wrote it.
    pub fn core(&self) -> &CoreVersion {
        &self.core
    }
}

/// A proposal approved. It keeps the proposal's sets, so replaying it needs no other record, and
/// the proposal it settles, so which proposals are settled is read from the catalog's stream
/// alone.
#[derive(Debug, Clone, PartialEq)]
pub struct Approved {
    proposal: EntryId,
    after: Sources,
    by: Principal,
    at: At,
    core: CoreVersion,
}

impl Approved {
    /// The approval.
    pub fn new(
        proposal: EntryId,
        after: Sources,
        by: Principal,
        at: At,
        core: CoreVersion,
    ) -> Self {
        Self {
            proposal,
            after,
            by,
            at,
            core,
        }
    }

    /// The proposal it settles.
    pub fn proposal(&self) -> &EntryId {
        &self.proposal
    }

    /// The sets after it.
    pub fn after(&self) -> &Sources {
        &self.after
    }

    /// Who approved it, as it was judged.
    pub fn by(&self) -> &Principal {
        &self.by
    }

    /// When.
    pub fn at(&self) -> At {
        self.at
    }

    /// The version that wrote it.
    pub fn core(&self) -> &CoreVersion {
        &self.core
    }
}

/// A proposal rejected.
#[derive(Debug, Clone, PartialEq)]
pub struct Declined {
    proposal: EntryId,
    by: Principal,
    at: At,
}

impl Declined {
    /// The rejection.
    pub fn new(proposal: EntryId, by: Principal, at: At) -> Self {
        Self { proposal, by, at }
    }

    /// The proposal it settles.
    pub fn proposal(&self) -> &EntryId {
        &self.proposal
    }

    /// Who rejected it.
    pub fn by(&self) -> &Principal {
        &self.by
    }

    /// When.
    pub fn at(&self) -> At {
        self.at
    }
}

/// A record of a worktree's stream.
#[derive(Debug, Clone, PartialEq)]
pub enum WorkRecord {
    /// An act, which always takes effect.
    Act(ActEntry),
    /// A claim, with whether its transaction took effect.
    Claim(ClaimEntry),
    /// A record the store could not read back.
    Lost(LostEntry),
    /// A request to write, which the rules do not fold.
    Request(RequestEntry),
}

impl WorkRecord {
    /// The event the rules fold for this record, if any. This is the one place that says so: an
    /// act, a claim that took effect, and a record that could not be read back (as one that
    /// could not be read) are folded; a claim that did not take effect is not, as the state it
    /// leaves is the state before it, and a request is not, as it is not something that happened.
    pub fn folded(&self) -> Option<&Event> {
        match self {
            Self::Act(act) => Some(&act.event),
            Self::Claim(claim) => match claim.decision {
                TxDecision::Commit => Some(&claim.event),
                TxDecision::Abort => None,
            },
            Self::Lost(lost) => Some(&lost.event),
            Self::Request(_) => None,
        }
    }
}

/// Where an act came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActSource {
    /// Read from the platform.
    Platform,
    /// Made by a command to write, by the request.
    Instructed {
        /// The request.
        request: BaseId,
    },
}

/// Where a claim came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSource {
    /// Read from the platform.
    Platform,
    /// Made by the judge: the record of a judgment.
    Judge,
}

/// An act: the generation of the catalog it was judged under, where it came from, and the event.
#[derive(Debug, Clone, PartialEq)]
pub struct ActEntry {
    under: GenerationMark,
    source: ActSource,
    event: Event,
}

impl ActEntry {
    /// An act read from the platform: refused when the event is a claim, and when its kind is not
    /// taken from the platform ([`accepts_from_platform`]).
    pub fn observed(under: GenerationMark, event: Event) -> Result<Self, RecordError> {
        let kind = event.body.kind();
        if kind.nature() != Nature::Act {
            return Err(RecordError::NotAnAct(kind));
        }
        if !accepts_from_platform(kind) {
            return Err(RecordError::NotFromPlatform(kind));
        }
        Ok(Self {
            under,
            source: ActSource::Platform,
            event,
        })
    }

    /// An act made by a request: only the start of a task is.
    pub fn instructed(
        under: GenerationMark,
        event: Event,
        request: BaseId,
    ) -> Result<Self, RecordError> {
        match event.body {
            Body::TaskStart => Ok(Self {
                under,
                source: ActSource::Instructed { request },
                event,
            }),
            _ => Err(RecordError::NotATaskStart(event.body.kind())),
        }
    }

    /// The generation it was judged under.
    pub fn under(&self) -> &GenerationMark {
        &self.under
    }

    /// Where it came from.
    pub fn source(&self) -> &ActSource {
        &self.source
    }

    /// The event.
    pub fn event(&self) -> &Event {
        &self.event
    }
}

/// A claim and the decision of its transaction ([`Catalog::admit`](crate::domain::catalog::Catalog::admit)).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimEntry {
    under: GenerationMark,
    source: ClaimSource,
    event: Event,
    decision: TxDecision,
}

impl ClaimEntry {
    /// A record of a judgment made by the judge: refused when the event is not one.
    pub fn judged(
        under: GenerationMark,
        event: Event,
        decision: TxDecision,
    ) -> Result<Self, RecordError> {
        match event.body {
            Body::Judged { .. } => Ok(Self {
                under,
                source: ClaimSource::Judge,
                event,
                decision,
            }),
            _ => Err(RecordError::NotAJudgment(event.body.kind())),
        }
    }

    /// A claim read from the platform: refused when the event is an act, and when its kind is
    /// not taken from the platform ([`accepts_from_platform`]).
    pub fn observed(
        under: GenerationMark,
        event: Event,
        decision: TxDecision,
    ) -> Result<Self, RecordError> {
        let kind = event.body.kind();
        if kind.nature() != Nature::Claim {
            return Err(RecordError::NotAClaim(kind));
        }
        if !accepts_from_platform(kind) {
            return Err(RecordError::NotFromPlatform(kind));
        }
        Ok(Self {
            under,
            source: ClaimSource::Platform,
            event,
            decision,
        })
    }

    /// The generation it was judged under.
    pub fn under(&self) -> &GenerationMark {
        &self.under
    }

    /// Where it came from.
    pub fn source(&self) -> ClaimSource {
        self.source
    }

    /// The event.
    pub fn event(&self) -> &Event {
        &self.event
    }

    /// Whether it took effect.
    pub fn decision(&self) -> TxDecision {
        self.decision
    }
}

/// Whether an event of the kind may come from the platform. This is the one place that says so,
/// and the list of kinds that may not is this match alone: a record of a judgment, the answer of
/// a classifier and a score are what the judge, a classifier and an oracle state, and taking
/// them from the platform would let what the agent writes stand for them. The record of a
/// judgment enters only from the judge ([`ClaimEntry::judged`]). The start of a task is made
/// only by the request to start one, from a prompt the platform shows the user typed
/// ([`ActEntry::instructed`]): what a platform reports about its task lists (a task created or
/// completed) is not where a piece of work starts, and a start taken from it would let the agent
/// restart what a rule counts within a task.
pub fn accepts_from_platform(kind: EventKind) -> bool {
    match kind {
        EventKind::Judged | EventKind::Classified | EventKind::Measured | EventKind::TaskStart => {
            false
        }
        EventKind::SessionStart
        | EventKind::Spawn
        | EventKind::PromptSubmit
        | EventKind::ToolUse
        | EventKind::Stop
        | EventKind::Used
        | EventKind::ModeSwitch
        | EventKind::Adjust
        | EventKind::Cancel
        | EventKind::Unreadable => true,
    }
}

/// A record the store could not read back, kept as one that could not be read: the rules fold it
/// so ([`Body::Unreadable`]). Kept apart from an act that the platform could not read, so that a
/// report can say that part of the store could not be read.
#[derive(Debug, Clone, PartialEq)]
pub struct LostEntry {
    event: Event,
}

impl LostEntry {
    /// The lost record, as of when and by whom the store says it was, which may have been an
    /// event of any of the kinds in `may_have_been`.
    pub fn new(at: At, by: Principal, may_have_been: KindSet) -> Self {
        Self {
            event: Event {
                at,
                by,
                body: Body::Unreadable { may_have_been },
            },
        }
    }

    /// The event folded for it.
    pub fn event(&self) -> &Event {
        &self.event
    }
}

/// A request to write: which verb, who asked and how. It is kept apart from what the rules fold,
/// as it is not something that happened; the result it led to, if any, is the record at its
/// first derived id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEntry {
    verb: VerbName,
    by: Principal,
    at: At,
    via: Via,
}

impl RequestEntry {
    /// The request.
    pub fn new(verb: VerbName, by: Principal, at: At, via: Via) -> Self {
        Self { verb, by, at, via }
    }

    /// The verb.
    pub fn verb(&self) -> VerbName {
        self.verb
    }

    /// Who asked, as the platform reports.
    pub fn by(&self) -> &Principal {
        &self.by
    }

    /// When.
    pub fn at(&self) -> At {
        self.at
    }

    /// How the request came.
    pub fn via(&self) -> Via {
        self.via
    }
}

/// The name of a verb, without its arguments. The enum is where the names are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerbName {
    /// Start the first lineage of an empty store.
    Init,
    /// Start a new lineage over a catalog.
    Rebase,
    /// Change the sets.
    Change,
    /// Bring in a set.
    Import,
    /// Approve a proposal.
    Approve,
    /// Reject a proposal.
    Reject,
    /// Start a task.
    Task,
}

impl VerbName {
    /// The name as a command spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Rebase => "rebase",
            Self::Change => "change",
            Self::Import => "import",
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Task => "task",
        }
    }
}

impl fmt::Display for VerbName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a request came from: a fact of the platform, which the adapter tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Via {
    /// A prompt the platform shows the user typed.
    AttestedPrompt,
    /// A prompt the platform cannot tell from a turn it started itself.
    Prompt,
    /// A tool call of an agent or a sub agent.
    ToolCall,
}

/// Why a record was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// An act was asked for and the event is a claim.
    NotAnAct(EventKind),
    /// A claim was asked for and the event is an act.
    NotAClaim(EventKind),
    /// A record of a judgment was asked for and the event is not one.
    NotAJudgment(EventKind),
    /// An act made by a request was asked for and the event is not the start of a task.
    NotATaskStart(EventKind),
    /// The event is of a kind not taken from the platform ([`accepts_from_platform`]).
    NotFromPlatform(EventKind),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnAct(kind) => write!(f, "an event of kind {kind:?} is not an act"),
            Self::NotAClaim(kind) => write!(f, "an event of kind {kind:?} is not a claim"),
            Self::NotAJudgment(kind) => {
                write!(f, "an event of kind {kind:?} is not a record of a judgment")
            }
            Self::NotATaskStart(kind) => write!(
                f,
                "a request makes only the start of a task, not an event of kind {kind:?}"
            ),
            Self::NotFromPlatform(kind) => {
                write!(
                    f,
                    "an event of kind {kind:?} is not taken from the platform"
                )
            }
        }
    }
}

impl std::error::Error for RecordError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::name::ClassifierName;
    use crate::domain::policy::Level;
    use crate::domain::schema::Judgment;

    fn under() -> GenerationMark {
        GenerationMark {
            lineage: Lineage::new("l").unwrap(),
            n: 0,
        }
    }

    fn event(body: Body) -> Event {
        Event {
            at: At::from_millis(0),
            by: Principal::new("agent"),
            body,
        }
    }

    fn judged() -> Event {
        event(Body::Judged {
            policy: "00000000-0000-7000-8000-000000000001".parse().unwrap(),
            judgment: Judgment::Allowed,
            written: Level::Force,
            enforced: Level::Force,
        })
    }

    fn classified() -> Event {
        event(Body::Classified {
            classifier: "c@1".parse::<ClassifierName>().unwrap(),
            answer: 0.5,
        })
    }

    fn measured() -> Event {
        event(Body::Measured {
            oracle: "o".to_owned(),
            score: 1.0,
        })
    }

    fn spawn() -> Event {
        event(Body::Spawn {
            child: Principal::new("child"),
            under: Principal::new("agent"),
        })
    }

    #[test]
    fn only_judgments_answers_scores_and_task_starts_are_refused_from_the_platform() {
        for &kind in EventKind::ALL {
            let refused = matches!(
                kind,
                EventKind::Judged
                    | EventKind::Classified
                    | EventKind::Measured
                    | EventKind::TaskStart
            );
            assert_eq!(accepts_from_platform(kind), !refused, "{kind:?}");
        }
    }

    #[test]
    fn an_act_entry_takes_an_act_from_the_platform_and_a_task_start_from_a_request() {
        let request = BaseId::new("r").unwrap();
        assert!(ActEntry::observed(under(), event(Body::Stop)).is_ok());
        assert_eq!(
            ActEntry::observed(under(), spawn()),
            Err(RecordError::NotAnAct(EventKind::Spawn))
        );
        assert_eq!(
            ActEntry::observed(under(), judged()),
            Err(RecordError::NotAnAct(EventKind::Judged))
        );
        assert_eq!(
            ActEntry::observed(under(), event(Body::TaskStart)),
            Err(RecordError::NotFromPlatform(EventKind::TaskStart))
        );
        let task = ActEntry::instructed(under(), event(Body::TaskStart), request.clone()).unwrap();
        assert_eq!(
            task.source(),
            &ActSource::Instructed {
                request: request.clone()
            }
        );
        assert_eq!(
            ActEntry::instructed(under(), event(Body::Stop), request),
            Err(RecordError::NotATaskStart(EventKind::Stop))
        );
    }

    #[test]
    fn a_claim_entry_takes_a_judgment_from_the_judge_and_other_claims_from_the_platform() {
        let judge = ClaimEntry::judged(under(), judged(), TxDecision::Commit).unwrap();
        assert_eq!(judge.source(), ClaimSource::Judge);
        assert_eq!(
            ClaimEntry::judged(under(), spawn(), TxDecision::Commit),
            Err(RecordError::NotAJudgment(EventKind::Spawn))
        );
        let platform = ClaimEntry::observed(under(), spawn(), TxDecision::Abort).unwrap();
        assert_eq!(platform.source(), ClaimSource::Platform);
        assert_eq!(
            ClaimEntry::observed(under(), event(Body::Stop), TxDecision::Commit),
            Err(RecordError::NotAClaim(EventKind::Stop))
        );
        for (claim, kind) in [
            (judged(), EventKind::Judged),
            (classified(), EventKind::Classified),
            (measured(), EventKind::Measured),
        ] {
            assert_eq!(
                ClaimEntry::observed(under(), claim, TxDecision::Commit),
                Err(RecordError::NotFromPlatform(kind))
            );
        }
    }

    #[test]
    fn only_acts_claims_that_took_effect_and_lost_records_are_folded() {
        let act = WorkRecord::Act(ActEntry::observed(under(), event(Body::Stop)).unwrap());
        let commit =
            WorkRecord::Claim(ClaimEntry::observed(under(), spawn(), TxDecision::Commit).unwrap());
        let abort =
            WorkRecord::Claim(ClaimEntry::observed(under(), spawn(), TxDecision::Abort).unwrap());
        let lost = WorkRecord::Lost(LostEntry::new(
            At::from_millis(0),
            Principal::new("agent"),
            KindSet::any(),
        ));
        let request = WorkRecord::Request(RequestEntry::new(
            VerbName::Task,
            Principal::new("user"),
            At::from_millis(0),
            Via::AttestedPrompt,
        ));
        assert_eq!(act.folded().map(|e| e.body.kind()), Some(EventKind::Stop));
        assert_eq!(
            commit.folded().map(|e| e.body.kind()),
            Some(EventKind::Spawn)
        );
        assert_eq!(abort.folded(), None);
        assert_eq!(
            lost.folded().map(|e| e.body.kind()),
            Some(EventKind::Unreadable)
        );
        assert_eq!(request.folded(), None);
    }
}
