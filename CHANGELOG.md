# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A requirements ledger, `agent_caps::_requirements`: use cases, principles and
  functional requirements in one module doc, outside semver. `cargo test`
  checks its tables and every `UC<n>` / `FR<n>` cited in a doc comment, and
  fails on a test of the core that cites neither (#13).
- `Catalog::effective(mode)`: every policy with its `Effect` (`On(level)` or
  `Off`) under a mode, and what was degraded, without judging an event. It is
  what `judge` reads, so a platform adapter and a judgment see the same list
  (#6).
- `Scope::Since(EventFilter)`: a period that lasts from the last event that
  matches the filter. The matching event belongs to the interval it closes, so
  `once(test, Since(commit))` stops a second commit with no new test in between.
  Usable as the scope of `once`, `count` and `last`, and as the lifetime of an
  exemption (`Within(Since(..))`). When it cannot be told whether the interval
  closed (a condition not known yet, a record that could not be read), the
  scope's facts become unknown. The filters of `Since` are type-checked when a
  catalog is accepted, and an exemption that arrives as an event takes effect
  only if its target and filter type-check against the guard it names (#10).
- `EventFilter::check`.
- `domain::authority`: `Principal` (an opaque key) and `Authority`, a hierarchy
  of principals with one or more roots that cannot be made with a cycle or an
  unknown parent. `Authority::covers(actor, author)` says whether the actor is
  the author or above it. The module knows nothing of policies; `arch-lint.toml`
  keeps it so (#14).
- `Catalog::change(after, by)`: accepts a changed policy graph and judges
  whether `by` may make the change. What `by` covers is free to change; of what
  it does not cover, no policy may be removed, nothing may be loosened (an
  override is judged by what its policy comes to), nothing new may be made,
  and no policy may take effect below what it is without `by`'s own work,
  under no mode or any named mode (an unknown mode follows from them). A meta
  policy never differs, for anyone.
  Rejections are `ChangeRejected` (`Invalid`, `Meta`, `UnknownPrincipal`,
  `Loosens` with each `Loosening`). `classify` gives the direction of one
  policy's difference (a change to its examples loosens: they are the evidence
  for the rule), and `PolicyGraph::not_covered_by` narrows a graph (#14).
- New accept checks: every author is of the hierarchy
  (`AcceptError::UnknownAuthor`), a meta policy is written by a root
  (`MetaAuthorNotRoot`), and an item refers only to items of its own author or
  above it (`ReferencesBelow`), a reward's `bound_by` and an override's target
  (#14).
- `domain::tx`: a claim (an exemption, a mode switch, a record of a judgment or
  a score) is a transaction. It is applied to a copy of the state, judged by
  the difference (`State` changes) from several points of view
  (`AdjustmentCheck`, each giving a `CheckFinding` with a `Verdict`: `Neutral`,
  `Tightens(Confidence)` or `Loosens { authors, .. }`), and kept as a whole or
  not at all. The domain's checks (`ExemptionCheck`, `ModeCheck`, `SlotCheck`)
  always apply; a `TxPolicy` adds checks of its own and the `Combine` that
  merges the findings (`TxPolicy::standard()`: none added, `AllOk`). The floor
  is fixed: a loosening finding whose authors the claim's author does not
  cover aborts the claim, whatever the combination says.
  `Catalog::apply_with` and `Catalog::fold_with` take a `TxPolicy`;
  `Catalog::admit` reports the decision and every finding (`TxReport`).
- `EventKind::nature`: whether a kind of event is an act (observed on the
  platform, always taken as it is) or a claim (`Nature`).
- `Authority::may_loosen(by, authors)`: the one question of whether `by` may
  loosen what the authors wrote (`NotCovered::UnknownPrincipal` or
  `Uncovered`). `Catalog::change` and the transaction of a claim both ask it.
- `catalog::lowered` and `Lowered`: the policies whose effect goes down from one
  effective list to another, read by `Catalog::change` and `ModeCheck`.
- `KindSet`: the kinds of event a record that could not be read may have been.

- `Pred::ActorUnder(principal)`: a rule for a role, as a condition on the acting
  principal (the event's `by`): it holds when the actor is the principal or sits
  below it in the hierarchy of actors, which is the `Authority` plus the leaves
  that spawns add. An actor the hierarchy does not know, or one placed after a
  record that may have been a spawn was lost, is unknown, so a stopping rule
  stops it. No event needs to end a role. `Catalog::accept` rejects a rule that
  names a principal outside the hierarchy (`AcceptError::UnknownActor`).
- `Body::Spawn { child, under }` and `EventKind::Spawn`: a sub agent joins the
  hierarchy of actors under a place. A spawn is a claim, judged as a
  transaction by the new domain check `SpawnCheck` against a place directly
  under its spawner: a child placed into a principal that a rule applies inside
  tightens it (open to anyone); one that leaves a principal such a rule applies
  inside, or that is read in a direction that cannot be told (outside a
  principal, in a guard's `rule`, in a reward), loosens it, and takes effect
  only from one who covers the rule's author. `StateChange::ActorAdded` and
  `FindingDetail::Spawn` carry it. A spawned leaf is no author, so what it
  claims loosens nothing. The ledger has P15 and FR38 for it, and FR39 for the
  scope of one actor, which is undecided.
- `Capabilities`: what a platform can enforce, as data in the words of an event
  filter (a level per `EventFilter`, and an `otherwise`), type-checked by
  `Capabilities::new` and supplied with each judgment. The catalog is the same
  on every platform. The cap of an event (`Capabilities::cap`) is the lowest
  level among the possible worlds, so a filter that cannot tell whether it
  matches counts too; the cap of a kind (`Capabilities::cap_kind`) is a `Cap`,
  `Fixed` or `ByEvent { at_least, at_most }`. Whether a filter matches is
  decided by the matcher the state already uses.
- The strength a policy is written at (`Effective`, unchanged) and the strength
  a platform enforces it at (`Enforced`, with `EnforcedPolicy` and
  `EnforcedEffect`) are separate types. `Catalog::enforced(mode, caps)` lists
  the second, and `judge` and the list lower through one function, so the list
  never says more than a judgment does. A reward follows the level its guard is
  enforced at on every event of the guard's kind. What was lowered is
  `Lowering` (`BeyondCapability`, `RewardFollowsGuard`), apart from what the
  layers degraded (`Degraded`). `Catalog::change`, the checks of a claim and
  the fixtures read only the written strength.
- `Catalog::check_capabilities(caps)`: what a platform cannot hold of a
  catalog, mode by mode (the modes `Catalog::change` compares), for an adapter
  that refuses such a catalog when it loads it. The core always lowers and
  reports at run time.
- The ledger's FR28 is withdrawn for FR40, which widens it: per event filter
  instead of per kind of event, the level a policy was written at and the level
  it was enforced at recorded with each judgment, and a catalog checked against
  the capabilities. FR31 and the use cases UC11, UC17 and UC24 cite FR40.

### Changed

- Breaking, before 1.0: a rule says whose events it means, and who may start
  its scope again (#42, #25). `once`, `count` and `last` take `select:
  Selector { filter: EventFilter, by: By }` instead of `event: EventFilter`,
  and `Scope::Since` takes a `Selector`. `By` is `Anyone`, `Under(Principal)`
  or `Only(Principal)` and has no default: `Under(p)` takes only the events
  whose actor is `p` or below it in the hierarchy of actors, read as
  `Pred::ActorUnder` reads it, and an actor whose place is not known makes the
  choice unknown; `Only(p)` takes the events of `p` itself, reads no hierarchy
  and is never unknown. `Scope::Task` is
  now `Scope::Task(By)`, started again by a `TaskStart` whose actor the `By`
  chooses, and the new `Scope::Turn(By)` starts again at a `PromptSubmit`.
  `EventFilter` is unchanged and stays event-only: `Capabilities` and the cover
  of an exemption cannot hold a `By`. To translate, `event: f` becomes
  `select: Selector { filter: f, by: By::Anyone }`, `Scope::Since(f)` becomes
  `Scope::Since(Selector { filter: f, by: By::Anyone })`, and `Scope::Task`
  becomes `Scope::Task(By::Anyone)`. `Anyone` keeps today's meaning, where the
  acts of the one a limit is about can start its count over. That one sits
  below whoever set the limit, so `Under` of the limit's author takes its acts
  too: a limit only one principal may start again, such as at most three pushes
  since the last review by the user, is written with `Only`, which no spawn can
  move. A principal a `By::Under` or `By::Only` names must be in the hierarchy
  (`AcceptError::UnknownActor`, as for `ActorUnder`), and a temporary
  adjustment whose lifetime chooses by one that is not is refused with the new
  `Inadmissible::UnknownActor`. A spawn that places a child under the principal
  of an `Under` is judged
  as a loosening of the rule's author, and one that changes who ends a
  temporary adjustment lasting within such a scope as a loosening of the one
  who made it: `FindingDetail::Spawn::loosened` is now `Vec<Reader>`, with
  `Reader::Policy(PolicyId)` or `Reader::Adjustment(AdjustmentId)`. When a
  start or close of a scope is unknown (an actor of unknown place, a condition
  not known yet), an adjustment that lasts within it no longer ends: it is kept
  with `HeldAdjustment::holding` set to the new `Holding::MaybeEnded`, and read
  in the direction that tightens (its exemption covers nothing, the bindings it
  adds still hold, its suspensions no longer hold) until a known start or close
  ends it; before, an unknown close ended a raise with no transaction.
  `HeldAdjustment` has the new public field `holding`. The ledger's FR39 is
  withdrawn for FR44, and UC26 is new.
- Breaking, before 1.0: an exemption is one kind of temporary adjustment, and
  a temporary adjustment can also add and suspend bindings for a while (#39).
  The module `domain::exempt` is now `domain::adjust`. `Body::Exempt(Exempt)`
  is replaced by `Body::Adjust(Adjustment { id: AdjustmentId, change:
  Temporary, lifetime, reason })`, with `Temporary::Exempt { guard, cover }`
  (the old `target` is `cover`) or `Temporary::Rebind { add:
  Vec<TemporaryBinding { policy, level }>, suspend: Vec<BindingId> }`, and
  `Body::Cancel { id }` ends the adjustment in effect with that id.
  `EventKind::Exempt` is replaced by `EventKind::Adjust` and
  `EventKind::Cancel`, both claims. To translate,
  `Body::Exempt(Exempt { guard, target, lifetime, reason })` becomes
  `Body::Adjust(Adjustment { id, change: Temporary::Exempt { guard, cover:
  target }, lifetime, reason })` with an id of the caller's that no
  adjustment in effect holds; `Exempt::check` is gone (whether one may take
  effect is decided inside the catalog). `AdjustmentId` (and
  `NameError::AdjustmentId`) is new. An adjustment or a cancel that cannot
  take effect, whoever makes it, is aborted, and the new field
  `TxReport::inadmissible: Option<Inadmissible>` says why: its id is held
  (`DuplicateId`), its lifetime has run out by the time of its claim
  (`Expired`), it names a policy or binding the catalog lacks
  (`UnknownPolicy`, `UnknownBinding`) or one of the meta layer (`Meta`), an
  exemption names no guard (`NotAGuard`) or its cover does not type-check
  (`ExemptionError`), a `Since` filter of its lifetime does not type-check
  (`SinceFilterError`), a temporary binding is Force on a reward
  (`RewardForce`) or on a guard without the fixtures of a stopping guard
  (`MissingFixtures`), a rebinding lasts for `Lifetime::Next`
  (`NextOnRebind`) or changes nothing (`Empty`), the maker of a temporary
  binding is not in the hierarchy, a spawned leaf included (`AuthorUnknown`),
  or is neither the policy's author nor below it (`AuthorAbove`), the same
  rule a binding of the catalog keeps, now asked of both through the new
  `Authority::within` (with `NotWithin`); a cancel of an id that is not held
  is `NotHeld`. Code that builds a `TxReport` sets the new field.
  `StateChange::ExemptionAdded(PolicyId)` and
  `ExemptionEnded(PolicyId)` are `AdjustmentAdded(AdjustmentId)` and
  `AdjustmentEnded(AdjustmentId)`. `State::adjustments()` lists the
  adjustments in effect, each a `HeldAdjustment { by, adjustment }`, and
  `State::adjustments_lost()` tells whether a record that may have been an
  adjustment or a cancel was lost. `Catalog::effective_in(&State)` adds the
  state's adjustments to `Catalog::effective`, and `judge` and the checks of a
  claim read it; under a lost record of an adjustment no suspension holds and
  every policy outside the meta layer takes effect at least as strongly as a
  temporary binding could make it (Force for a guard with stopping fixtures,
  Advise otherwise). A lost record that may have been a cancel also ends every
  exemption held. An adjustment and a cancel are judged by their result
  through `rule_moves`: a temporary binding that carried a lost strength asks
  the one who made it, so cancelling another's raise asks the raiser; a claim
  that closes the `Within(Since(..))` scope of an adjustment is judged by that
  adjustment's end; and the new `RuleMove::Suspended { policy, binding,
  authors }` asks the suspended binding's author whether or not the policy
  goes down. An adjustment that runs out by time is not judged: its lifetime
  is its maker's choice, and event times are the adapter's to give.
  `Catalog::enforced_in(&State, &Capabilities)` lists what is enforced with
  the state's adjustments; `Catalog::enforced(mode, caps)` stays the catalog
  as written. The ledger
  withdraws P14 for P18 and FR30 and FR32 for FR43; UC6 and UC25 cite FR43.
- Breaking, before 1.0: a policy holds no strength; a binding does (#39).
  `Binding { id: BindingId, policy, level, mode: ModeScope, author }` puts a
  policy into effect at a level where its scope holds (`ModeScope::Any`,
  `In(mode)`, `Outside(ModeSet)`, answered by `ModeScope::holds`, which is
  unknown when the mode is not known). A policy takes effect at the strongest
  level of its bindings that hold, and is off with none, so adding a binding
  never lowers a policy. `PolicyGraph` has `bindings` in place of
  `overrides`; `Override`, `OverrideLayer`, `Change`, `RewardLevel`,
  `PolicyDef::enabled`, `Policy::enabled`, `Policy::base_level` and
  `PolicyGraph::not_covered_by` are removed, and `Polarity` is `Guard` or
  `Reward { bound_by }` with no level. `ModeSet::new` refuses an empty set and
  a mode given twice (`ModeSetError`); `BindingId` reads a hyphenated UUID, as
  `PolicyId` does (`NameError::BindingId`). To translate a graph: `Off`
  removes the binding, `On` adds one, `Level` replaces the binding with one at
  the other level, and a mode's override turns the binding into
  `Outside([mode])` beside an `In(mode)` binding at the mode's level.
- Breaking, before 1.0: `Catalog::accept` checks the bindings. Binding ids are
  unique (`AcceptError::DuplicateBinding`), a binding names a policy of the
  graph (`UnknownBindingPolicy`), its author is in the hierarchy
  (`UnknownAuthor` with `Target::Binding`) and is the policy's author or below
  it (`ReferencesBelow`), no reward is bound at Force (`RewardForce`), a guard
  bound at Force has a fixture it fails on and one it holds on
  (`MissingFixtures { policy, binding }`), and a meta policy has exactly one
  binding, by its author, under `ModeScope::Any` (`MetaBinding`). The variants
  `RewardAboveGuard`, `RaisedWithoutFixtures`, `UnknownOverride`,
  `MetaOverride`, `RewardOverrideLevel` and `DuplicateOverride` and
  `Target::Override` are removed. A reward whose bindings are stronger than its
  guard's is lowered to the guard and reported as `Degraded`, as before.
- Breaking, before 1.0: when the mode is not known, `Catalog::effective`
  computes each mode it may be (no mode, and every mode a binding's scope
  names), rewards held to their guards in each, and each policy takes the
  strongest effect any of them gives, and nowhere else is that decided; so a
  guard is the strongest any of its bindings gives.
- Breaking, before 1.0: how the rules take effect in a claim is judged by one
  new domain check, `RuleCheck`, over the whole state before and after, once
  per claim, through `rule_moves` (`RuleMove`: `Lowered`, `Raised`,
  `Exempted`, `Unexempted`). A policy that goes down asks the authors of the
  bindings that carried the strength it lost; an exemption that starts (each
  one counted, so a wider exemption beside a narrower one is one that starts)
  asks the guard's author and the author of every binding of it, under any
  mode. `ExemptionCheck` is removed, and `ModeCheck` only reads how rules read
  the mode with `ModeIs`. A policy that moves either way now loosens every
  other policy that reads its judgments (before, only one that came to apply to
  more did), for the rules, a mode switch and a spawn alike.
  `FindingDetail::ExemptionAdded` is removed, `FindingDetail::Mode` has only
  `reading`, and `FindingDetail::Rules { moves, reading }` is new.
- Breaking, before 1.0: `Catalog::change` judges what takes effect by the same
  `rule_moves` as a claim, under every compared mode (no mode, and every mode a
  binding's scope names), with the readers of the catalogs before and after;
  every author a loosening asks must be covered. A new binding in the name of
  one the changer does not cover, and one of theirs removed, lowered, given
  another scope or taken over (even while an equal binding of the changer's
  keeps the policy's strength), is `Loosening::Uncovered` with
  `Target::Binding`. The comparison with the graph narrowed to what the
  changer does not cover is removed, with `Loosening::BelowUncovered`; its
  place is `Loosening::Moves { mode, authors, detail }`. So a change that only
  tightens is no longer rejected for falling below that floor. A meta policy's
  binding differing is `ChangeRejected::Meta`, whoever changes it. `classify`
  no longer compares a level or an on and off state.
- The ledger withdraws P9 for P17 (Trust is held by the bindings of a rule)
  and FR5 and FR6 for FR42 (a permanent change of the level or the on and off
  state, by the bindings, judged by its result). UC7 cites FR42, FR31 cites
  P17, and P4, P14 and FR11 no longer speak of overrides.
- Breaking, before 1.0: `Pred::Last` is `Last { event: EventFilter, scope, test:
  Cond }` in place of `Last { field, scope, value }`: the last event within the
  scope that matches the filter, and a condition on it, the same condition a
  `Now`, a `Once` or a `Count` takes, so a score can be compared
  (`Last { Measured where oracle == "bench", Session, score >= 0.8 }`). The old
  form is `Last { event: EventFilter { kind: field.kind(), cond: None }, scope,
  test: Cond::Eq(field, value) }`. The slot holds the last matching event, and
  the condition is checked and evaluated as any other (no new error). A `last`
  of judgments now has a filter, so it can name policies, is limited to the
  policies its author may count when it names none, and is accepted beside a
  policy below when it names none of them; a policy named in its test is
  checked like one named in its filter (a `last` of judgments whose test names a
  policy below is `ReferencesBelow`); the ledger's FR37 is withdrawn for FR41,
  which says so.
- A mode switch is judged by the direction in which a policy reads the mode
  (`Reads::modes` carries it, as the actors do): it tightens a policy that
  applies inside a mode it enters, and loosens one that applies inside a mode it
  leaves or that reads the mode in a direction that cannot be told (under a
  `not`, in a guard's `rule`, in a reward), as a placement of a spawned child
  does. Before, any policy that read the mode before or after loosened. A mode
  that is not known before the switch counts the mode it goes to as entered, and
  every other mode as left. One rule of direction (`Move`, `direction`) serves
  the mode check and the spawn check. A policy a claim makes apply to more
  writes more judgments, so every other policy that reads its judgments is
  loosened by the claim too, for a mode switch and for a spawn alike: a lower
  principal's switch or placement that makes a guard apply to more no longer
  takes effect while a rule of a higher author reads that guard's judgments.
- Breaking, before 1.0: `judge(catalog, state, event, &Capabilities)` takes the
  platform's capabilities (`Capabilities::full()` lowers nothing).
  `GuardResult` and `RewardResult` have `written` and `enforced` in place of
  `level`, and a guard stops by `enforced`. `Outcome` has `lowered` beside
  `degraded`, of the policies that judged the event. `Body::Judged` has
  `written` and `enforced`, and `Outcome::evidence` copies them from the
  results, so a warning that was written as a stop is told from one that was
  written as a warning. The transaction of a claim (`apply_with`, `fold_with`,
  `admit`, `TxPolicy`) is unchanged and does not see the capabilities.
  `Level` is defined in `domain::schema` (so that an event can carry it) and is
  still read as `domain::policy::Level`.
- Breaking, before 1.0: `Body::AgentStart`, `EventKind::AgentStart`,
  `Field::AgentType` and `Scope::Agent` are removed, replaced by `Body::Spawn`
  and `Pred::ActorUnder`. A role is read from where the actor sits, not from
  the last agent type seen, so a role needs no event to end it and a rule
  needs no copy per role. "Once for each agent" can no longer be written
  (FR39). `StateChange`, `AcceptError`, `FindingDetail`, `EventKind`, `Pred`
  and `Body` each have new variants; the ledger's P12 is withdrawn for P16
  (the scope's vocabulary without an agent).
- Breaking, before 1.0: `schema::Origin` and `schema::Source` are removed, with
  `EventKind::source` and `EventKind::may_be_lost_in`. The domain holds no
  roles: an `Event` has `by: Principal`, and whether a claim takes effect is
  decided by the catalog's `Authority`, not by who the event is from. A
  loosening claim takes effect only from one who covers the authors of what it
  loosens; one that only tightens takes effect from anyone, a principal outside
  the hierarchy included.
- Breaking, before 1.0: a filter of judgments that does not narrow to named
  policies (`count(Judged where judgment == denied, Session) < 5`, or
  `any(policy == id, judgment == denied)`) sees only the
  judgments of the policies in the catalog whose authors cover its policy's
  author, its own and those above, instead of every policy's; so a rule of
  one above no longer stops the ones below from adding a policy, and their
  records of judgments do not count for it. It no longer counts a judgment of a
  policy that is not in the catalog. Who is visible is decided once, when the
  catalog is accepted, and compiled into the predicate the catalog uses; the
  policy as written is kept, so `Catalog::graph` and `Catalog::change` read
  what was written. A policy named in a filter of judgments, in any shape of
  filter, is still rejected when it is below (`ReferencesBelow`), and so is a
  `last` of a judgment's field beside a policy below, as it reads every policy.
  A Meta policy may not read judgments without naming the policies, a `last`
  of a judgment's field included (`AcceptError::MetaReadsUnscoped`). A text
  that is an id only in another case (`policy == "ABCD…"`) names no policy, as
  no judgment's policy reads as it. The ledger's FR35 is withdrawn for FR37
  (#31).
- Breaking, before 1.0: `Body::Unreadable` holds `may_have_been: KindSet`, the
  kinds the lost record may have been, given by the adapter (`KindSet::any`
  when it cannot tell; there is no empty default), instead of where
  it was. The state makes unknown only what an event of each of those kinds may
  have changed: the slots that read it, a `Since` scope looking for it, the mode
  and the mode's scope for a mode switch, an exemption for the next judgment for
  a judgment.
- Breaking, before 1.0: `GuardResult` and `RewardResult` have the judged
  policy's `author` and are no longer `Copy`, and `Outcome::evidence` writes
  each record of a judgment in the name of that author.
- Breaking, before 1.0: `AcceptError::ReferencesBelow` also covers what a
  predicate reads. A policy may read the judgments only of policies whose
  authors cover its own: a filter that names a policy below is not accepted,
  and a `last` of a judgment's field reads every policy. (A filter that names no
  policy sees only the judgments of its own author and those above: see the
  entry for #31.)
- Fixtures are folded by the same transaction as a run, so a claim in a fixture
  takes effect, or not, as it would at run time.
- Breaking, before 1.0: `PolicyDef` and `Override` have an `author:
  Principal`, and `Catalog::accept(graph, authority)` takes the `Authority` the
  catalog is accepted with and keeps it (`Catalog::authority`). To change the
  hierarchy, accept the graph again with the new one (#14).
- Breaking, before 1.0: `Effect` is ordered `Off, On(Level)` and derives
  `PartialOrd` and `Ord`, so `Off < On(Inform) < On(Advise) < On(Force)`; the
  variants changed places (#14).
- Breaking, before 1.0: `Scope` is no longer `Copy`, `Eq` or `Hash`, since it
  can hold a filter, and it moved from `domain::schema` to `domain::predicate`
  (#10).
- Breaking, before 1.0: `Level::Require` is removed, and `Level` is now
  `Inform < Advise < Force`. A guard that stops is `Level::Force`. A level says
  how much the agent is trusted with a rule, not when the check happens: that
  follows from the event the policy judges, and which mechanism of a platform
  stops it is the adapter's (#5).

### Fixed

- "The latest bench score is at least 0.8" can be written: the last score of an
  oracle compared as a number, so a high score that a low one followed no
  longer lets a turn end (#4).
- A record of a judgment or a measured score no longer counts whoever writes
  it: one that would move a rule's slot counts only from one who covers the
  rule's author, so a `denied` written by one below the guard's author does not
  let a deny-once guard through (#3). A mode switch now takes effect from anyone
  when it lowers no policy's effect and moves nothing a rule reads of an author
  it does not cover (a rule that reads the mode with `ModeIs`, or a slot that
  restarts with the mode); and a principal may exempt the guards whose authors
  it covers, its own included (#17).
- `Catalog::effective` under an unknown mode now computes every mode to the
  end, rewards bound to their guards, and gives each policy the strictest
  effect any of them gives. Before, it took each policy's strictest level
  before binding the rewards, which could give a reward a level no mode gives;
  what is listed as degraded is now only what the strictest effect still shows
  (#14).
- `Catalog::accept` now rejects an override that raises a guard to Force when
  the guard lacks a fixture it fails on and one it holds on
  (`AcceptError::RaisedWithoutFixtures`); before, only the level a guard was
  defined with was checked (#11).
