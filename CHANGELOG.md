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
- A rule that code cannot express can be judged by a classifier (#1, UC23,
  FR26, FR52). The classifier's answer is a recorded claim, `Body::Classified
  { classifier: ClassifierName, answer: f64 }` (`EventKind::Classified`, of
  `Nature::Claim`; `Field::Classifier` and `Field::Answer`), which an ordinary
  rule reads with `Last`, counted only from one who covers the rule's author as
  any record a rule reads is, so an answer the agent writes counts neither way.
  `ClassifierName` is a name that may hold `@`, so the version is part of it
  (`commit-why@3`; `NameError::Classifier`). Two `Body` values compare the
  answer as a number with NaN equal to NaN, as a score.
- The declaration of a classifier is an item of the policy graph:
  `Classifier { name, author, bound: Calibration, record:
  Option<CalibrationRecord> }`, made with `PolicyGraph::parse_with` and read
  with `classifiers()` and `classifier(name)`. `Calibration::new(min_cases,
  max_false_stops)` refuses a bound of no case, and
  `CalibrationRecord::new(cases, false_stops)` a record with more false
  stops than cases (`CalibrationError`); their fields are read with getters.
  `Calibration::admit(record)` is the one place that says whether a record
  suffices (`Err(Shortfall)`, `Short { cases, false_stops }` or `Missing`).
  The declaration composes as a policy does (FR48): the same declaration in
  two sets is one item, and two different ones under a name are a
  `Clash::Classifier`; declare a classifier in one set and read it by name
  from the others.
- A policy that judges `Classified` events reads the classifier its `when`
  narrows to, by the same rule, and is refused, lowered and reported as a
  policy with a filter is.
- A policy reads a classifier with a filter of `Classified` events that
  narrows to its name with `classifier == name`. The catalog refuses a filter
  that does not (`AcceptError::UnnamedClassifier`), a name no set declares
  (`UndeclaredClassifier`), a declaration of an author below the policy's own
  (`ReferencesBelow`, with `Target::Classifier`) and a Meta policy that reads
  one (`MetaReadsClassifier`).
- A guard at Force that reads a classifier takes effect at Force only while
  the record of each classifier it reads meets the bound of its declaration;
  otherwise it is Advise, and `Effective::degraded` reports one
  `Degraded::Uncalibrated { guard, classifier, shortfall, to }` for each
  classifier that falls short. Decided in `Catalog::effective`, so `effective`,
  `effective_in`, `enforced`, `judge` and `Catalog::change` agree. A reward
  bound to a lowered guard follows it.
- `Catalog::change` judges a classifier declaration as it judges a policy
  (`change::classify_classifier`): a declaration removed, or changed in its
  bound or its record, is a loosening that needs one who covers its author.
- A bound on how long a temporary adjustment may last (#56). The root declares
  it, in a set it owns, with `PolicyGraph::parse_with(.., Some(TemporaryBound))`
  (`TemporaryBound::from_millis`, more than zero), and `Catalog::accept` decides
  it once; `Catalog::temporary_bound()` reads it. An adjustment states the time
  it ends by (`Adjustment::ends_by`), and one that ends further ahead of the
  clock than the bound, or lasts within a window of `Every` longer than the
  bound, is refused (`Inadmissible::EndsTooLate`, `WindowTooLong`), never
  rounded. One made before the first act has no clock to be checked against, so
  it is held and checked at the first act, where it ends if it lies too far
  ahead. Every adjustment ends at the time it ends by, or sooner by its
  lifetime's event, which closes the gap that a `Within` a mode, a `since`
  scope or a span, and an exemption for `Next`, had no end. The unseen past of a
  fold from `Origin::Unknown` is held unseen until the bound has passed since
  its first act (FR20), not for the whole fold. Changing the bound is a change
  of the root's set, judged as any (FR49), so one who does not cover the root
  cannot change it in either direction.
  New accept errors: `AcceptError::NoTemporaryBound`, `BoundNotRoot { set }`
  and `BoundConflict`. FR46 is withdrawn for FR55, which adds the bound; the
  tests and use cases that cite FR46 cite FR55.
- A judgment state is tied to the catalog generation that made it (#55, FR56).
  `Lineage` is a name the caller gives a catalog accepted from nothing
  (`Lineage::new`, not empty), and `Generation { lineage, n }` is the version of
  a catalog: `Catalog::accept` starts a lineage at 0 and `Catalog::change`
  keeps it and goes one on (`Catalog::generation()`; a number that cannot go on
  is `ChangeRejected::GenerationsExhausted`). `Catalog::start` stamps its
  generation on the state (`State::generation()`), and `Catalog::owns(&State)`
  is the one check that the state is the catalog's. A state of another
  generation is refused as a `StaleState`, which holds both generations and
  says `kind()`: `Staleness::Behind` (fold the history again under this
  catalog), `Ahead` (this catalog is the old one) or `OtherLineage` (the wrong
  catalog). `Catalog::apply` and `apply_with` give a refused state back in
  `StaleApply`. The domain compares positions only: naming a lineage once and
  keeping it a single line, one change from the current generation, are the
  application's and the store's.
- `TxInput::effective_before()` and `effective_after()`: what takes effect
  before a claim and after it as the next event finds it, which leaves out an
  adjustment that lasted only within a scope the claim closed, for a check of
  one's own. `RuleCheck` reads the state after a claim in the same place.

### Changed

- Breaking, before 1.0: a state is used only with the catalog generation that
  made it (#55). `Catalog::accept(sources, authority, lineage)` takes a
  `Lineage`. `Catalog::apply` and `apply_with` return
  `Result<State, StaleApply>`; `Catalog::admit`, `judge`,
  `Catalog::effective_in` and `Catalog::enforced_in` return
  `Result<_, StaleState>`. `fold` and `fold_with` start the state themselves
  and stay as they were. `TxInput` has private fields, made only by the
  transaction: read them with the getters `catalog()`, `event()`, `before()`,
  `after()` and `changes()`. To migrate, name a lineage when a catalog is
  accepted from nothing, handle the refusal of a state of another generation
  (fold the history again under a changed catalog), and call a getter where a
  check read a field.
- Breaking, before 1.0: a temporary adjustment states the time it ends by, and
  a catalog declares a bound (#56). `Lifetime` is `Next`, `Within(Scope)` and
  `Timed`: `Lifetime::Until(At)` is removed, and `Adjustment` has a required
  `ends_by: At`, the only end by time, so `Until(t)` is written `Timed` with
  `ends_by: t`. A catalog must declare the bound in a set a root owns, and every
  root that owns a set declares the same value: `Catalog::accept` refuses one
  with none (`NoTemporaryBound`, which includes a catalog with no set a root
  owns, that is, one whose sets all have owners below the roots), a declaration
  in a set whose owner is not a root (`BoundNotRoot`), and roots that declare
  different values or a root that owns a set and declares none (`BoundConflict`).
  `PolicyGraph::parse_with` takes the bound as a fourth argument (`None`
  declares none; `parse` declares none), and `PolicyGraph::into_parts` returns
  it as a fourth element. `Inadmissible::Expired` now means the time it ends by
  is at or before the clock. To migrate, add a set owned by a root that declares
  the bound, write `ends_by` on every adjustment, and replace `Until` with
  `Timed`.
- A temporary adjustment no longer ends at every session start (#54): one
  that lasts within a mode, a `since` scope, or a span whose starter does not
  choose the session's starter outlasts the session, as a count does. Until a
  bound on how far ahead an adjustment's end may lie is added (#56), such an
  adjustment has no upper bound; #54 and #56 are meant to ship together.
- Breaking, before 1.0: the periods that events open are nested spans with a
  stated starter, and a fold says what it knows of the past (#54). The new
  `Span` (`Session`, `Task`, `Turn`) has `Span::opening()`, the event that
  opens it, and `Span::inside(outer)`, how spans nest: a session holds tasks
  and turns, which are siblings. `Scope::Session`, `Scope::Task(By)` and
  `Scope::Turn(By)` are replaced by `Scope::Span { span, by }`, so a span's
  starter cannot be left out (a session had none). The start of a span starts
  again that span and the spans inside it, each only when its own `By`
  chooses the actor of the start event, and nothing outside it: a user's
  session start starts `Span { Task, Only(user) }` again and an agent's does
  not, so an agent cannot start its limit over by starting a session; a task's
  start does not start a turn again. A record that could not be read and may
  have been the start of a span leaves that span and the spans inside it
  unknown, whoever its `By` chooses, which closes the known gap that a lost
  start left a scope looking as if it had not started again. One lost line may
  have been any of the starts, so it leaves the counts of every span unknown
  until their next start and a stopping rule on them stops more (FR20).
  `Scope::by()` is that of `Span` and `Since`; `Mode` and `Every` have none.
  `Catalog::start`, `Catalog::fold` and `Catalog::fold_with` take an `Origin` as
  their first argument, with no default: `Origin::Genesis` is the start there
  was (the history is whole, counts start at zero), `Origin::Unknown` starts in
  the middle of a history, with every slot, the mode and the clock as after a
  record that could not be read, and an adjustment made before the fold may only
  strengthen the rules. `State::origin()` and `State::may_hold_unseen()` (a lost
  adjustment record, or an `Unknown` origin) are new, and the effect of the rules
  reads the latter in place of `adjustments_lost()`. Until a bound on how long an
  adjustment lasts is in, the strengthening holds for the whole of an `Unknown`
  fold. P19 is withdrawn for P20, and FR44 is withdrawn for FR54, which names the
  start events of every span.
  To migrate, write `Scope::Span { span: Span::Task, by }` for `Task(by)`,
  `Span::Turn` for `Turn(by)`, and `Span::Session` with the `By` that chooses
  who may start the session again (`By::Anyone` for the old behaviour) for
  `Session`, and pass `Origin::Genesis` where the history is whole. A
  `Span::Task` or `Span::Turn` whose `By` is `Under` or `Only` no longer starts
  again at every session's start, only at one whose starter it chooses.
- A session's start no longer starts a `since` scope or the scope of a mode
  again (FR33 is withdrawn for FR53, and P20 replaces P19). A `Span` is started again only by the
  start of its span or of one it is inside, and only when its `By` chooses the
  one who started it; a `Since` scope is closed only by the event it looks for,
  and `Scope::Mode` by a mode switch. A test or a review that came before a new
  session therefore still counts, which loosens a rule that relied on the
  session to forget it; write the span the rule is about, or close the `Since`
  with the event that should end it.
- Breaking, before 1.0: the classifier adds variants and a field type.
  `Body::Classified`, `EventKind::Classified`, `Field::Classifier` and
  `Field::Answer`, `Degraded::Uncalibrated`, `Clash::Classifier`,
  `Target::Classifier`, `NameError::Classifier`, and `AcceptError::
  UnnamedClassifier`, `UndeclaredClassifier` and `MetaReadsClassifier` are
  new variants, and a `match` on one of these enums that has no wildcard arm
  stops compiling. `AcceptError::ReferencesBelow { item,
  referenced }` now holds a `Target` in `referenced` (`Target::Policy(id)` for
  what it held before), so that it can name a classifier.
  `PolicyGraph::into_parts` returns the classifiers too, `(Vec<PolicyDef>,
  Vec<Binding>, Vec<Classifier>)`, so that `parse_with` takes back exactly
  what it gave; a caller that destructures the pair adds the third.

- Knowledge, a document meant for the agent's context, is no longer seen as
  part of the Core domain (#12). Putting it into the agent's context is a
  platform's form of context, as an instruction file or a skill is (FR51,
  Adapter, undecided). What can be observed of it, an edit of an area
  without having read its design document in the task, is an ordinary guard
  bound at Advise, which warns and does not stop (UC28, which replaces
  UC13). The scenario no longer writes knowledge as a reward with a guard
  that cannot fail to carry it; a reward is still always bound by a guard.
  No API changes.
- Breaking, before 1.0: a catalog is accepted from sets of policies, and
  keeps them (#47). The new module `domain::set` has `SetId` (a surrogate
  key in the hyphenated UUID form, as `PolicyId` is; `NameError::SetId` for
  one that is not), `SetName` (a name, as `Mode` is), `Source { id, name,
  owner, graph }`, `Sources` (by id, made by `Sources::new`, which refuses an
  id given twice and a name given twice, every one at once, with
  `SourcesError::Duplicate` and `DuplicateName`; changed into another value
  by `with`, `without(id)` and `replaced`, which make it through `new` again
  and refuse an id that is missing with `Unknown`; a new version keeps its id
  and may change its name) and `JoinConflict`, which names the two sets by
  id. `Catalog::accept(sources, authority)` and `Catalog::change(after, by)`
  take `Sources`; write a single graph as
  `Sources::new(vec![Source { id, name, owner, graph }])?`, with an owner
  that every author of the graph is or is below. `Catalog::sources()` returns
  the sets, and `Catalog::graph()` the graph they compose to. Sets compose by
  adding only (`Sources::compose`): the policies and bindings of every set, by
  id, an item two sets hold the same once, and two different items under one
  id, or two policies of one name, a conflict (`AcceptError::Conflict`, with
  the `Clash` and the two sets, every pair that differs, in `SetId` order).
  The join is commutative, associative and idempotent; nothing is replaced by
  id and no set wins over another, so the caller's composition that let a
  later binding take the place of one with its id is gone. Accepting checks
  that every item of a set is by its owner or one below
  (`AcceptError::NotWithinOwner`) and that the owner is of the hierarchy
  (`AcceptError::UnknownOwner`). A change judges a set as an item whose author
  is its owner (`Target::Set`): adding, removing, replacing, renaming or
  re-owning a set whose owner `by` does not cover is a `Loosening::Uncovered`, reported beside
  what its items loosen; so a change by one below no longer edits a binding of
  a set above in place, even to raise it, and adds a binding in its own set
  instead. A swap of a set (`replaced`) is one change. A set holding a meta
  policy enters only when a catalog is first accepted. In the ledger, FR3,
  FR4 and FR25 are withdrawn for FR48, FR49 and FR50, and UC7 for UC27.
- Breaking, before 1.0: a policy graph is keyed by id (#46). The fields of
  `PolicyGraph` are private, and a graph is made only by
  `PolicyGraph::parse(policies, bindings)`, which refuses a second policy or
  binding with an id already there, even an equal one, and a second policy
  with a name already there, returning every clash at once
  (`Vec<GraphError>`, each with its `Clash`: `Policy(id)`, `Binding(id)` or
  `Name(name)`). Write `PolicyGraph { policies, bindings }` as
  `PolicyGraph::parse(policies, bindings)?`, and read a graph with
  `policies()`, `bindings()`, `policy(id)`, `binding(id)` or `into_parts()`.
  `AcceptError::DuplicateId`, `DuplicateName` and `DuplicateBinding` are gone:
  a graph cannot hold what they reported, and the clash is reported by
  `parse` instead. `Catalog::accept` and `Catalog::change` take the graph as
  before, and `Catalog::graph()` returns `&PolicyGraph`.
- Breaking, before 1.0: every list follows one order, by id, whatever order
  the policies and bindings were written in (#46): `Catalog::policies`,
  `Effective::policies` and `Enforced::policies`, the policies a filter of
  judgments sees (and so the slots two policies share), and what a judgment
  reports (the causes of a verdict, the rewards, what was degraded and
  lowered). No decision changes: the strongest binding and the strongest
  result still win whatever the order.
- Breaking, before 1.0: the number a condition compares a field with is a
  `Number` (#46): `Cond::Num(Field, Cmp, Number)`. `Number::new` refuses NaN
  and the infinities (`NumberError`) and takes negative numbers. With it,
  `PolicyDef`, `Binding`, `Fixture`, `Rule`, `Pred`, `Cond`, the types they
  hold, `Event`, `Body` and `Adjustment` are `Eq`, so a policy equals itself.
  Two `Body` values compare the score of a `Measured` as a number with NaN
  equal to NaN: a NaN score equals itself; `0.0` and `-0.0` are equal.
- Breaking, before 1.0: a rule can limit the sum of an amount used, such as
  the tokens of a task (#42). The new act `Body::Used { meter: Meter, amount:
  Option<Amount> }` (`EventKind::Used`, of `Nature::Act`) is what the platform
  measured as used; the adapter carries it as it carries the origin of any
  act. The new operator `Pred::Spent { meter, by, scope, order, n }` sums the
  amounts of the `Used` events of the meter whose actor `by` chooses, within
  the scope (every scope, `Every` and `Task(By)` included). Its `by` is the new
  `Whose` (`Anyone` or `Under(Principal)`), a `By` without `Only`: what is
  delegated counts toward the one who delegates, so a sub agent's use counts
  toward the principal it is spawned under, and no budget can be escaped by
  delegating. The `By` doc now says that an upper bound chosen with `Only`
  does not count what its principal delegates. It compares the
  sum with `n` by an `Order` (`Lt`, `Le`, `Ge`, `Gt`: no equality on a sum).
  `Amount::new` refuses NaN, the infinities and negative numbers
  (`AmountError`), and a sum is held at the largest finite number. `Meter` is
  a name, as `Mode` is, and the new `Field::Meter` (text, of `Used`) lets a
  condition test it; the amount is read only by `Spent`. A `Used` whose amount
  is `None` makes only a sum of its meter unknown, so a stopping guard stops; a
  `count` of `Used` events and a `Since` a `Used` closes still read it. A sum
  can pass its bound by one event, since an amount is known after the use, and
  an amount that goes down (a gauge) cannot be written. `Body`, `EventKind`
  and `Field` are `#[non_exhaustive]`, so a match on them outside the crate
  already has a wildcard arm; `Pred` is not, so an exhaustive match on `Pred`
  outside the crate needs a new arm for `Spent`. The ledger has FR47 for it,
  and UC26 cites it.
- Breaking, before 1.0: time is a clock that only acts advance, and a period
  can be a window of time (#42). The new `Scope::Every(Window)` is the window
  of fixed length the clock is in, aligned to the Unix epoch in UTC, and starts
  again when the clock crosses a boundary; `Window::from_millis` refuses zero
  and negative lengths (`WindowError::NotPositive`). A `SessionStart` does not
  start a window again, so a window spans sessions only as far as the caller
  folds. The state's clock is the latest time an act has carried, and no time
  before the first act; a claim's time never moves it, and an act dated
  earlier never moves it back. Every end by time reads it: a raise or a
  suspension with `Until` now ends at the first act at or after its instant,
  not at a claim dated after it, and an adjustment is `Inadmissible::Expired`
  only when the clock, not the claim's own time, is past its `Until`; before
  the first act nothing has ended by time. The one read that may take a
  claim's time is an exemption's cover, read at the later of the clock and the
  judged event's time, so a guard that judges a claim dated past an
  exemption's `Until`, or past the window of `Every` it lasts within, is not
  exempted. To read old folds: an `Until` compared
  with the time of a claim now waits for the next act, and an exemption or a
  raise claimed with a time past its `Until`, while the last act's time is
  still before it, is admitted, and ends at the next act at or after it. A
  record that could not be read advances the clock only when it may have been
  an act; one that may have been only claims carries a claim's time, and moves
  nothing. The ledger's P16 is withdrawn for P19 and FR43 for FR46, which
  reads a lifetime by the clock; FR45 is new, and UC6 and UC25 cite FR46.
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
