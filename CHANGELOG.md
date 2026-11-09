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
- `EventKind::source`: where events of a kind are recorded (caps's evidence or
  the transcript), `EventKind::may_be_lost_in`, and `EventFilter::check`.
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

### Changed

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
