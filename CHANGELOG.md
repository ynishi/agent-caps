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

### Changed

- Breaking, before 1.0: `Scope` is no longer `Copy`, `Eq` or `Hash`, since it
  can hold a filter, and it moved from `domain::schema` to `domain::predicate`
  (#10).
- Breaking, before 1.0: `Level::Require` is removed, and `Level` is now
  `Inform < Advise < Force`. A guard that stops is `Level::Force`. A level says
  how much the agent is trusted with a rule, not when the check happens: that
  follows from the event the policy judges, and which mechanism of a platform
  stops it is the adapter's (#5).

### Fixed

- `Catalog::accept` now rejects an override that raises a guard to Force when
  the guard lacks a fixture it fails on and one it holds on
  (`AcceptError::RaisedWithoutFixtures`); before, only the level a guard was
  defined with was checked (#11).
