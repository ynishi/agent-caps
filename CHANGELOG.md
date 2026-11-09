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

### Fixed

- `Catalog::accept` now rejects an override that raises a guard to Require or
  Force when the guard lacks a fixture it fails on and one it holds on
  (`AcceptError::RaisedWithoutFixtures`); before, only the level a guard was
  defined with was checked (#11).
