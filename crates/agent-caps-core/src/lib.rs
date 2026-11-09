//! Core (SDK) of agent-caps: the policy catalog and the judge, with no I/O.
//!
//! [`domain`] holds the model: policies, the events they judge, the state folded from those
//! events, and the judgment. It is pure: no file system, process, environment, network, clock or
//! randomness. Those come in as values, read by the umbrella crate's adapters.
//! `arch-lint.toml` at the workspace root states this, and `cargo test`
//! (`tests/architecture.rs`) fails when code breaks it.
#![warn(missing_docs)]

pub mod domain;
