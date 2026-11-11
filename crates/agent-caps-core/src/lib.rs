//! Core (SDK) of agent-caps: the policy catalog and the judge, with no I/O.
//!
//! [`domain`] holds the model: policies, the events they judge, the state folded from those
//! events, and the judgment. It is pure: no file system, process, environment, network, clock or
//! randomness. Those come in as values, read by the umbrella crate's adapters.
//! [`application`] holds the use cases around it: the catalog and the evidence kept in a store
//! behind one port ([`application::Log`]), what to judge and write for an observation, and the
//! operations that write. It is as pure, and holds no runtime and no shared mutable state.
//!
//! ```text
//! adapter ─▶ application (Service<L: Log>) ─▶ domain
//!                 │ Log (the one port)
//!                 ▼
//!              a store
//! ```
//!
//! `arch-lint.toml` at the workspace root states this, and that the domain knows nothing of the
//! application, and `cargo test` (`tests/architecture.rs`) fails when code breaks it.
#![warn(missing_docs)]

pub mod application;
pub mod domain;
