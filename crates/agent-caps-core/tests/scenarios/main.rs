//! Scenarios: what the Core domain should do, written against its public API only, in one test
//! binary. Each module is one topic and says in its own doc which scenario it checks.
//!
//! The scenarios have three groups: judging (a verdict on an event), seeing (whether a policy set
//! can express knowledge, a role or a procedure, and whether it reads naturally), and the
//! effective form (which policies hold at which level, and what operating on the layers does,
//! including who may change whose rules).
//!
//! Where the model cannot yet do what a scenario wants, the gap is kept in one place:
//!
//! - A policy that gives a wrong finding on an example carries a fixture with the right
//!   expectation and `known_gap: true`; a paired test in the same module pins the finding it gives
//!   today, and fails when the gap is fixed.
//! - A gap outside the policy that the public API can state is a test with the right
//!   expectation, marked `#[ignore = "..."]` with the issue; `cargo test -- --ignored` shows it
//!   fails.
//! - A gap that cannot be written (no type, no entry point, no event) is a test of what holds
//!   today where there is one, and the doc of its module says what is missing.
//!
//! A gap that was fixed is no longer kept: its module says it was fixed and where the fix is
//! checked. Every test cites the use case or the requirement of the ledger it checks.

mod common;

mod accept;
mod adjust;
mod authority;
mod binding;
mod capability;
mod claim;
mod commit_after_test;
mod compose;
mod deny_once;
mod effective;
mod exemption;
mod knowledge;
mod last;
mod layers;
mod limits;
mod mode_switch;
mod procedure;
mod refine;
mod reward;
mod role;
mod since;
mod timing;
mod typecheck;
mod unreadable;
