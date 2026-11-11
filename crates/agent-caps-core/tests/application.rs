//! Scenarios of the application: what the use cases do over a store, written against the public
//! API only, in one test binary apart from the domain's scenarios (`tests/scenarios/`), whose
//! groups they leave as they are.
//!
//! The store is the in-memory one of `common/log.rs`, which lives here and not in the library.
//! Writers racing each other, and a store that breaks its promises, are made by it with no thread
//! and no sleep, so each scenario runs the same way every time. Every test cites the requirement of
//! the ledger it checks.
//!
//! - `lineage`: the catalog's line, its replay, and what an empty or unreplayable store answers.
//! - `evidence`: what an observation judges and writes, and how it takes in a racing writer.
//! - `requests`: the operations that write, who may make them from where, and their results.

// The modules live in `application/`, beside this file, as the domain's do in `scenarios/`.
#[path = "application/common/mod.rs"]
mod common;

#[path = "application/evidence.rs"]
mod evidence;
#[path = "application/lineage.rs"]
mod lineage;
#[path = "application/requests.rs"]
mod requests;
