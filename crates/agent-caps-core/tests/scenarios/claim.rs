//! A claim is a transaction: it is applied to a copy of the state, judged from several points of
//! view, and kept as a whole or not at all. The domain's checks always apply; a `TxPolicy` adds
//! checks and the `Combine` of the findings. The floor is fixed: a loosening finding whose
//! authors the claim's author does not cover aborts the claim, whatever the combination says.

use agent_caps_core::domain::adjust::Lifetime;
use agent_caps_core::domain::authority::{NotCovered, Principal};
use agent_caps_core::domain::catalog::{Capabilities, Catalog};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Verdict, judge};
use agent_caps_core::domain::policy::Level;
use agent_caps_core::domain::predicate::{By, Scope, Span};
use agent_caps_core::domain::state::{Known, Origin};
use agent_caps_core::domain::tx::{
    AdjustmentCheck, CheckFinding, CheckName, Combine, Confidence, TxDecision, TxInput, TxPolicy,
    Verdict as Direction,
};

use super::common::{
    GUARD, OTHER, agent, at, bind, catalog, edit, exempt_n, id, inside, mode, src_edit_guard,
    test_guard, the_user,
};

/// One outside the scenarios' hierarchy.
fn stranger() -> Principal {
    Principal::new("stranger")
}

/// An exemption of the guard of the scenarios for the task.
fn exempt() -> Body {
    exempt_n(
        1,
        GUARD,
        None,
        Lifetime::Within(Scope::Span {
            span: Span::Task,
            by: By::Anyone,
        }),
    )
}

/// The root's guard on edits under `src/`, Force, and Force on the end of a turn in `fix`.
fn src_and_fix() -> Catalog {
    let mut stop = test_guard(Level::Advise);
    stop.id = id(OTHER);
    stop.name = "stop-guard".parse().unwrap();
    catalog(
        vec![src_edit_guard(), stop],
        vec![bind(OTHER, 1, Level::Force, inside("fix"), the_user())],
    )
}

/// A combination that commits whatever the findings are.
struct AlwaysCommit;

impl Combine for AlwaysCommit {
    fn combine(&self, _findings: &[CheckFinding]) -> TxDecision {
        TxDecision::Commit
    }
}

/// A combination that aborts on any finding a check is not sure of.
struct OnlyCertain;

impl Combine for OnlyCertain {
    fn combine(&self, findings: &[CheckFinding]) -> TxDecision {
        let unsure = findings
            .iter()
            .any(|f| matches!(f.verdict, Direction::Tightens(Confidence::Uncertain(_))));
        if unsure {
            TxDecision::Abort
        } else {
            TxDecision::Commit
        }
    }
}

/// A check from outside that finds every claim tightening, with the given confidence.
struct SaysTightens(Confidence);

impl AdjustmentCheck for SaysTightens {
    fn judge(&self, _input: &TxInput<'_>) -> Vec<CheckFinding> {
        vec![CheckFinding {
            check: CheckName::new("says-tightens"),
            verdict: Direction::Tightens(self.0),
        }]
    }
}

/// The verdict on the last event, with the state folded with `policy`.
fn verdict_with(catalog: &Catalog, events: &[Event], policy: &TxPolicy) -> Verdict {
    let state = catalog.fold_with(Origin::Genesis, events, policy);
    judge(
        catalog,
        &state,
        events.last().unwrap(),
        &Capabilities::full(),
    )
    .unwrap()
    .verdict
}

/// UC25, FR34, FR11: a principal outside the hierarchy covers nobody's work, so its loosening
/// claim does not take effect, for `UnknownPrincipal`; its tightening claim does, since a
/// tightening is open to anyone.
#[test]
fn a_stranger_cannot_loosen_but_can_tighten() {
    let catalog = src_and_fix();
    let start = catalog.fold(Origin::Genesis, [&agent(Body::TaskStart)]);
    let report = catalog
        .admit(&start, &at(stranger(), 0, exempt()), &TxPolicy::standard())
        .unwrap();
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::UnknownPrincipal(stranger())]
    );

    let switch = at(stranger(), 0, Body::ModeSwitch { to: mode("fix") });
    let report = catalog
        .admit(&start, &switch, &TxPolicy::standard())
        .unwrap();
    assert_eq!(report.decision, TxDecision::Commit);
    assert!(report.uncovered.is_empty());
    assert_eq!(
        catalog
            .fold(Origin::Genesis, [&agent(Body::TaskStart), &switch])
            .mode(),
        &Known::Known(Some(mode("fix")))
    );
}

/// FR36, UC25: a combination that always commits does not get past the floor: the exemption from
/// below of the root's guard is aborted, and the report says whose cover is missing. With no
/// check added, the domain's checks still apply.
#[test]
fn a_combination_that_commits_cannot_get_past_the_floor() {
    let catalog = src_and_fix();
    let policy = TxPolicy {
        extra: Vec::new(),
        combine: Box::new(AlwaysCommit),
    };
    let start = agent(Body::TaskStart);
    let claim = agent(exempt());
    let report = catalog
        .admit(&catalog.fold(Origin::Genesis, [&start]), &claim, &policy)
        .unwrap();
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::Uncovered(vec![the_user()])]
    );
    assert!(matches!(
        verdict_with(&catalog, &[start, claim, edit("src/a.rs")], &policy),
        Verdict::Deny(_)
    ));
}

/// FR36, UC23: a check added from outside cannot cancel a loosening: its tightening finding sits
/// beside the domain's, and the floor still aborts the claim from below.
#[test]
fn an_added_check_cannot_cancel_a_loosening() {
    let catalog = src_and_fix();
    let policy = TxPolicy {
        extra: vec![Box::new(SaysTightens(Confidence::Certain))],
        combine: Box::new(AlwaysCommit),
    };
    let start = agent(Body::TaskStart);
    let claim = agent(exempt());
    let report = catalog
        .admit(&catalog.fold(Origin::Genesis, [&start]), &claim, &policy)
        .unwrap();
    assert_eq!(report.decision, TxDecision::Abort);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == CheckName::new("says-tightens"))
    );
    assert!(matches!(
        verdict_with(&catalog, &[start, claim, edit("src/a.rs")], &policy),
        Verdict::Deny(_)
    ));
}

/// FR36, UC23: a combination may abort a claim the floor lets through: here, on an uncertain
/// finding of a check added from outside, the root's tightening switch is aborted. With the
/// standard policy, the same switch takes effect.
#[test]
fn a_combination_may_abort_on_an_uncertain_finding() {
    let catalog = src_and_fix();
    let policy = TxPolicy {
        extra: vec![Box::new(SaysTightens(Confidence::Uncertain(0.6)))],
        combine: Box::new(OnlyCertain),
    };
    let start = agent(Body::TaskStart);
    let switch = at(the_user(), 0, Body::ModeSwitch { to: mode("fix") });
    let report = catalog
        .admit(&catalog.fold(Origin::Genesis, [&start]), &switch, &policy)
        .unwrap();
    assert_eq!(report.decision, TxDecision::Abort);
    assert!(report.uncovered.is_empty());
    assert_eq!(
        catalog
            .fold_with(Origin::Genesis, [&start, &switch], &policy)
            .mode(),
        &Known::Known(None)
    );
    assert_eq!(
        catalog.fold(Origin::Genesis, [&start, &switch]).mode(),
        &Known::Known(Some(mode("fix")))
    );
}
