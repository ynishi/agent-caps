//! A policy takes effect by its bindings: the strongest binding that holds under the mode wins,
//! so adding a binding never lowers a policy. Whether a claim or a change of the catalog loosens
//! is read from the result, policy by policy: a policy that goes down asks the authors of the
//! bindings that carried the strength it lost, an exemption that starts asks the guard's author
//! and every binding's, and a policy that moves either way asks the authors of the rules that read
//! its judgments. A claim and a change are judged by the same function.

use agent_caps_core::domain::authority::NotCovered;
use agent_caps_core::domain::catalog::{AcceptError, Catalog, Effect, Target};
use agent_caps_core::domain::change::{ChangeRejected, Loosening};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::exempt::{Exempt, Lifetime};
use agent_caps_core::domain::policy::{DefLayer, Level, ModeScope, PolicyGraph};
use agent_caps_core::domain::predicate::{Cond, Lit, Scope};
use agent_caps_core::domain::schema::Field;
use agent_caps_core::domain::state::Known;
use agent_caps_core::domain::tx::checks::RuleMove;
use agent_caps_core::domain::tx::{FindingDetail, TxDecision, TxPolicy, TxReport, Verdict};

use super::common::{
    GUARD, OTHER, agent, at, bind, binding_id, catalog, graph_of, id, inside, listed, mode,
    outside, push_after_allowed, rejected, src_edit_guard, test_guard, the_agent, the_helper,
    the_user,
};

/// The effect of the guard of the scenarios under no mode.
fn guard_effect(catalog: &Catalog) -> Effect {
    listed(catalog, Known::Known(None))
        .into_iter()
        .find(|(policy, _)| *policy == id(GUARD))
        .map(|(_, effect)| effect)
        .unwrap()
}

/// The graph of `catalog` without the binding `n` of `policy`.
fn without(catalog: &Catalog, policy: &str, n: u8) -> PolicyGraph {
    let mut graph = catalog.graph();
    graph.bindings.retain(|b| b.id != binding_id(id(policy), n));
    graph
}

/// The transaction of `event` after `before`.
fn admit(catalog: &Catalog, before: &[Event], event: &Event) -> TxReport {
    catalog.admit(&catalog.fold(before), event, &TxPolicy::standard())
}

/// The verdict of the rule check in the report, which must have one.
fn rules_finding(report: &TxReport) -> &Verdict {
    &report
        .findings
        .iter()
        .find(|f| f.check.as_str() == "rules")
        .unwrap_or_else(|| panic!("no rules finding: {report:?}"))
        .verdict
}

/// The switch to the mode, by the agent's helper below it.
fn helper_switch(name: &str) -> Event {
    at(the_helper(), 0, Body::ModeSwitch { to: mode(name) })
}

/// An exemption of the guard of the scenarios for the task, of the events on `target` when one is
/// given.
fn exempt(target: Option<&str>) -> Body {
    Body::Exempt(Exempt {
        guard: id(GUARD),
        target: target.map(|path| Cond::Eq(Field::Path, Lit::Text(path.to_owned()))),
        lifetime: Lifetime::Within(Scope::Task),
        reason: "for the task".parse().unwrap(),
    })
}

/// FR42, UC20: a binding that one below adds to the user's guard does not lower it: the
/// strongest binding wins, so the change is the agent's to make and the guard stays at Force.
#[test]
fn a_binding_added_by_one_below_does_not_lower_the_rule_above() {
    let before = catalog(vec![test_guard(Level::Force)], vec![]);
    let mut graph = before.graph();
    graph
        .bindings
        .push(bind(GUARD, 1, Level::Inform, ModeScope::Any, the_agent()));
    let after = before.change(graph, &the_agent()).unwrap();
    assert_eq!(guard_effect(&after), Effect::On(Level::Force));
}

/// FR42, UC20: what one above binds cannot be taken away by one below. The agent may remove its
/// own binding of the user's guard, which the user's keeps at Force, but not the user's, which
/// carried the strength. And the user cannot bind the agent's policy at all: a binding is by the
/// policy's author or one below it.
#[test]
fn a_binding_of_the_one_above_cannot_be_removed_by_the_one_below() {
    let before = catalog(
        vec![test_guard(Level::Force)],
        vec![bind(GUARD, 1, Level::Advise, ModeScope::Any, the_agent())],
    );
    // The agent's own: removed, and nothing goes down.
    let own_removed = before
        .change(without(&before, GUARD, 1), &the_agent())
        .unwrap();
    assert_eq!(guard_effect(&own_removed), Effect::On(Level::Force));
    // The user's: not the agent's to remove, and the guard would go down to Advise, which asks
    // the user.
    let Err(ChangeRejected::Loosens(loosenings)) =
        before.change(without(&before, GUARD, 0), &the_agent())
    else {
        panic!("the agent removed the user's binding");
    };
    assert!(matches!(
        loosenings.as_slice(),
        [
            Loosening::Uncovered { target: Target::Binding(removed) },
            Loosening::Moves { mode: None, authors, .. },
        ] if *removed == binding_id(id(GUARD), 0) && *authors == vec![the_user()]
    ));
    // The user removes its own.
    before
        .change(without(&before, GUARD, 0), &the_user())
        .unwrap();

    // The user's binding of the agent's policy is not accepted.
    let mut agents = test_guard(Level::Advise);
    agents.author = the_agent();
    assert_eq!(
        rejected(
            vec![agents],
            vec![bind(GUARD, 1, Level::Force, ModeScope::Any, the_user())],
        ),
        vec![AcceptError::ReferencesBelow {
            item: Target::Binding(binding_id(id(GUARD), 1)),
            referenced: id(GUARD),
        }]
    );
}

/// FR42, UC20: a binding of one below beside the binding of the one above, at the same level, does
/// not let one below take the one above's away, nor change it, while its own masks the loss: the
/// one above's binding is not one below's to remove, and with it gone the one below's own would
/// be all that carried the strength, the one below's to drop.
#[test]
fn a_binding_of_the_one_above_cannot_be_removed_behind_one_of_ones_own() {
    let before = catalog(
        vec![test_guard(Level::Force)],
        vec![bind(GUARD, 1, Level::Force, ModeScope::Any, the_agent())],
    );
    let removed = before.change(without(&before, GUARD, 0), &the_agent());
    assert_eq!(
        removed,
        Err(ChangeRejected::Loosens(vec![Loosening::Uncovered {
            target: Target::Binding(binding_id(id(GUARD), 0)),
        }]))
    );
    let mut weakened = before.graph();
    for b in &mut weakened.bindings {
        if b.id == binding_id(id(GUARD), 0) {
            b.level = Level::Inform;
        }
    }
    assert_eq!(
        before.change(weakened, &the_agent()),
        Err(ChangeRejected::Loosens(vec![Loosening::Uncovered {
            target: Target::Binding(binding_id(id(GUARD), 0)),
        }]))
    );
    // The user may.
    before
        .change(without(&before, GUARD, 0), &the_user())
        .unwrap();
}

/// FR11, FR42, UC21: bindings of the same level inside a mode and outside it make a switch into
/// the mode neutral: nothing takes effect otherwise, so it takes effect from anyone.
#[test]
fn a_switch_between_bindings_of_the_same_level_is_neutral() {
    let mut guard = test_guard(Level::Advise);
    guard.level = None;
    let catalog = catalog(
        vec![guard],
        vec![
            bind(GUARD, 1, Level::Advise, outside(&["focus"]), the_user()),
            bind(GUARD, 2, Level::Advise, inside("focus"), the_user()),
        ],
    );
    let report = admit(&catalog, &[], &helper_switch("focus"));
    assert_eq!(report.decision, TxDecision::Commit);
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.verdict == Verdict::Neutral),
        "{report:?}"
    );
}

/// FR11, FR42, UC25: a strength only an `Outside` binding carries goes down when the mode is
/// entered, and that asks the author of that binding, not the author of the policy: the agent's
/// Force outside `explore`, beside the user's Advise, is the agent's to drop.
#[test]
fn entering_a_mode_lowers_what_only_an_outside_binding_carried_and_asks_its_author() {
    let catalog = catalog(
        vec![test_guard(Level::Advise)],
        vec![bind(
            GUARD,
            1,
            Level::Force,
            outside(&["explore"]),
            the_agent(),
        )],
    );
    let report = admit(&catalog, &[], &helper_switch("explore"));
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::Uncovered(vec![the_agent()])]
    );
    assert_eq!(
        rules_finding(&report),
        &Verdict::Loosens {
            authors: vec![the_agent()],
            detail: FindingDetail::Rules {
                moves: vec![RuleMove::Lowered {
                    policy: id(GUARD),
                    authors: vec![the_agent()],
                }],
                reading: vec![],
            },
        }
    );
    let by_agent = agent(Body::ModeSwitch {
        to: mode("explore"),
    });
    assert_eq!(admit(&catalog, &[], &by_agent).decision, TxDecision::Commit);
}

/// FR42, FR41, UC25: one below that removes its binding of the user's guard moves the judgments
/// of the guard, and so every rule that reads them: the change asks the reader's author too, and
/// is the agent's to make only where no rule of the user reads the guard.
#[test]
fn removing_a_binding_asks_the_authors_of_the_rules_that_read_its_judgments() {
    let mut guard = test_guard(Level::Force);
    guard.level = None;
    let agents_binding = bind(GUARD, 1, Level::Force, ModeScope::Any, the_agent());

    let alone = catalog(vec![guard.clone()], vec![agents_binding.clone()]);
    let off = alone
        .change(without(&alone, GUARD, 1), &the_agent())
        .unwrap();
    assert_eq!(guard_effect(&off), Effect::Off);

    let read = catalog(vec![guard, push_after_allowed(GUARD)], vec![agents_binding]);
    let Err(ChangeRejected::Loosens(loosenings)) =
        read.change(without(&read, GUARD, 1), &the_agent())
    else {
        panic!("the agent turned off a guard a rule of the user reads");
    };
    assert_eq!(
        loosenings,
        vec![Loosening::Moves {
            mode: None,
            authors: vec![the_agent(), the_user()],
            detail: FindingDetail::Rules {
                moves: vec![RuleMove::Lowered {
                    policy: id(GUARD),
                    authors: vec![the_agent()],
                }],
                reading: vec![id(OTHER)],
            },
        }]
    );
}

/// FR14, UC10: the binding of a Meta policy cannot be changed, not even by the root that wrote
/// it.
#[test]
fn the_binding_of_a_meta_policy_cannot_be_changed_even_by_the_root() {
    let mut meta = test_guard(Level::Force);
    meta.layer = DefLayer::Meta;
    let before = catalog(vec![meta.clone()], vec![]);
    let mut lowered = meta;
    lowered.level = Some(Level::Advise);
    assert_eq!(
        before.change(graph_of(vec![lowered], vec![]), &the_user()),
        Err(ChangeRejected::Meta(vec![id(GUARD)]))
    );
}

/// FR34, UC25: an exemption of a guard that is off now, bound only inside a mode, still loosens:
/// it reaches the guard whatever the mode becomes, so it asks the guard's author and the author
/// of every binding of it, under any mode.
#[test]
fn an_exemption_of_a_guard_off_now_asks_the_authors_of_its_bindings() {
    let mut guard = test_guard(Level::Force);
    guard.level = None;
    let catalog = catalog(
        vec![guard],
        vec![bind(GUARD, 1, Level::Force, inside("bugfix"), the_agent())],
    );
    assert_eq!(guard_effect(&catalog), Effect::Off);
    let report = admit(&catalog, &[], &agent(exempt(None)));
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::Uncovered(vec![the_user()])]
    );
    assert_eq!(
        rules_finding(&report),
        &Verdict::Loosens {
            authors: vec![the_user(), the_agent()],
            detail: FindingDetail::Rules {
                moves: vec![RuleMove::Exempted {
                    policy: id(GUARD),
                    authors: vec![the_user(), the_agent()],
                }],
                reading: vec![],
            },
        }
    );
    assert_eq!(
        admit(&catalog, &[], &at(the_user(), 0, exempt(None))).decision,
        TxDecision::Commit
    );
}

/// FR34, UC25: exemptions are counted one by one, so a wide exemption added to a guard that has a
/// narrow one in effect loosens it, and so does the same narrow one again.
#[test]
fn a_wider_exemption_beside_a_narrow_one_loosens_too() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let narrow = at(the_user(), 0, exempt(Some("src/a.rs")));
    let before = [agent(Body::TaskStart), narrow.clone()];
    assert_eq!(
        admit(&catalog, &before[..1], &narrow).decision,
        TxDecision::Commit
    );
    for claim in [exempt(None), exempt(Some("src/a.rs"))] {
        let report = admit(&catalog, &before, &agent(claim));
        assert_eq!(report.decision, TxDecision::Abort, "{report:?}");
        assert!(matches!(
            rules_finding(&report),
            Verdict::Loosens {
                detail: FindingDetail::Rules { moves, .. },
                ..
            } if *moves == vec![RuleMove::Exempted {
                policy: id(GUARD),
                authors: vec![the_user()],
            }]
        ));
    }
}
