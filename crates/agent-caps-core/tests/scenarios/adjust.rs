//! Temporary adjustments: bindings added and suspended for a lifetime, seen in the state, and
//! cancelled. A claim of one, and its cancel, are judged by their result: a policy that goes down
//! asks the authors of the bindings that carried what it lost (a temporary binding by the one who
//! made it), and a binding suspended asks its author whether or not the policy goes down. A
//! temporary binding is by the policy's author or one below it, as a binding of the catalog is.
//! One that cannot take effect, whoever makes it, is aborted and its transaction says why. A lost
//! record of one makes every rule as strong as a temporary binding could make it.

use agent_caps_core::domain::adjust::{Inadmissible, Lifetime, Temporary, TemporaryBinding};
use agent_caps_core::domain::authority::{NotCovered, Principal};
use agent_caps_core::domain::catalog::{Catalog, Effect};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::name::BindingId;
use agent_caps_core::domain::policy::{DefLayer, Level};
use agent_caps_core::domain::predicate::{EventFilter, Scope};
use agent_caps_core::domain::schema::{At, EventKind};
use agent_caps_core::domain::state::{Known, State};
use agent_caps_core::domain::tx::checks::RuleMove;
use agent_caps_core::domain::tx::{FindingDetail, TxDecision, TxPolicy, TxReport};

use super::common::{
    GUARD, OTHER, REWARD, adjustment, adjustment_id, agent, at, bind, binding_id, catalog,
    clippy_reward, exempt_n, id, inside, mode_switch, push_after_allowed, test_guard, the_agent,
    the_helper, the_user, unreadable, user, verdict, violated,
};

/// The id of a meta policy of these scenarios.
const META: &str = "00000000-0000-7000-8000-000000000004";

/// Bindings added and suspended.
fn rebind(add: &[(&str, Level)], suspend: &[BindingId]) -> Temporary {
    Temporary::Rebind {
        add: add
            .iter()
            .map(|(policy, level)| TemporaryBinding {
                policy: id(policy),
                level: *level,
            })
            .collect(),
        suspend: suspend.to_vec(),
    }
}

/// The `n`th adjustment, a rebinding for the task.
fn for_the_task(n: u8, change: Temporary) -> Body {
    adjustment(n, change, Lifetime::Within(Scope::Task))
}

/// The binding the guard's author puts it into effect with.
fn base() -> BindingId {
    binding_id(id(GUARD), 0)
}

/// The lowering of the guard for the task: its author's Force binding suspended, Advise added.
fn lowering(n: u8) -> Body {
    for_the_task(n, rebind(&[(GUARD, Level::Advise)], &[base()]))
}

/// The raise of the guard to Force for the task.
fn raise(n: u8) -> Body {
    for_the_task(n, rebind(&[(GUARD, Level::Force)], &[]))
}

fn cancel(n: u8) -> Body {
    Body::Cancel {
        id: adjustment_id(n),
    }
}

/// The transaction of `event` after `before`.
fn admit(catalog: &Catalog, before: &[Event], event: &Event) -> TxReport {
    catalog.admit(&catalog.fold(before), event, &TxPolicy::standard())
}

/// The moves the rule check of the report found, which must have one that loosens.
fn loosening_moves(report: &TxReport) -> Vec<RuleMove> {
    report
        .findings
        .iter()
        .find_map(|f| match &f.verdict {
            agent_caps_core::domain::tx::Verdict::Loosens {
                detail: FindingDetail::Rules { moves, .. },
                ..
            } => Some(moves.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no loosening rules finding: {report:?}"))
}

/// What the policy comes to in the state.
fn effect_in(catalog: &Catalog, state: &State, policy: &str) -> Effect {
    catalog
        .effective_in(state)
        .policies
        .iter()
        .find(|p| p.policy.id() == id(policy))
        .map(|p| p.effect)
        .unwrap()
}

/// The guard warned, not stopped.
fn warned() -> Verdict {
    Verdict::Warn(vec![Cause::Violated(id(GUARD))])
}

/// FR43, UC6: a raise for a while is a Force binding added. It tightens, so the agent may make
/// it; the guard stops while it lasts, and warns again from its `Until` on.
#[test]
fn a_temporary_raise_takes_effect_and_ends_at_its_until() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let start = agent(Body::TaskStart);
    let raise = at(
        the_agent(),
        0,
        adjustment(
            1,
            rebind(&[(GUARD, Level::Force)], &[]),
            Lifetime::Until(At::from_millis(100)),
        ),
    );
    assert_eq!(
        admit(&catalog, std::slice::from_ref(&start), &raise).decision,
        TxDecision::Commit
    );
    let stop_at = |millis| at(the_agent(), millis, Body::Stop);
    assert_eq!(
        verdict(&catalog, &[start.clone(), raise.clone(), stop_at(50)]),
        violated()
    );
    assert_eq!(
        verdict(&catalog, &[start.clone(), raise.clone(), stop_at(100)]),
        warned()
    );
    assert!(
        catalog
            .fold(&[start, raise, stop_at(100)])
            .adjustments()
            .is_empty()
    );
}

/// FR43, UC25: a lowering for a while suspends the Force binding and adds an Advise one. It
/// loosens, as to the author of the suspended binding: the agent cannot make it, the user can, and
/// the guard then warns.
#[test]
fn a_temporary_lowering_needs_the_cover_of_the_suspended_bindings_author() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let start = agent(Body::TaskStart);
    let report = admit(&catalog, std::slice::from_ref(&start), &agent(lowering(1)));
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::Uncovered(vec![the_user()])]
    );
    assert_eq!(
        loosening_moves(&report),
        vec![
            RuleMove::Lowered {
                policy: id(GUARD),
                authors: vec![the_user()],
            },
            RuleMove::Suspended {
                policy: id(GUARD),
                binding: base(),
                authors: vec![the_user()],
            },
        ]
    );
    let lowered = user(lowering(1));
    assert_eq!(
        admit(&catalog, std::slice::from_ref(&start), &lowered).decision,
        TxDecision::Commit
    );
    assert_eq!(
        verdict(&catalog, &[start, lowered, agent(Body::Stop)]),
        warned()
    );
}

/// FR43, UC25: the agent cannot hide a loss behind a binding of its own. It may add an equal Force
/// binding to the user's guard, but suspending the user's binding next to it is a loosening as to
/// the user, though the guard stays at Force; so is doing both in one adjustment. Otherwise the
/// agent could cancel its own binding later.
#[test]
fn suspending_anothers_binding_behind_an_equal_binding_of_ones_own_is_refused() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let start = agent(Body::TaskStart);
    let own = agent(raise(1));
    let report = admit(&catalog, std::slice::from_ref(&start), &own);
    assert_eq!(report.decision, TxDecision::Commit);
    assert!(report.findings.is_empty(), "{:?}", report.findings);

    let suspended = RuleMove::Suspended {
        policy: id(GUARD),
        binding: base(),
        authors: vec![the_user()],
    };
    let before = [start.clone(), own];
    let report = admit(
        &catalog,
        &before,
        &agent(for_the_task(2, rebind(&[], &[base()]))),
    );
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(loosening_moves(&report), vec![suspended.clone()]);

    let both = agent(for_the_task(2, rebind(&[(GUARD, Level::Force)], &[base()])));
    let report = admit(&catalog, std::slice::from_ref(&start), &both);
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(loosening_moves(&report), vec![suspended]);
}

/// FR43, UC25: a cancel is judged by its result. Cancelling the user's raise lowers the guard, as
/// to the user, so the agent cannot; cancelling the user's lowering raises it, so anyone may.
#[test]
fn a_cancel_is_judged_by_what_ending_the_adjustment_moves() {
    let start = agent(Body::TaskStart);

    let advising = catalog(vec![test_guard(Level::Advise)], vec![]);
    let raised = [start.clone(), user(raise(1))];
    let report = admit(&advising, &raised, &agent(cancel(1)));
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        loosening_moves(&report),
        vec![RuleMove::Lowered {
            policy: id(GUARD),
            authors: vec![the_user()],
        }]
    );
    assert_eq!(
        admit(&advising, &raised, &user(cancel(1))).decision,
        TxDecision::Commit
    );

    let stopping = catalog(vec![test_guard(Level::Force)], vec![]);
    let lowered = [start, user(lowering(1))];
    assert_eq!(
        admit(&stopping, &lowered, &agent(cancel(1))).decision,
        TxDecision::Commit
    );
    let mut events = lowered.to_vec();
    events.extend([agent(cancel(1)), agent(Body::Stop)]);
    assert_eq!(verdict(&stopping, &events), violated());
    // A cancel of an adjustment that is not in effect does nothing, and its transaction says so.
    let start = agent(Body::TaskStart);
    let report = admit(&stopping, std::slice::from_ref(&start), &agent(cancel(7)));
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.inadmissible,
        Some(Inadmissible::NotHeld(adjustment_id(7)))
    );
    assert_eq!(
        stopping.fold(&[start.clone(), agent(cancel(7))]),
        stopping.fold(&[start])
    );
}

/// FR43, FR2, FR14: an adjustment that cannot take effect takes none, even from the root: a
/// rebinding for the next judgment, Force on a reward or on a guard without the fixtures of a
/// stopping guard, a meta policy or a binding of one, a policy the catalog lacks, a rebinding that
/// changes nothing, and an id held by an adjustment in effect.
#[test]
fn an_adjustment_that_cannot_take_effect_takes_none() {
    let mut no_fixtures = push_after_allowed(GUARD);
    no_fixtures.level = None;
    let mut meta = test_guard(Level::Force);
    meta.id = id(META);
    meta.name = "meta-guard".parse().unwrap();
    meta.layer = DefLayer::Meta;
    let catalog = catalog(
        vec![
            test_guard(Level::Advise),
            clippy_reward(Level::Advise),
            no_fixtures,
            meta,
        ],
        vec![],
    );
    let start = agent(Body::TaskStart);
    // The claim is aborted, says why, and leaves the state as it was.
    let refused = |before: &[Event], claim: Body, why: Inadmissible| {
        let claim = user(claim);
        let report = admit(&catalog, before, &claim);
        assert_eq!(report.decision, TxDecision::Abort, "{claim:?}");
        assert_eq!(report.inadmissible, Some(why), "{claim:?}");
        let mut with = before.to_vec();
        with.push(claim);
        assert_eq!(catalog.fold(&with), catalog.fold(before));
    };
    let alone = std::slice::from_ref(&start);
    let unknown = "00000000-0000-7000-8000-0000000000ff";
    let cases = [
        (
            adjustment(1, rebind(&[(GUARD, Level::Force)], &[]), Lifetime::Next),
            Inadmissible::NextOnRebind,
        ),
        (
            for_the_task(1, rebind(&[(REWARD, Level::Force)], &[])),
            Inadmissible::RewardForce(id(REWARD)),
        ),
        (
            for_the_task(1, rebind(&[(OTHER, Level::Force)], &[])),
            Inadmissible::MissingFixtures(id(OTHER)),
        ),
        (
            for_the_task(1, rebind(&[(META, Level::Inform)], &[])),
            Inadmissible::Meta(id(META)),
        ),
        (
            for_the_task(1, rebind(&[], &[binding_id(id(META), 0)])),
            Inadmissible::Meta(id(META)),
        ),
        (
            exempt_n(1, META, None, Lifetime::Within(Scope::Task)),
            Inadmissible::Meta(id(META)),
        ),
        (
            exempt_n(1, REWARD, None, Lifetime::Within(Scope::Task)),
            Inadmissible::NotAGuard(id(REWARD)),
        ),
        (
            for_the_task(1, rebind(&[(unknown, Level::Advise)], &[])),
            Inadmissible::UnknownPolicy(id(unknown)),
        ),
        (
            for_the_task(1, rebind(&[], &[binding_id(id(OTHER), 0)])),
            Inadmissible::UnknownBinding(binding_id(id(OTHER), 0)),
        ),
        (for_the_task(1, rebind(&[], &[])), Inadmissible::Empty),
    ];
    for (claim, why) in cases {
        refused(alone, claim, why);
    }
    // What fits takes effect: Advise on the guard without fixtures, Force on the stopping guard.
    let held_after = |claim: Body| {
        catalog
            .fold(&[start.clone(), user(claim)])
            .adjustments()
            .len()
    };
    assert_eq!(
        held_after(for_the_task(1, rebind(&[(OTHER, Level::Advise)], &[]))),
        1
    );
    assert_eq!(held_after(raise(1)), 1);

    // An id held by an adjustment in effect.
    refused(
        &[start.clone(), user(raise(1))],
        for_the_task(1, rebind(&[(REWARD, Level::Advise)], &[])),
        Inadmissible::DuplicateId(adjustment_id(1)),
    );
}

/// FR43, UC25, FR38: a temporary binding is held to the rule of a binding of the catalog: its
/// maker is of the hierarchy and is the policy's author or below it. The user cannot bind the
/// agent's guard, nor can one outside the hierarchy or a leaf a spawn added; the helper below the
/// agent can, and the agent, who covers the helper, may still exempt its own guard.
#[test]
fn a_temporary_binding_is_by_the_policys_author_or_one_below_it() {
    let mut own = test_guard(Level::Advise);
    own.author = the_agent();
    let catalog = catalog(vec![own], vec![]);
    let start = agent(Body::TaskStart);
    let alone = std::slice::from_ref(&start);
    let why = |claim: &Event| admit(&catalog, alone, claim).inadmissible;

    assert_eq!(
        why(&user(raise(1))),
        Some(Inadmissible::AuthorAbove {
            policy: id(GUARD),
            author: the_user(),
        })
    );
    let stranger = Principal::new("stranger");
    assert_eq!(
        why(&at(stranger.clone(), 0, raise(1))),
        Some(Inadmissible::AuthorUnknown(stranger))
    );
    let leaf = Principal::new("leaf-1");
    let spawn = agent(Body::Spawn {
        child: leaf.clone(),
        under: the_agent(),
    });
    let spawned = [start.clone(), spawn];
    assert_eq!(
        admit(&catalog, &spawned, &at(leaf.clone(), 0, raise(1))).inadmissible,
        Some(Inadmissible::AuthorUnknown(leaf))
    );

    let raised = [start, at(the_helper(), 0, raise(1))];
    assert_eq!(
        admit(&catalog, &raised[..1], &raised[1]).decision,
        TxDecision::Commit
    );
    let exempt = agent(exempt_n(2, GUARD, None, Lifetime::Within(Scope::Task)));
    let report = admit(&catalog, &raised, &exempt);
    assert_eq!(report.decision, TxDecision::Commit, "{report:?}");
}

/// FR43, FR33, UC25: a claim that closes the scope another's raise lasts within ends the raise,
/// and is judged by that: the agent's score that closes `Since(score)` lowers the user's raise, so
/// it needs the user's cover; the user's own score does not.
#[test]
fn a_claim_that_closes_the_scope_of_anothers_raise_needs_the_raisers_cover() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let until_scored = Lifetime::Within(Scope::Since(EventFilter {
        kind: EventKind::Measured,
        cond: None,
    }));
    let raised = [
        agent(Body::TaskStart),
        user(adjustment(
            1,
            rebind(&[(GUARD, Level::Force)], &[]),
            until_scored,
        )),
    ];
    let score = |by| {
        at(
            by,
            0,
            Body::Measured {
                oracle: "bench".to_owned(),
                score: 0.9,
            },
        )
    };
    let report = admit(&catalog, &raised, &score(the_agent()));
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::Uncovered(vec![the_user()])]
    );
    assert_eq!(
        loosening_moves(&report),
        vec![RuleMove::Lowered {
            policy: id(GUARD),
            authors: vec![the_user()],
        }]
    );
    assert_eq!(
        admit(&catalog, &raised, &score(the_user())).decision,
        TxDecision::Commit
    );
    let mut events = raised.to_vec();
    events.extend([score(the_user()), agent(Body::Stop)]);
    assert_eq!(verdict(&catalog, &events), warned());
}

/// FR43, FR20, UC3: a lost record that may have been an adjustment or a cancel makes every rule
/// as strong as a temporary binding could make it, to the end of the fold: a guard with the
/// fixtures of a stopping guard stops though the user lowered it (the suspension is not taken to
/// hold), and a guard without them, off before, advises.
#[test]
fn a_lost_adjustment_makes_each_rule_as_strong_as_a_temporary_binding_could() {
    let mut no_fixtures = push_after_allowed(GUARD);
    no_fixtures.level = None;
    let catalog = catalog(vec![test_guard(Level::Force), no_fixtures], vec![]);
    let start = agent(Body::TaskStart);
    let lowered = [
        start.clone(),
        user(adjustment(
            1,
            rebind(&[(GUARD, Level::Advise)], &[base()]),
            Lifetime::Within(Scope::Session),
        )),
    ];
    let mut events = lowered.to_vec();
    events.push(agent(Body::Stop));
    assert_eq!(verdict(&catalog, &events), warned());
    let state = catalog.fold(&lowered);
    assert_eq!(effect_in(&catalog, &state, OTHER), Effect::Off);
    assert!(!state.adjustments_lost());

    for lost in [EventKind::Adjust, EventKind::Cancel] {
        let mut events = lowered.to_vec();
        events.extend([unreadable(&[lost]), agent(Body::TaskStart)]);
        let state = catalog.fold(&events);
        assert!(state.adjustments_lost());
        assert_eq!(effect_in(&catalog, &state, GUARD), Effect::On(Level::Force));
        assert_eq!(
            effect_in(&catalog, &state, OTHER),
            Effect::On(Level::Advise)
        );
        events.extend([agent(Body::SessionStart), agent(Body::TaskStart)]);
        events.push(agent(Body::Stop));
        assert_eq!(verdict(&catalog, &events), violated(), "{lost:?}");
    }
}

/// FR43, UC6: the adjustments in effect are seen in the state, each with who made it, until it is
/// cancelled.
#[test]
fn the_state_shows_the_adjustments_in_effect_with_who_made_them() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let mut events = vec![agent(Body::TaskStart), user(raise(1)), agent(raise(2))];
    let seen = |events: &[Event]| -> Vec<_> {
        catalog
            .fold(events)
            .adjustments()
            .iter()
            .map(|held| (held.by.clone(), held.adjustment.id))
            .collect()
    };
    assert_eq!(
        seen(&events),
        vec![
            (the_user(), adjustment_id(1)),
            (the_agent(), adjustment_id(2))
        ]
    );
    events.push(user(cancel(1)));
    assert_eq!(seen(&events), vec![(the_agent(), adjustment_id(2))]);
}

/// FR43, FR11, FR20: a temporary binding holds under every mode, and a suspension under every
/// mode; when the mode is not known each mode is computed to the end and the strongest taken.
#[test]
fn a_temporary_binding_under_an_unknown_mode() {
    let mut guard = test_guard(Level::Force);
    guard.level = None;
    let fix = bind(GUARD, 1, Level::Force, inside("fix"), the_user());
    let catalog = catalog(vec![guard], vec![fix.clone()]);
    let advise = user(for_the_task(1, rebind(&[(GUARD, Level::Advise)], &[])));
    let lost_switch = unreadable(&[EventKind::ModeSwitch]);
    let effect = |events: &[Event]| effect_in(&catalog, &catalog.fold(events), GUARD);

    assert_eq!(effect(&[]), Effect::Off);
    assert_eq!(
        effect(std::slice::from_ref(&advise)),
        Effect::On(Level::Advise)
    );
    assert_eq!(
        effect(&[mode_switch("explore"), advise.clone()]),
        Effect::On(Level::Advise)
    );
    let unknown = [advise.clone(), lost_switch.clone()];
    assert_eq!(catalog.fold(&unknown).mode(), &Known::Unknown);
    assert_eq!(effect(&unknown), Effect::On(Level::Force));

    let suspend_fix = user(for_the_task(2, rebind(&[], &[fix.id])));
    assert_eq!(
        effect(&[advise, suspend_fix, lost_switch]),
        Effect::On(Level::Advise)
    );
}
