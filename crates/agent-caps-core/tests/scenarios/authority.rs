//! Authority: who may change whose rules. A policy and an override each have an author, the
//! authors form a hierarchy, and `Catalog::change` accepts a change by a principal only if it does
//! not loosen what the principal does not cover. `Catalog::accept` and `Catalog::change` hold the
//! judgment; the tests compare what they accept and reject.

use agent_caps_core::domain::authority::{Authority, AuthorityError, Principal};
use agent_caps_core::domain::catalog::{AcceptError, Catalog, Effect, Target};
use agent_caps_core::domain::change::{ChangeRejected, Loosening};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::Verdict;
use agent_caps_core::domain::policy::{
    Change, DefLayer, Finding, Level, OverrideLayer, Polarity, PolicyDef, RewardLevel, Rule,
};
use agent_caps_core::domain::predicate::{Cmp, Cond, EventFilter, Lit, Pred, Scope};
use agent_caps_core::domain::schema::{EventKind, Field, Judgment};
use agent_caps_core::domain::state::Known;
use agent_caps_core::domain::tx::{TxDecision, TxPolicy};

use super::common::{
    GUARD, OTHER, REWARD, accept, agent, at, authority, catalog, clippy_reward, graph_of, id, mode,
    outcome, over, rejected, test_guard, tested, the_agent, the_helper, the_user, verdict,
};

const AGENT_REWARD: &str = "00000000-0000-7000-8000-000000000004";
const HELPER_REWARD: &str = "00000000-0000-7000-8000-000000000005";

/// A guard of the agent's own, beside the user's: the same checks, written by the agent.
fn agent_guard(level: Level) -> PolicyDef {
    let mut guard = test_guard(level);
    guard.id = id(OTHER);
    guard.name = "agent-guard".parse().unwrap();
    guard.author = the_agent();
    guard
}

/// A second guard of the user's.
fn other_user_guard(level: Level) -> PolicyDef {
    let mut guard = test_guard(level);
    guard.id = id(OTHER);
    guard.name = "other-guard".parse().unwrap();
    guard
}

/// A reward bound by `bound_by`, written by `author`.
fn reward_by(policy: &str, bound_by: &str, author: Principal) -> PolicyDef {
    let mut reward = clippy_reward(RewardLevel::Advise);
    reward.id = id(policy);
    reward.name = format!("reward-{policy}").parse().unwrap();
    reward.polarity = Polarity::Reward {
        level: RewardLevel::Advise,
        bound_by: id(bound_by),
    };
    reward.author = author;
    reward
}

/// What the policy comes to under the mode (no mode when `None`).
fn effect_of(catalog: &Catalog, policy: &str, under: Option<&str>) -> Effect {
    let under = Known::Known(under.map(mode));
    catalog
        .effective(&under)
        .policies
        .iter()
        .find(|p| p.policy.id() == id(policy))
        .unwrap()
        .effect
}

/// The loosenings of a change that was rejected for loosening, and nothing else.
fn loosenings(result: Result<Catalog, ChangeRejected>) -> Vec<Loosening> {
    match result.unwrap_err() {
        ChangeRejected::Loosens(loosenings) => loosenings,
        other => panic!("rejected, but not for loosening: {other:?}"),
    }
}

fn uncovered_policy(policy: &str) -> Loosening {
    Loosening::Uncovered {
        target: Target::Policy(id(policy)),
    }
}

fn below(policy: &str, under: Option<&str>, before: Effect, after: Effect) -> Loosening {
    Loosening::BelowUncovered {
        policy: id(policy),
        mode: under.map(mode),
        before,
        after,
    }
}

/// FR16, UC19: an agent below the user adds a guard of its own without approval, and it takes
/// effect: it stops, and the user's rules are what they were.
#[test]
fn an_agent_below_the_user_adds_a_guard_and_it_takes_effect() {
    let before = catalog(vec![test_guard(Level::Advise)], vec![]);
    let after = graph_of(
        vec![test_guard(Level::Advise), agent_guard(Level::Force)],
        vec![],
    );
    let changed = before.change(after, &the_agent()).unwrap();
    assert_eq!(effect_of(&changed, OTHER, None), Effect::On(Level::Force));
    assert_eq!(effect_of(&changed, GUARD, None), Effect::On(Level::Advise));
    let events = [agent(Body::TaskStart), agent(Body::Stop)];
    assert!(matches!(verdict(&changed, &events), Verdict::Deny(_)));
    // The catalog it came from is not changed by the change.
    assert_eq!(before.policies().len(), 1);
}

/// FR5, FR6, FR7, FR18, UC20: an agent cannot lower the user's guard, turn it off, remove it or
/// rewrite its rule, whether in the guard itself or by an override of its own; the user can.
#[test]
fn an_agent_cannot_loosen_the_users_guard() {
    let before = catalog(vec![test_guard(Level::Force)], vec![]);
    let by_agent = |policies, overrides| before.change(graph_of(policies, overrides), &the_agent());

    let mut off = test_guard(Level::Force);
    off.enabled = false;
    let mut rewritten = test_guard(Level::Force);
    rewritten.rule = Rule::Structural(Pred::All(vec![tested()]));
    let in_the_guard = [
        test_guard(Level::Advise),
        off.clone(),
        rewritten,
        // Authored by the agent, so that the guard is the agent's own: taken over.
        {
            let mut taken = test_guard(Level::Force);
            taken.author = the_agent();
            taken
        },
    ];
    for guard in in_the_guard {
        assert_eq!(
            loosenings(by_agent(vec![guard], vec![])),
            vec![uncovered_policy(GUARD)]
        );
    }
    assert_eq!(
        loosenings(by_agent(vec![], vec![])),
        vec![uncovered_policy(GUARD)]
    );

    let by_override = |change| {
        by_agent(
            vec![test_guard(Level::Force)],
            vec![over(OverrideLayer::Project, GUARD, change, the_agent())],
        )
    };
    let force = Effect::On(Level::Force);
    assert_eq!(
        loosenings(by_override(Change::Level(Level::Advise))),
        vec![below(GUARD, None, force, Effect::On(Level::Advise))]
    );
    assert_eq!(
        loosenings(by_override(Change::Off)),
        vec![below(GUARD, None, force, Effect::Off)]
    );

    // The user, who covers what it wrote, changes its own guard freely.
    let user = |policies| before.change(graph_of(policies, vec![]), &the_user());
    assert!(user(vec![test_guard(Level::Advise)]).is_ok());
    assert!(user(vec![off]).is_ok());
    assert!(user(vec![]).is_ok());
}

/// FR2, FR18: an agent cannot weaken the examples of the user's guard, by marking one as a known
/// gap or by dropping one: they are the evidence for the rule. The user may.
#[test]
fn an_agent_cannot_weaken_the_examples_of_the_users_guard() {
    // An advising guard, since a stopping one needs both of its examples to be accepted at all.
    let before = catalog(vec![test_guard(Level::Advise)], vec![]);
    let mut marked = test_guard(Level::Advise);
    marked.fixtures[0].known_gap = true;
    let mut dropped = test_guard(Level::Advise);
    dropped.fixtures.pop();
    for guard in [marked, dropped] {
        let after = graph_of(vec![guard], vec![]);
        assert_eq!(
            loosenings(before.change(after.clone(), &the_agent())),
            vec![uncovered_policy(GUARD)]
        );
        assert!(before.change(after, &the_user()).is_ok());
    }
}

/// FR7, FR13, UC9: an agent cannot remove or lower the user's reward, nor turn off the guard
/// that binds it, which takes the reward with it.
#[test]
fn an_agent_cannot_remove_the_users_reward() {
    let policies = || vec![test_guard(Level::Force), clippy_reward(RewardLevel::Advise)];
    let before = catalog(policies(), vec![]);
    let by_agent = |policies, overrides| before.change(graph_of(policies, overrides), &the_agent());

    assert_eq!(
        loosenings(by_agent(vec![test_guard(Level::Force)], vec![])),
        vec![uncovered_policy(REWARD)]
    );
    assert_eq!(
        loosenings(by_agent(
            vec![test_guard(Level::Force), clippy_reward(RewardLevel::Inform)],
            vec![]
        )),
        vec![uncovered_policy(REWARD)]
    );
    // Turning the guard off turns its reward off: both fall below what they are.
    let off = over(OverrideLayer::Project, GUARD, Change::Off, the_agent());
    assert_eq!(
        loosenings(by_agent(policies(), vec![off])),
        vec![
            below(GUARD, None, Effect::On(Level::Force), Effect::Off),
            below(REWARD, None, Effect::On(Level::Advise), Effect::Off),
        ]
    );
}

/// FR18, UC20: an agent removes the guard it added and the override it placed, and the user's
/// rules are what they were before it.
#[test]
fn an_agent_removes_its_own_guard_and_its_own_override() {
    let raise = over(
        OverrideLayer::Project,
        GUARD,
        Change::Level(Level::Force),
        the_agent(),
    );
    let before = catalog(
        vec![test_guard(Level::Advise), agent_guard(Level::Force)],
        vec![raise],
    );
    assert_eq!(effect_of(&before, GUARD, None), Effect::On(Level::Force));

    let changed = before
        .change(
            graph_of(vec![test_guard(Level::Advise)], vec![]),
            &the_agent(),
        )
        .unwrap();
    assert_eq!(effect_of(&changed, GUARD, None), Effect::On(Level::Advise));
    assert!(changed.policy(id(OTHER)).is_none());
}

/// FR5, FR16, UC19: an override of the agent's raises the user's guard, in the project and in
/// a mode, and takes effect.
#[test]
fn an_agents_override_can_raise_the_users_guard() {
    let before = catalog(vec![test_guard(Level::Advise)], vec![]);
    let raise = |layer| over(layer, GUARD, Change::Level(Level::Force), the_agent());
    let after = graph_of(
        vec![test_guard(Level::Advise)],
        vec![
            raise(OverrideLayer::Project),
            // Even when the mode is the one that was never named before.
            raise(OverrideLayer::Mode(mode("bug-fix"))),
        ],
    );
    let changed = before.change(after, &the_agent()).unwrap();
    assert_eq!(effect_of(&changed, GUARD, None), Effect::On(Level::Force));
    assert_eq!(
        effect_of(&changed, GUARD, Some("bug-fix")),
        Effect::On(Level::Force)
    );
}

/// FR5, FR6, UC8: an override for a mode that nothing named before cannot weaken the user's
/// guard: the compared modes are those of the change too.
#[test]
fn an_override_for_a_new_mode_cannot_weaken_the_users_guard() {
    let before = catalog(vec![test_guard(Level::Force)], vec![]);
    let weaken = |change| {
        graph_of(
            vec![test_guard(Level::Force)],
            vec![over(
                OverrideLayer::Mode(mode("explore")),
                GUARD,
                change,
                the_agent(),
            )],
        )
    };
    let force = Effect::On(Level::Force);
    assert_eq!(
        loosenings(before.change(weaken(Change::Off), &the_agent())),
        vec![below(GUARD, Some("explore"), force, Effect::Off)]
    );
    assert_eq!(
        loosenings(before.change(weaken(Change::Level(Level::Inform)), &the_agent())),
        vec![below(
            GUARD,
            Some("explore"),
            force,
            Effect::On(Level::Inform)
        )]
    );
}

/// FR6, FR5: the agent removes the user's override that turns a guard off, which tightens, and
/// it is accepted.
#[test]
fn removing_the_users_off_override_tightens_and_is_accepted() {
    let off = over(OverrideLayer::Project, GUARD, Change::Off, the_user());
    let before = catalog(vec![test_guard(Level::Force)], vec![off]);
    assert_eq!(effect_of(&before, GUARD, None), Effect::Off);

    let changed = before
        .change(
            graph_of(vec![test_guard(Level::Force)], vec![]),
            &the_agent(),
        )
        .unwrap();
    assert_eq!(effect_of(&changed, GUARD, None), Effect::On(Level::Force));
}

/// FR6, FR5: the conservative case. The agent removes the user's override that turns a guard off
/// and places an override of its own that sets it to Inform: the guard is stricter than before,
/// but weaker than it is with nothing of the agent's, so the change is rejected. Removing the
/// override alone is accepted.
#[test]
fn removing_an_off_override_and_placing_an_inform_one_is_rejected_though_it_tightens() {
    let off = over(OverrideLayer::Project, GUARD, Change::Off, the_user());
    let before = catalog(vec![test_guard(Level::Force)], vec![off]);
    let inform = |layer| {
        graph_of(
            vec![test_guard(Level::Force)],
            vec![over(
                layer,
                GUARD,
                Change::Level(Level::Inform),
                the_agent(),
            )],
        )
    };
    let force = Effect::On(Level::Force);

    // In another layer: stricter in every mode, and still below what the guard is without it.
    let elsewhere = inform(OverrideLayer::Mode(mode("explore")));
    let stricter = accept(elsewhere.clone()).unwrap();
    for under in [None, Some("explore")] {
        assert!(effect_of(&stricter, GUARD, under) > effect_of(&before, GUARD, under));
    }
    assert_eq!(
        loosenings(before.change(elsewhere, &the_agent())),
        vec![below(
            GUARD,
            Some("explore"),
            force,
            Effect::On(Level::Inform)
        )]
    );

    // In the same layer, the agent also takes over what was the user's.
    assert_eq!(
        loosenings(before.change(inform(OverrideLayer::Project), &the_agent())),
        vec![
            Loosening::Uncovered {
                target: Target::Override(OverrideLayer::Project, id(GUARD))
            },
            below(GUARD, None, force, Effect::On(Level::Inform)),
        ]
    );
}

/// FR16, FR18: an item refers only to items of its own author or above: what is above never
/// depends on what is below. The agent's reward may be bound by the user's guard; the user's
/// reward may not be bound by the agent's guard, nor the user's override target the agent's.
#[test]
fn an_item_refers_only_to_items_of_its_own_author_or_above() {
    // The agent's reward, bound by the user's guard.
    catalog(
        vec![
            test_guard(Level::Force),
            reward_by(AGENT_REWARD, GUARD, the_agent()),
        ],
        vec![],
    );
    // The user's reward, bound by the agent's guard.
    let mut under_the_agent = agent_guard(Level::Force);
    under_the_agent.id = id(GUARD);
    let errors = rejected(
        vec![under_the_agent.clone(), clippy_reward(RewardLevel::Advise)],
        vec![],
    );
    assert_eq!(
        errors,
        vec![AcceptError::ReferencesBelow {
            item: Target::Policy(id(REWARD)),
            referenced: id(GUARD),
        }]
    );
    // The user's override, on the agent's guard.
    let errors = rejected(
        vec![under_the_agent],
        vec![over(
            OverrideLayer::Project,
            GUARD,
            Change::Level(Level::Inform),
            the_user(),
        )],
    );
    assert_eq!(
        errors,
        vec![AcceptError::ReferencesBelow {
            item: Target::Override(OverrideLayer::Project, id(GUARD)),
            referenced: id(GUARD),
        }]
    );
}

/// The judgments of a session counted below one, by a filter of `cond`, as the guard's `when`;
/// the guard is the test guard, with no fixtures.
fn counting(cond: Option<Cond>) -> PolicyDef {
    let mut guard = test_guard(Level::Advise);
    guard.fixtures = vec![];
    guard.when = Some(Pred::Count {
        event: EventFilter {
            kind: EventKind::Judged,
            cond,
        },
        scope: Scope::Session,
        cmp: Cmp::Lt,
        n: 1,
    });
    guard
}

fn of(policy: &str) -> Cond {
    Cond::Eq(Field::Policy, Lit::Text(policy.to_owned()))
}

fn denied() -> Cond {
    Cond::Eq(Field::Judgment, Lit::Text("denied".to_owned()))
}

/// The user's stopping guard, which applies until a `denied` judgment has been counted in the
/// session by a filter that names no policy, so it counts whatever it is allowed to see.
fn stops_until_denied() -> PolicyDef {
    let mut guard = test_guard(Level::Force);
    guard.when = counting(Some(denied())).when;
    guard
}

/// What the guard finds on the last of the events, folded as a run is. A guard that does not
/// judge the event is not in the outcome: it is not applicable.
fn found(catalog: &Catalog, events: &[Event], guard: &str) -> Finding {
    outcome(catalog, events)
        .guards
        .iter()
        .find(|g| g.policy == id(guard))
        .map_or(Finding::NotApplicable, |g| g.finding)
}

/// The record of a judgment of `policy`, from `by`.
fn denial(policy: &str, by: Principal) -> Event {
    at(
        by,
        0,
        Body::Judged {
            policy: id(policy),
            judgment: Judgment::Denied,
        },
    )
}

/// FR37, UC25: a policy names the judgments only of policies whose authors cover its own. The
/// root's guard that names the guard below it is rejected, whatever the shape of the filter that
/// names it: alone, in an `all`, in an `any` beside a branch that names nothing, or under a
/// `not`. The guard below may name the root's.
#[test]
fn a_policy_names_the_judgments_only_of_policies_above_it() {
    let below = vec![AcceptError::ReferencesBelow {
        item: Target::Policy(id(GUARD)),
        referenced: id(OTHER),
    }];
    for cond in [
        Cond::All(vec![of(OTHER), denied()]),
        Cond::In(Field::Policy, vec![Lit::Text(OTHER.to_owned())]),
        of(OTHER),
        Cond::Any(vec![of(GUARD), of(OTHER)]),
        Cond::Any(vec![of(OTHER), denied()]),
        Cond::Not(Box::new(of(OTHER))),
        Cond::All(vec![denied(), Cond::Not(Box::new(of(OTHER)))]),
    ] {
        assert_eq!(
            rejected(
                vec![counting(Some(cond.clone())), agent_guard(Level::Force)],
                vec![]
            ),
            below,
            "{cond:?}"
        );
    }
    // Narrowed to its own judgments, or naming its own beside a branch that names nothing, it is
    // accepted beside the guard below.
    for cond in [
        Cond::All(vec![of(GUARD), denied()]),
        Cond::Any(vec![of(GUARD), of(GUARD)]),
        Cond::Any(vec![of(GUARD), denied()]),
    ] {
        catalog(
            vec![counting(Some(cond)), agent_guard(Level::Force)],
            vec![],
        );
    }
    // The guard below names the root's judgments.
    let mut reads_above = counting(Some(of(GUARD)));
    reads_above.id = id(OTHER);
    reads_above.name = "reads-above".parse().unwrap();
    reads_above.author = the_agent();
    catalog(vec![test_guard(Level::Force), reads_above], vec![]);
}

/// FR37, UC25: a filter of judgments that names no policy is accepted beside a policy below its
/// author, and what was written is kept: the catalog's graph is the one it was accepted from.
#[test]
fn an_unnamed_read_of_judgments_is_accepted_beside_a_policy_below() {
    for cond in [Some(denied()), None] {
        let written = vec![counting(cond.clone()), agent_guard(Level::Force)];
        let accepted = catalog(written.clone(), vec![]);
        assert_eq!(accepted.graph().policies, written, "{cond:?}");
    }
    // At any depth of the predicate, and in the scope of a `once` or a `last` as well.
    let mut deep = counting(None);
    deep.rule = Rule::Structural(Pred::Not(Box::new(Pred::Once {
        event: EventFilter {
            kind: EventKind::Stop,
            cond: None,
        },
        scope: Scope::Since(EventFilter {
            kind: EventKind::Judged,
            cond: Some(denied()),
        }),
    })));
    catalog(vec![deep, agent_guard(Level::Force)], vec![]);
}

/// FR37, UC25, UC2: the user's rule that counts denials without naming a policy does not count
/// a denial of the policy below it, even one the agent genuinely records in its own name: the
/// user's guard goes on stopping, and the record is not aborted, since it moves no rule of the
/// user's.
#[test]
fn an_unnamed_read_does_not_count_the_judgments_of_a_policy_below() {
    let catalog = catalog(
        vec![stops_until_denied(), agent_guard(Level::Force)],
        vec![],
    );
    let before = [
        agent(Body::SessionStart),
        agent(Body::TaskStart),
        agent(Body::Stop),
    ];
    let record = denial(OTHER, the_agent());
    let report = catalog.admit(&catalog.fold(&before), &record, &TxPolicy::standard());
    assert_eq!(report.decision, TxDecision::Commit);
    assert!(report.uncovered.is_empty());

    let mut events = before.to_vec();
    events.push(record);
    events.push(agent(Body::Stop));
    assert_eq!(found(&catalog, &events, GUARD), Finding::Violated);
}

/// FR37, UC25, UC2: the same rule counts a denial of the user's own policy, which the user records
/// in its name, and then lets the turn end.
#[test]
fn an_unnamed_read_counts_the_judgments_of_policies_of_its_own_author_and_above() {
    let user_only = catalog(
        vec![stops_until_denied(), agent_guard(Level::Force)],
        vec![],
    );
    let mut events = vec![agent(Body::TaskStart), agent(Body::Stop)];
    assert_eq!(found(&user_only, &events, GUARD), Finding::Violated);
    events.push(denial(GUARD, the_user()));
    events.push(agent(Body::Stop));
    assert_eq!(found(&user_only, &events, GUARD), Finding::NotApplicable);

    // A policy of the agent's counts the judgments of the user's and of its own, and not of the
    // helper's below it.
    let mut counts = stops_until_denied();
    counts.id = id(OTHER);
    counts.name = "agent-counts".parse().unwrap();
    counts.author = the_agent();
    let mut helper = agent_guard(Level::Force);
    helper.id = id(REWARD);
    helper.name = "helper-guard".parse().unwrap();
    helper.author = the_helper();
    let three = catalog(vec![test_guard(Level::Force), counts, helper], vec![]);
    let counted = |policy: &str, by: Principal| {
        let events = [
            agent(Body::TaskStart),
            denial(policy, by),
            agent(Body::Stop),
        ];
        found(&three, &events, OTHER) == Finding::NotApplicable
    };
    assert!(counted(GUARD, the_user()), "the user's judgment counts");
    assert!(counted(OTHER, the_agent()), "its own counts");
    assert!(!counted(REWARD, the_helper()), "the helper's does not");
}

/// FR37, UC25: a rule that names no policy and a policy below it that is added by a change: the
/// rule as written and what it comes to are the same, and the record of the policy below is not
/// counted. A policy the user adds itself widens what the rule counts.
#[test]
fn a_change_by_one_below_leaves_the_rule_above_as_it_was() {
    let before = catalog(vec![stops_until_denied()], vec![]);
    let with_agent = graph_of(
        vec![stops_until_denied(), agent_guard(Level::Force)],
        vec![],
    );
    let changed = before.change(with_agent, &the_agent()).unwrap();
    assert_eq!(changed.graph().policies[0], stops_until_denied());
    assert_eq!(
        changed.policies()[0],
        before.policies()[0],
        "the rule above comes to the same, written and compiled"
    );
    let stopped = [
        agent(Body::TaskStart),
        agent(Body::Stop),
        denial(OTHER, the_agent()),
        agent(Body::Stop),
    ];
    assert_eq!(found(&changed, &stopped, GUARD), Finding::Violated);
    assert_eq!(found(&before, &stopped, GUARD), Finding::Violated);

    // The user adds a policy of its own: the rule now counts its denials, and the written rule
    // is again the same.
    let with_user = graph_of(
        vec![stops_until_denied(), other_user_guard(Level::Force)],
        vec![],
    );
    let widened = before.change(with_user, &the_user()).unwrap();
    assert_eq!(widened.graph().policies[0], stops_until_denied());
    assert_ne!(widened.policies()[0], before.policies()[0]);
    let counted = [
        agent(Body::TaskStart),
        agent(Body::Stop),
        denial(OTHER, the_user()),
        agent(Body::Stop),
    ];
    assert_eq!(found(&widened, &counted, GUARD), Finding::NotApplicable);
    assert_eq!(found(&before, &counted, GUARD), Finding::Violated);
}

/// FR37, UC25: a judgment of a policy that is not in the catalog is not counted by a filter that
/// names no policy, whoever writes it.
#[test]
fn an_unnamed_read_does_not_count_a_policy_that_is_not_in_the_catalog() {
    let catalog = catalog(vec![stops_until_denied()], vec![]);
    let events = [
        agent(Body::TaskStart),
        agent(Body::Stop),
        denial(OTHER, the_user()),
        agent(Body::Stop),
    ];
    assert_eq!(found(&catalog, &events, GUARD), Finding::Violated);
}

/// FR37, UC25: a meta policy reads judgments only by naming the policies: a filter that names
/// none, and a `last` of a judgment's field, are rejected whether or not a policy is below, and a
/// filter that names policies is accepted.
#[test]
fn a_meta_policy_reads_judgments_only_by_naming_the_policies() {
    let meta = |mut guard: PolicyDef| {
        guard.layer = DefLayer::Meta;
        guard
    };
    let unscoped = vec![AcceptError::MetaReadsUnscoped(id(GUARD))];
    for cond in [
        Some(denied()),
        None,
        Some(Cond::Any(vec![of(GUARD), denied()])),
    ] {
        for beside in [vec![], vec![agent_guard(Level::Force)]] {
            let mut policies = vec![meta(counting(cond.clone()))];
            policies.extend(beside);
            assert_eq!(rejected(policies, vec![]), unscoped, "{cond:?}");
        }
    }
    // A `last` of a judgment's field, with no policy below.
    let mut last = meta(test_guard(Level::Advise));
    last.fixtures = vec![];
    last.rule = Rule::Structural(Pred::Last {
        field: Field::Judgment,
        scope: Scope::Session,
        value: Lit::Text("denied".to_owned()),
    });
    assert_eq!(rejected(vec![last], vec![]), unscoped);
    // Naming the policies is accepted, beside a policy below as well.
    for cond in [
        Cond::All(vec![of(GUARD), denied()]),
        Cond::In(Field::Policy, vec![Lit::Text(GUARD.to_owned())]),
    ] {
        catalog(
            vec![meta(counting(Some(cond))), agent_guard(Level::Force)],
            vec![],
        );
    }
    // And one that names the policy below is rejected as any policy is.
    assert_eq!(
        rejected(
            vec![meta(counting(Some(of(OTHER)))), agent_guard(Level::Force)],
            vec![]
        ),
        vec![AcceptError::ReferencesBelow {
            item: Target::Policy(id(GUARD)),
            referenced: id(OTHER),
        }]
    );
}

/// FR37, UC25: a `last` of a judgment's field reads every policy's judgments, so the root's
/// policy that holds one is rejected when there is a policy below it, and accepted when there
/// is none.
#[test]
fn a_last_of_a_judgment_reads_every_policy() {
    let mut last = test_guard(Level::Advise);
    last.fixtures = vec![];
    last.rule = Rule::Structural(Pred::Last {
        field: Field::Policy,
        scope: Scope::Session,
        value: Lit::Text(GUARD.to_owned()),
    });
    assert_eq!(
        rejected(vec![last.clone(), agent_guard(Level::Force)], vec![]),
        vec![AcceptError::ReferencesBelow {
            item: Target::Policy(id(GUARD)),
            referenced: id(OTHER),
        }]
    );
    catalog(vec![last, other_user_guard(Level::Force)], vec![]);
}

/// FR16, FR18: an author must be of the hierarchy, whether of a policy or of an override, and so
/// must the one who changes.
#[test]
fn an_author_or_a_changer_outside_the_hierarchy_is_rejected() {
    let stranger = Principal::new("stranger");
    let mut written = test_guard(Level::Force);
    written.author = stranger.clone();
    assert_eq!(
        rejected(vec![written], vec![]),
        vec![AcceptError::UnknownAuthor {
            item: Target::Policy(id(GUARD)),
            author: stranger.clone(),
        }]
    );
    assert_eq!(
        rejected(
            vec![test_guard(Level::Force)],
            vec![over(
                OverrideLayer::Project,
                GUARD,
                Change::Off,
                stranger.clone()
            )]
        ),
        vec![AcceptError::UnknownAuthor {
            item: Target::Override(OverrideLayer::Project, id(GUARD)),
            author: stranger.clone(),
        }]
    );

    // A change whose graph has such an author is invalid.
    let before = catalog(vec![test_guard(Level::Force)], vec![]);
    let mut also = agent_guard(Level::Force);
    also.author = stranger.clone();
    let result = before.change(
        graph_of(vec![test_guard(Level::Force), also], vec![]),
        &the_user(),
    );
    assert!(matches!(result.unwrap_err(), ChangeRejected::Invalid(_)));
    // And one who is not of the hierarchy cannot change, even with nothing changed.
    assert_eq!(
        before.change(before.graph(), &stranger).unwrap_err(),
        ChangeRejected::UnknownPrincipal
    );
}

/// FR14, UC5, UC10: a meta policy is placed by a root, and no change differs in one, whoever
/// makes it, a root included.
#[test]
fn a_meta_policy_never_differs_for_anyone() {
    let meta = |level| {
        let mut guard = test_guard(level);
        guard.layer = DefLayer::Meta;
        guard
    };
    // Only a root places one.
    let mut by_the_agent = meta(Level::Force);
    by_the_agent.author = the_agent();
    assert_eq!(
        rejected(vec![by_the_agent], vec![]),
        vec![AcceptError::MetaAuthorNotRoot {
            policy: id(GUARD),
            author: the_agent(),
        }]
    );

    let before = catalog(vec![meta(Level::Force)], vec![]);
    let mut other_meta = other_user_guard(Level::Force);
    other_meta.layer = DefLayer::Meta;
    let differences = [
        (vec![meta(Level::Force), other_meta], vec![id(OTHER)]),
        (vec![meta(Level::Advise)], vec![id(GUARD)]),
        (vec![], vec![id(GUARD)]),
    ];
    for by in [the_user(), the_agent()] {
        for (policies, ids) in &differences {
            assert_eq!(
                before
                    .change(graph_of(policies.clone(), vec![]), &by)
                    .unwrap_err(),
                ChangeRejected::Meta(ids.clone())
            );
        }
    }
    // What is not meta is another matter: a root adds a guard beside it.
    let beside = graph_of(
        vec![meta(Level::Force), other_user_guard(Level::Force)],
        vec![],
    );
    assert!(before.change(beside, &the_user()).is_ok());
}

/// FR5, FR6, FR16: a change that tightens one of the user's guards and loosens another is
/// rejected as a whole, for the loosening only; each half alone is judged on its own.
#[test]
fn a_change_that_mixes_tightening_and_loosening_is_rejected_as_a_whole() {
    let before = catalog(
        vec![test_guard(Level::Advise), other_user_guard(Level::Advise)],
        vec![],
    );
    let both = graph_of(
        vec![test_guard(Level::Force), other_user_guard(Level::Inform)],
        vec![],
    );
    assert_eq!(
        loosenings(before.change(both, &the_agent())),
        vec![uncovered_policy(OTHER)]
    );
    let tightens = graph_of(
        vec![test_guard(Level::Force), other_user_guard(Level::Advise)],
        vec![],
    );
    let changed = before.change(tightens, &the_agent()).unwrap();
    assert_eq!(effect_of(&changed, GUARD, None), Effect::On(Level::Force));
}

/// FR16, FR18: a graph a catalog accepts, narrowed to what a principal does not cover, is
/// accepted again, for every principal of the hierarchy.
#[test]
fn the_narrowed_graph_always_accepts() {
    let graph = graph_of(
        vec![
            test_guard(Level::Force),
            clippy_reward(RewardLevel::Advise),
            agent_guard(Level::Force),
            reward_by(AGENT_REWARD, GUARD, the_agent()),
            reward_by(HELPER_REWARD, OTHER, the_helper()),
        ],
        vec![
            over(
                OverrideLayer::Project,
                GUARD,
                Change::Level(Level::Advise),
                the_user(),
            ),
            over(
                OverrideLayer::Mode(mode("explore")),
                OTHER,
                Change::Level(Level::Advise),
                the_agent(),
            ),
            over(OverrideLayer::Project, OTHER, Change::Off, the_helper()),
        ],
    );
    let full = accept(graph.clone()).unwrap();
    assert_eq!(full.graph(), graph);

    let remaining = |by: &Principal| {
        let narrowed = graph.not_covered_by(&authority(), by);
        accept(narrowed.clone()).unwrap();
        narrowed.policies.len() + narrowed.overrides.len()
    };
    assert_eq!(remaining(&the_user()), 0);
    // The agent and the helper below it are gone; the user's two policies and one override stay.
    assert_eq!(remaining(&the_agent()), 3);
    // The helper's own reward and override are gone.
    assert_eq!(remaining(&the_helper()), 6);
}

/// FR16, FR18: two roots do not cover each other: the work of one is not the other's to loosen,
/// and each changes its own freely.
#[test]
fn two_roots_do_not_cover_each_other() {
    let (a, b) = (Principal::new("a"), Principal::new("b"));
    let two_roots = Authority::new([(a.clone(), None), (b.clone(), None)]).unwrap();
    assert!(two_roots.covers(&a, &a));
    assert!(!two_roots.covers(&a, &b));
    assert!(!two_roots.covers(&b, &a));
    assert!(two_roots.is_root(&a) && two_roots.is_root(&b));

    let mut guard_a = test_guard(Level::Force);
    guard_a.author = a.clone();
    let mut guard_b = other_user_guard(Level::Force);
    guard_b.author = b.clone();
    let before = Catalog::accept(
        graph_of(vec![guard_a.clone(), guard_b.clone()], vec![]),
        two_roots,
    )
    .unwrap();

    let mut lowered_b = guard_b.clone();
    lowered_b.polarity = Polarity::Guard {
        level: Level::Advise,
    };
    assert_eq!(
        loosenings(before.change(graph_of(vec![guard_a.clone(), lowered_b], vec![]), &a)),
        vec![uncovered_policy(OTHER)]
    );
    let mut lowered_a = guard_a;
    lowered_a.polarity = Polarity::Guard {
        level: Level::Advise,
    };
    assert!(
        before
            .change(graph_of(vec![lowered_a, guard_b], vec![]), &a)
            .is_ok()
    );
}

/// FR16, FR18: a hierarchy with a cycle, an unknown parent, a principal twice or no root is
/// never made; what is above and what is beside are told apart.
#[test]
fn a_hierarchy_with_a_cycle_is_rejected() {
    let p = |key: &str| Principal::new(key);
    let link = |key: &str, parent: Option<&str>| (p(key), parent.map(p));

    assert_eq!(
        Authority::new([link("a", Some("b")), link("b", Some("a"))]).unwrap_err(),
        AuthorityError::Cycle(p("a"))
    );
    // A cycle beside a root is still a cycle.
    assert_eq!(
        Authority::new([link("r", None), link("a", Some("b")), link("b", Some("a"))]).unwrap_err(),
        AuthorityError::Cycle(p("a"))
    );
    assert_eq!(
        Authority::new([link("r", None), link("a", Some("a"))]).unwrap_err(),
        AuthorityError::Cycle(p("a"))
    );
    assert_eq!(
        Authority::new([link("r", None), link("a", Some("x"))]).unwrap_err(),
        AuthorityError::UnknownParent {
            principal: p("a"),
            parent: p("x"),
        }
    );
    assert_eq!(
        Authority::new([link("r", None), link("r", None)]).unwrap_err(),
        AuthorityError::Duplicate(p("r"))
    );
    assert_eq!(Authority::new([]).unwrap_err(), AuthorityError::Empty);

    let hierarchy = authority();
    assert!(hierarchy.covers(&the_user(), &the_helper()));
    assert!(hierarchy.covers(&the_agent(), &the_helper()));
    assert!(!hierarchy.covers(&the_helper(), &the_agent()));
    assert!(hierarchy.covers(&the_agent(), &the_agent()));
    assert_eq!(hierarchy.roots().collect::<Vec<_>>(), vec![&the_user()]);
}

/// FR16, FR18: a catalog accepted again with another hierarchy uses it. Where the agent is below
/// the user, the user removes the agent's guard; where they are two roots, it may not; and a
/// hierarchy without the agent does not accept what the agent wrote.
#[test]
fn a_catalog_accepted_again_with_a_new_hierarchy_uses_it() {
    let graph = graph_of(
        vec![test_guard(Level::Force), agent_guard(Level::Force)],
        vec![],
    );
    let removed = || graph_of(vec![test_guard(Level::Force)], vec![]);

    let below = accept(graph.clone()).unwrap();
    assert!(below.change(removed(), &the_user()).is_ok());

    let two_roots = Authority::new([(the_user(), None), (the_agent(), None)]).unwrap();
    let beside = Catalog::accept(graph.clone(), two_roots.clone()).unwrap();
    assert_eq!(beside.authority(), &two_roots);
    assert_eq!(
        loosenings(beside.change(removed(), &the_user())),
        vec![uncovered_policy(OTHER)]
    );

    let errors = Catalog::accept(graph, Authority::single(the_user())).unwrap_err();
    assert_eq!(
        errors.0,
        vec![AcceptError::UnknownAuthor {
            item: Target::Policy(id(OTHER)),
            author: the_agent(),
        }]
    );
}
