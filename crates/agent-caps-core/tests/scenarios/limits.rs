//! Limits the agent cannot start over by its own acts: at most so many pushes since the last
//! review, or within a task, where only the acts of one above the agent start the count over.
//!
//! A rule says whose events it chooses with a `By`: the pushes it counts, the reviews that close
//! a `Since`, the `TaskStart` that starts a task again and the `PromptSubmit` that starts a turn
//! again. `By::Under(p)` takes the acts of `p` and of the actors below it in the hierarchy of
//! actors, so the agent's own review does not start a count over that only the reviewer's does.
//! Placing a child under `p` makes its acts start the count over, so that spawn is asked of the
//! rule's author; and a temporary adjustment that lasts within such a scope is ended by those
//! acts, so the spawn is asked of the one who made it.
//!
//! The agent sits below the user, so `By::Under(user)` takes the agent's acts too. A limit that
//! only the user may start again is written with `By::Only(user)`: the user's own acts, not
//! those below it. A spawned leaf is never that principal, so no spawn moves an `Only`.
//!
//! When it cannot be told whether such a scope closed (a review by an actor of unknown place, or
//! a condition not known yet), an adjustment that lasts within it is kept as possibly ended and
//! read in the direction that tightens: a raise still holds, an exemption covers nothing, and a
//! suspension no longer holds. A later known close ends it.

use agent_caps_core::domain::adjust::{Inadmissible, Lifetime, Temporary, TemporaryBinding};
use agent_caps_core::domain::authority::{NotCovered, Principal};
use agent_caps_core::domain::catalog::{AcceptError, Catalog, Effect};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{Expect, Level, Rule};
use agent_caps_core::domain::predicate::{By, Cmp, Cond, EventFilter, Pred, Scope, Selector, Span};
use agent_caps_core::domain::schema::{EventKind, Field};
use agent_caps_core::domain::state::{Holding, Origin};
use agent_caps_core::domain::tx::{
    FindingDetail, Reader, TxDecision, TxPolicy, TxReport, Verdict as TxVerdict,
};

use super::common::{
    GUARD, Written, adjustment, adjustment_id, anyone, at, bash, binding_id, catalog,
    commit_filter, exempt_n, fixture, id, rejected, test_guard, the_agent, the_helper,
    the_reviewer, the_user, unreadable, verdict, violated, words,
};

/// The `n`th adjustment of the test guard, adding `add` and suspending its author's Force binding
/// when `suspend`, for as long as `lifetime`.
pub(super) fn rebind_guard(n: u8, add: Level, suspend: bool, lifetime: Lifetime) -> Body {
    adjustment(
        n,
        Temporary::Rebind {
            add: vec![TemporaryBinding {
                policy: id(GUARD),
                level: add,
            }],
            suspend: if suspend {
                vec![binding_id(id(GUARD), 0)]
            } else {
                vec![]
            },
        },
        lifetime,
    )
}

/// The effect of the test guard after `events`, and how each adjustment held then is held.
pub(super) fn guard_after(catalog: &Catalog, events: &[Event]) -> (Effect, Vec<Holding>) {
    let state = catalog.fold(Origin::Genesis, events);
    let effect = catalog
        .effective_in(&state)
        .unwrap()
        .policies
        .iter()
        .find(|p| p.policy.id() == id(GUARD))
        .map(|p| p.effect)
        .unwrap();
    let holding = state.adjustments().iter().map(|h| h.holding).collect();
    (effect, holding)
}

fn stranger() -> Principal {
    Principal::new("stranger")
}

/// FR54, FR55, FR20: a review by an actor the hierarchy does not know may or may not close the
/// scope a raise lasts within. The raise is kept, possibly ended, and still holds, so not knowing
/// ends no raise without a transaction; a later review by the reviewer ends it.
#[test]
fn a_raise_whose_scope_may_have_closed_still_holds() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let raise = by(
        &the_agent(),
        rebind_guard(
            1,
            Level::Force,
            false,
            Lifetime::Within(Scope::Since(reviewer_review())),
        ),
    );
    let maybe = [raise, review_by(&stranger()), push()];
    assert_eq!(
        guard_after(&catalog, &maybe),
        (Effect::On(Level::Force), vec![Holding::MaybeEnded])
    );
    let mut ended = maybe.to_vec();
    ended.extend([review_by(&the_reviewer()), push()]);
    assert_eq!(
        guard_after(&catalog, &ended),
        (Effect::On(Level::Advise), vec![])
    );
}

/// FR54, FR34, FR20: an exemption within the same scope, after the review of an actor of unknown
/// place, covers nothing: the guard judges the end of the turn again.
#[test]
fn an_exemption_whose_scope_may_have_closed_covers_nothing() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let exempt = by(
        &the_user(),
        exempt_n(
            1,
            GUARD,
            None,
            Lifetime::Within(Scope::Since(reviewer_review())),
        ),
    );
    let stop = || by(&the_agent(), Body::Stop);
    assert_eq!(verdict(&catalog, &[exempt.clone(), stop()]), Verdict::Allow);
    assert_eq!(
        verdict(&catalog, &[exempt, review_by(&stranger()), stop()]),
        violated()
    );
}

/// FR54, FR55, FR20: a lowering that suspends the guard's Force binding, after the review of an
/// actor of unknown place, suspends it no more: the guard is back at Force.
#[test]
fn a_suspension_whose_scope_may_have_closed_no_longer_holds() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let lowering = by(
        &the_user(),
        rebind_guard(
            1,
            Level::Advise,
            true,
            Lifetime::Within(Scope::Since(reviewer_review())),
        ),
    );
    assert_eq!(
        guard_after(&catalog, &[lowering.clone(), push()]),
        (Effect::On(Level::Advise), vec![Holding::Held])
    );
    assert_eq!(
        guard_after(&catalog, &[lowering, review_by(&stranger()), push()]),
        (Effect::On(Level::Force), vec![Holding::MaybeEnded])
    );
}

/// FR53, FR55, FR20: a commit whose result is not back may or may not close a scope that only a
/// successful commit closes, so a raise within it is kept, possibly ended, and still holds.
#[test]
fn a_raise_within_a_since_whose_condition_is_unknown_still_holds() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let raise = by(
        &the_agent(),
        rebind_guard(
            1,
            Level::Force,
            false,
            Lifetime::Within(Scope::Since(anyone(commit_filter(true)))),
        ),
    );
    let pending = bash("git commit -m x", None);
    assert_eq!(
        guard_after(&catalog, &[raise.clone(), pending, push()]),
        (Effect::On(Level::Force), vec![Holding::MaybeEnded])
    );
    assert_eq!(
        guard_after(
            &catalog,
            &[raise, bash("git commit -m x", Some(true)), push()]
        ),
        (Effect::On(Level::Advise), vec![])
    );
}

/// The event, by the actor.
pub(super) fn by(actor: &Principal, body: Body) -> Event {
    at(actor.clone(), 0, body)
}

fn bash_by(actor: &Principal, command: &str) -> Event {
    by(
        actor,
        Body::ToolUse {
            tool: "Bash".to_owned(),
            command: Some(words(command)),
            path: None,
            ok: Some(true),
        },
    )
}

pub(super) fn push() -> Event {
    bash_by(&the_agent(), "git push")
}

pub(super) fn review_by(actor: &Principal) -> Event {
    bash_by(actor, "gh pr review --approve")
}

/// A sub agent of the platform: a name that is new at each start.
pub(super) fn leaf(name: &str) -> Principal {
    Principal::new(name)
}

/// `spawner` starts the sub agent `child`, placed under `under`.
pub(super) fn spawn(spawner: &Principal, child: &Principal, under: &Principal) -> Event {
    by(
        spawner,
        Body::Spawn {
            child: child.clone(),
            under: under.clone(),
        },
    )
}

/// The transaction of `event` after `before`.
fn admit(catalog: &Catalog, before: &[Event], event: &Event) -> TxReport {
    catalog
        .admit(
            &catalog.fold(Origin::Genesis, before),
            event,
            &TxPolicy::standard(),
        )
        .unwrap()
}

/// What a spawn's check found, when it found one thing: its verdict.
fn spawn_finding(report: &TxReport) -> &TxVerdict {
    let [found] = report.findings.as_slice() else {
        panic!("one finding was expected: {report:?}")
    };
    assert_eq!(found.check.as_str(), "spawn");
    &found.verdict
}

fn tool_filter(command: &str) -> EventFilter {
    EventFilter {
        kind: EventKind::ToolUse,
        cond: Some(Cond::Words(Field::Command, words(command))),
    }
}

/// A review by the reviewer or an actor below it.
fn reviewer_review() -> Selector {
    Selector {
        filter: tool_filter("gh pr review"),
        by: By::Under(the_reviewer()),
    }
}

/// The user's Force guard on a push: at most `n` pushes, of anyone, within `scope`, the judged
/// push included.
pub(super) fn push_limit(scope: Scope, n: u32) -> Written {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ToolUse;
    guard.when = Some(Pred::Now(Cond::Words(Field::Command, words("git push"))));
    guard.rule = Rule::Structural(Pred::Count {
        select: anyone(tool_filter("git push")),
        scope,
        cmp: Cmp::Le,
        n,
    });
    guard.fixtures = vec![
        fixture(
            "one push too many",
            (0..=n).map(|_| push()).collect(),
            Expect::Violated,
        ),
        fixture("one push", vec![push()], Expect::Satisfied),
    ];
    guard
}

/// At most two pushes since the last review by the reviewer.
pub(super) fn pushes_since_review() -> Catalog {
    catalog(vec![push_limit(Scope::Since(reviewer_review()), 2)], vec![])
}

pub(super) fn unknown() -> Verdict {
    Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
}

/// UC26, FR54: the agent's own review does not start the count of pushes over; a review by a
/// child placed under the reviewer does.
#[test]
fn only_a_review_under_the_reviewer_starts_the_count_of_pushes_over() {
    let catalog = pushes_since_review();
    assert_eq!(
        verdict(&catalog, &[push(), push(), review_by(&the_agent()), push()]),
        violated()
    );
    let child = leaf("r1");
    assert_eq!(
        verdict(
            &catalog,
            &[
                spawn(&the_user(), &child, &the_reviewer()),
                push(),
                push(),
                review_by(&child),
                push(),
            ]
        ),
        Verdict::Allow
    );
    // The reviewer itself is under the reviewer.
    assert_eq!(
        verdict(
            &catalog,
            &[push(), push(), review_by(&the_reviewer()), push()]
        ),
        Verdict::Allow
    );
}

/// UC26, FR54: placing a child under the reviewer lets its reviews start the count over, which
/// cannot be read as tightening, so only one who covers the rule's author may: the agent's spawn
/// does not take effect, and the review of the child it would have placed is of an actor the
/// hierarchy does not know, so the count is unknown and the push is stopped. The user's spawn
/// takes effect.
#[test]
fn placing_a_child_under_the_reviewer_is_asked_of_the_rules_author() {
    let catalog = pushes_since_review();
    let child = leaf("r2");
    let by_agent = spawn(&the_agent(), &child, &the_reviewer());
    let report = admit(&catalog, &[], &by_agent);
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::Uncovered(vec![the_user()])]
    );
    assert_eq!(
        spawn_finding(&report),
        &TxVerdict::Loosens {
            authors: vec![the_user()],
            detail: FindingDetail::Spawn {
                child: child.clone(),
                under: the_reviewer(),
                loosened: vec![Reader::Policy(id(GUARD))],
            },
        }
    );
    assert_eq!(
        verdict(
            &catalog,
            &[by_agent, push(), push(), review_by(&child), push()]
        ),
        unknown()
    );

    let by_user = spawn(&the_user(), &child, &the_reviewer());
    assert_eq!(admit(&catalog, &[], &by_user).decision, TxDecision::Commit);
}

/// UC26, FR54: a task scope that chooses its start by actor starts again only at a `TaskStart`
/// of an actor it chooses: the agent is not under the reviewer, so its `TaskStart` does not
/// start the count of pushes over, and the reviewer's does.
#[test]
fn a_task_chosen_by_a_principal_is_not_started_again_by_the_agent() {
    let catalog = catalog(
        vec![push_limit(
            Scope::Span {
                span: Span::Task,
                by: By::Under(the_reviewer()),
            },
            2,
        )],
        vec![],
    );
    let start_by = |actor: &Principal| by(actor, Body::TaskStart);
    assert_eq!(
        verdict(&catalog, &[push(), push(), start_by(&the_agent()), push()]),
        violated()
    );
    assert_eq!(
        verdict(
            &catalog,
            &[push(), push(), start_by(&the_reviewer()), push()]
        ),
        Verdict::Allow
    );
}

/// UC26, FR54: a task that only the user may start again is written with `Only(user)`: the
/// agent sits below the user, and its `TaskStart` does not start the count of pushes over; the
/// user's does.
#[test]
fn a_task_only_the_user_starts_is_not_started_again_by_the_agent() {
    let catalog = catalog(
        vec![push_limit(
            Scope::Span {
                span: Span::Task,
                by: By::Only(the_user()),
            },
            2,
        )],
        vec![],
    );
    assert_eq!(
        verdict(
            &catalog,
            &[push(), push(), by(&the_agent(), Body::TaskStart), push()]
        ),
        violated()
    );
    assert_eq!(
        verdict(
            &catalog,
            &[push(), push(), by(&the_user(), Body::TaskStart), push()]
        ),
        Verdict::Allow
    );
}

/// UC26, FR54: with `Since(review by Only(reviewer))`, only the reviewer's own review starts the
/// count over: a child placed under the reviewer does not close it, so placing one moves nothing
/// the rule reads, and the agent's spawn is not asked of the rule's author.
#[test]
fn a_child_under_the_reviewer_does_not_close_a_since_only_the_reviewer_closes() {
    let catalog = catalog(
        vec![push_limit(
            Scope::Since(Selector {
                filter: tool_filter("gh pr review"),
                by: By::Only(the_reviewer()),
            }),
            2,
        )],
        vec![],
    );
    let child = leaf("r5");
    let placing = spawn(&the_agent(), &child, &the_reviewer());
    let report = admit(&catalog, &[], &placing);
    assert_eq!(report.decision, TxDecision::Commit);
    assert_eq!(spawn_finding(&report), &TxVerdict::Neutral);
    assert_eq!(
        verdict(
            &catalog,
            &[placing, push(), push(), review_by(&child), push()]
        ),
        violated()
    );
    assert_eq!(
        verdict(
            &catalog,
            &[push(), push(), review_by(&the_reviewer()), push()]
        ),
        Verdict::Allow
    );
}

/// FR55, FR54: a temporary adjustment whose lifetime chooses by a principal outside the
/// hierarchy is refused with its reason, as a rule that does is not accepted.
#[test]
fn a_lifetime_that_chooses_by_a_principal_outside_the_hierarchy_is_refused() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let stranger = Principal::new("stranger");
    for by_stranger in [By::Only(stranger.clone()), By::Under(stranger.clone())] {
        let raise = by(
            &the_user(),
            adjustment(
                1,
                Temporary::Rebind {
                    add: vec![TemporaryBinding {
                        policy: id(GUARD),
                        level: Level::Force,
                    }],
                    suspend: vec![],
                },
                Lifetime::Within(Scope::Span {
                    span: Span::Task,
                    by: by_stranger,
                }),
            ),
        );
        let report = admit(&catalog, &[], &raise);
        assert_eq!(report.decision, TxDecision::Abort);
        assert_eq!(
            report.inadmissible,
            Some(Inadmissible::UnknownActor(stranger.clone()))
        );
    }
}

/// FR54, FR31: a turn scope starts again at a `PromptSubmit` its `By` chooses, and at the start
/// of a session.
#[test]
fn a_turn_starts_again_at_a_prompt() {
    let catalog = catalog(
        vec![push_limit(
            Scope::Span {
                span: Span::Turn,
                by: By::Anyone,
            },
            1,
        )],
        vec![],
    );
    let prompt = || by(&the_user(), Body::PromptSubmit);
    assert_eq!(verdict(&catalog, &[prompt(), push(), push()]), violated());
    assert_eq!(
        verdict(&catalog, &[prompt(), push(), prompt(), push()]),
        Verdict::Allow
    );
    assert_eq!(
        verdict(
            &catalog,
            &[push(), by(&the_user(), Body::SessionStart), push()]
        ),
        Verdict::Allow
    );
}

/// UC26, FR54, FR53: a session's start, the agent's or the user's, does not start over a limit of
/// pushes since the last review: a `Since` scope is closed by the event it looks for, and by no
/// span's start. Only the review by the reviewer starts the count over.
#[test]
fn a_session_start_does_not_start_a_limit_since_the_last_review_over() {
    let catalog = pushes_since_review();
    for actor in [the_agent(), the_user()] {
        assert_eq!(
            verdict(
                &catalog,
                &[push(), push(), by(&actor, Body::SessionStart), push()]
            ),
            violated()
        );
    }
    assert_eq!(
        verdict(
            &catalog,
            &[push(), push(), review_by(&the_reviewer()), push()]
        ),
        Verdict::Allow
    );
}

/// UC26, FR54: a session's start starts a task again only when the task's `By` chooses the one
/// who started the session: a limit within a task that only the user starts again is started
/// over by the user's session start, and not by the agent's. A session whose `By` is `Only(user)`
/// is started again by the user's start alone, too.
#[test]
fn a_session_start_starts_a_task_again_only_for_the_one_the_task_chooses() {
    let span_of = |span, actor: &Principal| {
        catalog(
            vec![push_limit(
                Scope::Span {
                    span,
                    by: By::Only(actor.clone()),
                },
                2,
            )],
            vec![],
        )
    };
    for span in [Span::Task, Span::Session] {
        let catalog = span_of(span, &the_user());
        assert_eq!(
            verdict(
                &catalog,
                &[push(), push(), by(&the_agent(), Body::SessionStart), push()]
            ),
            violated(),
            "{span:?}"
        );
        assert_eq!(
            verdict(
                &catalog,
                &[push(), push(), by(&the_user(), Body::SessionStart), push()]
            ),
            Verdict::Allow,
            "{span:?}"
        );
    }
}

/// UC26, FR54, FR31: the spans nest as a session that holds tasks and turns, which are siblings.
/// The start of a span starts again that span and the spans inside it and no other: a task's
/// start does not start a turn again, nor a turn's a task, and neither starts the session they
/// are in; a session's start starts the tasks and the turns again.
#[test]
fn a_span_starts_itself_and_the_spans_inside_and_not_a_sibling_or_an_outer_one() {
    let limit = |span, n| {
        catalog(
            vec![push_limit(
                Scope::Span {
                    span,
                    by: By::Anyone,
                },
                n,
            )],
            vec![],
        )
    };
    let start = |body| by(&the_agent(), body);
    let (task, turn, session) = (
        limit(Span::Task, 2),
        limit(Span::Turn, 2),
        limit(Span::Session, 2),
    );
    let pushes = |starts: Body| [push(), push(), start(starts), push()];
    // A sibling or an outer span's scope goes on.
    assert_eq!(verdict(&turn, &pushes(Body::TaskStart)), violated());
    assert_eq!(verdict(&task, &pushes(Body::PromptSubmit)), violated());
    assert_eq!(verdict(&session, &pushes(Body::TaskStart)), violated());
    assert_eq!(verdict(&session, &pushes(Body::PromptSubmit)), violated());
    // The span itself, and the spans inside a session, start again.
    assert_eq!(verdict(&task, &pushes(Body::TaskStart)), Verdict::Allow);
    assert_eq!(verdict(&turn, &pushes(Body::PromptSubmit)), Verdict::Allow);
    assert_eq!(
        verdict(&session, &pushes(Body::SessionStart)),
        Verdict::Allow
    );
    assert_eq!(verdict(&task, &pushes(Body::SessionStart)), Verdict::Allow);
    assert_eq!(verdict(&turn, &pushes(Body::SessionStart)), Verdict::Allow);
}

/// FR54, FR20: a child placed after a record that may have been a spawn was lost has an unknown
/// place, so whether its review closes the interval is unknown, and so is the count: the next push
/// is stopped as unknown.
#[test]
fn a_review_by_an_actor_of_unknown_place_makes_the_count_unknown() {
    let catalog = pushes_since_review();
    let child = leaf("r3");
    assert_eq!(
        verdict(
            &catalog,
            &[
                unreadable(&[EventKind::Spawn]),
                spawn(&the_user(), &child, &the_reviewer()),
                push(),
                review_by(&child),
                push(),
            ]
        ),
        unknown()
    );
}

/// FR54, FR55, UC25: a raise that lasts until the next review by the reviewer ends at the acts of
/// those under the reviewer, so a spawn that places a child there is asked of the one who raised:
/// the helper, below the agent that raised, cannot place one; the agent can. With no such raise
/// in effect, the helper's spawn reads nothing and takes effect.
#[test]
fn a_spawn_that_changes_who_ends_a_raise_is_asked_of_the_one_who_raised() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let raise = by(
        &the_agent(),
        adjustment(
            1,
            Temporary::Rebind {
                add: vec![TemporaryBinding {
                    policy: id(GUARD),
                    level: Level::Force,
                }],
                suspend: vec![],
            },
            Lifetime::Within(Scope::Since(reviewer_review())),
        ),
    );
    let child = leaf("r4");
    let by_helper = spawn(&the_helper(), &child, &the_reviewer());

    let report = admit(&catalog, std::slice::from_ref(&raise), &by_helper);
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::Uncovered(vec![the_agent()])]
    );
    assert_eq!(
        spawn_finding(&report),
        &TxVerdict::Loosens {
            authors: vec![the_agent()],
            detail: FindingDetail::Spawn {
                child: child.clone(),
                under: the_reviewer(),
                loosened: vec![Reader::Adjustment(adjustment_id(1))],
            },
        }
    );

    let by_agent = spawn(&the_agent(), &child, &the_reviewer());
    let report = admit(&catalog, std::slice::from_ref(&raise), &by_agent);
    assert_eq!(report.decision, TxDecision::Commit);

    assert_eq!(
        admit(&catalog, &[], &by_helper).decision,
        TxDecision::Commit
    );
}

/// FR55, FR54: an adjustment that lasts within a task or a turn ends when the scope starts again,
/// though no rule counts in that scope (the test guard counts in a task any actor starts): a raise
/// within a turn ends at the next prompt, and one within a task the reviewer starts ends at the
/// reviewer's `TaskStart`, not at the agent's.
#[test]
fn an_adjustment_ends_with_a_scope_no_rule_counts_in() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let raise_within = |scope| {
        by(
            &the_user(),
            adjustment(
                1,
                Temporary::Rebind {
                    add: vec![TemporaryBinding {
                        policy: id(GUARD),
                        level: Level::Force,
                    }],
                    suspend: vec![],
                },
                Lifetime::Within(scope),
            ),
        )
    };
    let held = |events: &[Event]| catalog.fold(Origin::Genesis, events).adjustments().len();

    let turn = raise_within(Scope::Span {
        span: Span::Turn,
        by: By::Anyone,
    });
    assert_eq!(held(std::slice::from_ref(&turn)), 1);
    assert_eq!(held(&[turn, by(&the_user(), Body::PromptSubmit)]), 0);

    let task = raise_within(Scope::Span {
        span: Span::Task,
        by: By::Under(the_reviewer()),
    });
    assert_eq!(held(&[task.clone(), by(&the_agent(), Body::TaskStart)]), 1);
    assert_eq!(held(&[task, by(&the_reviewer(), Body::TaskStart)]), 0);
}

/// FR54, FR38: a principal a selector or a scope chooses events by must be one of the hierarchy,
/// as one that `ActorUnder` names: a spawned actor's name is new at every start.
#[test]
fn choosing_by_a_principal_outside_the_hierarchy_is_not_accepted() {
    let stranger = Principal::new("stranger");
    let mut guard = push_limit(
        Scope::Span {
            span: Span::Task,
            by: By::Anyone,
        },
        2,
    );
    guard.rule = Rule::Structural(Pred::Count {
        select: Selector {
            filter: tool_filter("git push"),
            by: By::Under(stranger.clone()),
        },
        scope: Scope::Span {
            span: Span::Task,
            by: By::Anyone,
        },
        cmp: Cmp::Le,
        n: 2,
    });
    assert_eq!(
        rejected(vec![guard], vec![]),
        vec![AcceptError::UnknownActor {
            policy: id(GUARD),
            principal: stranger.clone(),
        }]
    );

    let in_scope = push_limit(
        Scope::Span {
            span: Span::Turn,
            by: By::Under(stranger.clone()),
        },
        2,
    );
    assert_eq!(
        rejected(vec![in_scope], vec![]),
        vec![AcceptError::UnknownActor {
            policy: id(GUARD),
            principal: stranger.clone(),
        }]
    );

    // `Only` reads no hierarchy a spawn can move, and is held to the hierarchy all the same.
    let only = push_limit(
        Scope::Span {
            span: Span::Task,
            by: By::Only(stranger.clone()),
        },
        2,
    );
    assert_eq!(
        rejected(vec![only], vec![]),
        vec![AcceptError::UnknownActor {
            policy: id(GUARD),
            principal: stranger,
        }]
    );
}
