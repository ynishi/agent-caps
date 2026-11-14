//! Scenario V2: a role seen as a condition on the acting principal. Inside a sub agent placed
//! under the role `reviewer`, an edit is stopped (Force). The guard applies where the actor of the
//! event is under `reviewer` in the hierarchy of actors, and its rule is that the tool is not an
//! edit.
//!
//! The role is a node of the hierarchy (`reviewer`, below the agent), and a sub agent is a leaf
//! that a spawn adds under it. Nothing ends an agent, and nothing needs to: the guard reads who
//! acts in each event, so the parent's next edit is not stopped, and a child of the reviewer is
//! stopped as long as it acts. Where a spawn places its child is a claim, judged against a place
//! directly under the spawner: a rule that applies inside `reviewer` is tightened when a child is
//! placed in it, which anyone may do; a rule that applies outside it, or whose reading of the
//! actor cannot be told, is loosened by it, which only one who covers that rule's author may do.
//! An actor the hierarchy does not know, or one placed after a record that may have been a spawn
//! was lost, is unknown to the hierarchy, and a rule stops there what it would stop in the role
//! (FR72).
//!
//! What cannot be written: a rule that counts the events of one actor since it was spawned. The
//! scope of an agent was removed with the event that started it, and a spawned actor has no name
//! a rule can use; a rule chooses events by the principal an actor sits under instead (FR54, see
//! the `limits` module).

use agent_caps_core::domain::adjust::Lifetime;
use agent_caps_core::domain::authority::{NotCovered, Principal};
use agent_caps_core::domain::catalog::{AcceptError, Catalog};
use agent_caps_core::domain::event::{Body, Event, Seen};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::name::GlobPattern;
use agent_caps_core::domain::policy::{DefLayer, Expect, Level, Polarity, PolicyDef, Rule};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred};
use agent_caps_core::domain::schema::{EventKind, Field};
use agent_caps_core::domain::state::Origin;
use agent_caps_core::domain::tx::{
    FindingDetail, Reader, TxDecision, TxPolicy, TxReport, Verdict as TxVerdict,
};

use super::common::{
    GUARD, OTHER, REWARD, Written, at, catalog, clippy_reward, exempt_n, fixture, id,
    push_after_allowed, rejected, test_guard, the_agent, the_helper, the_reviewer, the_user,
    unreadable, verdict, violated, written,
};

/// The event, by the actor.
fn by(actor: &Principal, body: Body) -> Event {
    at(actor.clone(), 0, body)
}

fn tool(actor: &Principal, tool: &str, path: &str) -> Event {
    by(
        actor,
        Body::ToolUse {
            tool: tool.to_owned(),
            command: Seen::Absent,
            path: Seen::Value(path.to_owned()),
            ok: None,
        },
    )
}

fn edit_by(actor: &Principal) -> Event {
    tool(actor, "Edit", "src/a.rs")
}

fn read_by(actor: &Principal, path: &str) -> Event {
    tool(actor, "Read", path)
}

/// A sub agent of the platform: a name that is new at each start.
fn leaf(name: &str) -> Principal {
    Principal::new(name)
}

/// `spawner` starts the sub agent `child`, placed under `under`.
fn spawn(spawner: &Principal, child: &Principal, under: &Principal) -> Event {
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

/// The events, and one more.
fn then(events: &[Event], last: Event) -> Vec<Event> {
    let mut all = events.to_vec();
    all.push(last);
    all
}

/// What a spawn's check found, when it found one thing: its verdict.
fn spawn_finding(report: &TxReport) -> &TxVerdict {
    let [found] = report.findings.as_slice() else {
        panic!("one finding was expected: {report:?}")
    };
    assert_eq!(found.check.as_str(), "spawn");
    &found.verdict
}

/// The verdict of a stopping guard that cannot tell.
fn unknown(policy: &str) -> Verdict {
    Verdict::Deny(vec![Cause::Unknown(id(policy))])
}

/// The verdict of a stopping guard that was violated.
fn violated_by(policy: &str) -> Verdict {
    Verdict::Deny(vec![Cause::Violated(id(policy))])
}

/// Force: no edit by an actor under the `reviewer`. It applies where the actor is under the role:
/// the principal is read where the guard applies.
fn reviewer_guard() -> Written {
    let child = leaf("r0");
    let def = PolicyDef {
        id: id(GUARD),
        name: "reviewer-does-not-edit".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: Some(Pred::ActorUnder(the_reviewer())),
        rule: Rule::Structural(Pred::Not(Box::new(Pred::Now(Cond::Eq(
            Field::Tool,
            Lit::Text("Edit".to_owned()),
        ))))),
        polarity: Polarity::Guard,
        fixtures: vec![
            fixture(
                "an edit by a sub agent under the reviewer",
                vec![
                    spawn(&the_agent(), &child, &the_reviewer()),
                    edit_by(&child),
                ],
                Expect::Violated,
            ),
            fixture(
                "a read by a sub agent under the reviewer",
                vec![
                    spawn(&the_agent(), &child, &the_reviewer()),
                    read_by(&child, "src/a.rs"),
                ],
                Expect::Satisfied,
            ),
        ],
        author: the_user(),
    };
    written(def, Level::Force)
}

/// Force: nothing outside the `reviewer` reads a secret. It applies where the actor is not under
/// the role: the principal is read where the direction cannot be told.
fn secret_guard() -> Written {
    let def = PolicyDef {
        id: id(OTHER),
        name: "only-the-reviewer-reads-secrets".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: Some(Pred::Not(Box::new(Pred::ActorUnder(the_reviewer())))),
        rule: Rule::Structural(Pred::Not(Box::new(Pred::Now(Cond::Glob(
            Field::Path,
            GlobPattern::new("secrets/*").unwrap(),
        ))))),
        polarity: Polarity::Guard,
        fixtures: vec![
            fixture(
                "a read of a secret by the agent",
                vec![read_by(&the_agent(), "secrets/key")],
                Expect::Violated,
            ),
            fixture(
                "a read of a source by the agent",
                vec![read_by(&the_agent(), "src/a.rs")],
                Expect::Satisfied,
            ),
        ],
        author: the_user(),
    };
    written(def, Level::Force)
}

/// Force: no edit by `under` or anything under it. It applies where the actor is under it.
fn no_edit_under(policy: &str, name: &str, under: Principal) -> Written {
    let mut guard = reviewer_guard();
    guard.id = id(policy);
    guard.name = name.parse().unwrap();
    guard.when = Some(Pred::ActorUnder(under.clone()));
    guard.fixtures = vec![
        fixture("an edit", vec![edit_by(&under)], Expect::Violated),
        fixture(
            "a read",
            vec![read_by(&under, "src/a.rs")],
            Expect::Satisfied,
        ),
    ];
    guard
}

/// The guard that stops an edit by the agent or anything under it.
fn agent_guard() -> Written {
    no_edit_under(GUARD, "the-agent-does-not-edit", the_agent())
}

/// UC29, FR73: an edit is stopped inside a reviewer and only there, and nothing has to end the
/// reviewer: the parent's next edit is not stopped, and a child of the reviewer's child is under
/// the reviewer too.
#[test]
fn an_edit_is_stopped_under_a_reviewer_and_only_there() {
    let catalog = catalog(vec![reviewer_guard()], vec![]);
    let (agent, r1, r1a) = (the_agent(), leaf("r1"), leaf("r1a"));
    let spawned = [spawn(&agent, &r1, &the_reviewer())];

    assert_eq!(verdict(&catalog, &then(&spawned, edit_by(&r1))), violated());
    // Reading is allowed in a reviewer.
    assert_eq!(
        verdict(&catalog, &then(&spawned, read_by(&r1, "src/a.rs"))),
        Verdict::Allow
    );
    // The parent's edit after the reviewer's work is not stopped; no event ended the reviewer.
    let worked = [
        spawned[0].clone(),
        read_by(&r1, "src/a.rs"),
        edit_by(&r1),
        read_by(&agent, "src/b.rs"),
    ];
    assert_eq!(
        verdict(&catalog, &then(&worked, edit_by(&agent))),
        Verdict::Allow
    );
    // And the reviewer's next edit is stopped again.
    let later = then(&worked, edit_by(&agent));
    assert_eq!(verdict(&catalog, &then(&later, edit_by(&r1))), violated());

    // A child of the reviewer's child, placed under it, is under the reviewer.
    let grandchild = [spawned[0].clone(), spawn(&r1, &r1a, &r1)];
    assert_eq!(
        verdict(&catalog, &then(&grandchild, edit_by(&r1a))),
        violated()
    );

    // A sub agent placed under another principal, and an actor of the hierarchy that was not
    // spawned, may edit.
    let (h1, helper_child) = (leaf("h1"), [spawn(&agent, &leaf("h1"), &the_helper())]);
    assert_eq!(
        verdict(&catalog, &then(&helper_child, edit_by(&h1))),
        Verdict::Allow
    );
    assert_eq!(verdict(&catalog, &[edit_by(&agent)]), Verdict::Allow);
}

/// UC29, FR73, UC25: a rule that applies inside the reviewer is tightened when a child is placed
/// under it, so the lowest principal of the hierarchy may place one, and the child is stopped.
#[test]
fn placing_a_child_under_a_role_tightens_a_rule_that_applies_inside_it() {
    let catalog = catalog(vec![reviewer_guard()], vec![]);
    let (helper, r2) = (the_helper(), leaf("r2"));
    let placing = spawn(&helper, &r2, &the_reviewer());

    let report = admit(&catalog, &[], &placing);
    assert_eq!(report.decision, TxDecision::Commit);
    assert!(report.uncovered.is_empty());
    assert!(matches!(spawn_finding(&report), TxVerdict::Tightens(_)));
    assert_eq!(verdict(&catalog, &[placing, edit_by(&r2)]), violated());
}

/// UC29, FR73, UC25: a rule that applies outside the reviewer reads the actor in a direction that
/// cannot be told as tightening, so a child placed under the reviewer loosens it. The agent does
/// not cover the user's rule, so its spawn does not take effect; the user's does.
#[test]
fn placing_a_child_under_a_role_loosens_a_rule_that_applies_outside_it() {
    let catalog = catalog(vec![secret_guard()], vec![]);
    let (agent, r3) = (the_agent(), leaf("r3"));
    let placing = spawn(&agent, &r3, &the_reviewer());

    let report = admit(&catalog, &[], &placing);
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
                child: r3.clone(),
                under: the_reviewer(),
                loosened: vec![Reader::Policy(id(OTHER))],
            },
        }
    );

    // The user covers the rule's author, so its spawn takes effect, and the child, now under the
    // reviewer, is outside the rule.
    let by_user = spawn(&the_user(), &r3, &the_reviewer());
    let report = admit(&catalog, &[], &by_user);
    assert_eq!(report.decision, TxDecision::Commit);
    assert_eq!(
        verdict(&catalog, &[by_user, read_by(&r3, "secrets/key")]),
        Verdict::Allow
    );
}

/// UC29, FR73, UC25, FR41: a child placed under the reviewer makes the reviewer's guard apply to
/// it, and so writes more judgments of that guard. A root rule that reads the guard's judgments is
/// moved by that, so the placement from below, which would otherwise only tighten, does not take
/// effect; the root's does.
#[test]
fn placing_a_child_where_a_guard_applies_loosens_a_rule_that_reads_that_guards_judgments() {
    // The reader makes the guard's placements the root's to make, so its fixtures are spawned by
    // the root.
    let mut guard = reviewer_guard();
    let child = leaf("r0");
    guard.fixtures = vec![
        fixture(
            "an edit by a sub agent the root placed under the reviewer",
            vec![spawn(&the_user(), &child, &the_reviewer()), edit_by(&child)],
            Expect::Violated,
        ),
        fixture(
            "a read by a sub agent the root placed under the reviewer",
            vec![
                spawn(&the_user(), &child, &the_reviewer()),
                read_by(&child, "src/a.rs"),
            ],
            Expect::Satisfied,
        ),
    ];
    let catalog = catalog(vec![guard, push_after_allowed(GUARD)], vec![]);
    let (helper, r5) = (the_helper(), leaf("r5"));
    let placing = spawn(&helper, &r5, &the_reviewer());

    let report = admit(&catalog, &[], &placing);
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::Uncovered(vec![the_user()])]
    );
    // The guard that applies to more stays tightened; the rule that reads its judgments loosens.
    assert_eq!(
        spawn_finding(&report),
        &TxVerdict::Loosens {
            authors: vec![the_user()],
            detail: FindingDetail::Spawn {
                child: r5.clone(),
                under: the_reviewer(),
                loosened: vec![Reader::Policy(id(OTHER))],
            },
        }
    );

    let by_user = spawn(&the_user(), &r5, &the_reviewer());
    assert_eq!(admit(&catalog, &[], &by_user).decision, TxDecision::Commit);
}

/// UC29, FR73, UC25: a child placed above its spawner leaves the principals between, and a rule
/// that applies inside one of them is loosened by it, so the agent, which does not cover the
/// user's rule, cannot place one. A child placed under another principal that is still below the
/// agent stays in the agent's work, and so does one a lower principal places under the agent.
#[test]
fn placing_a_child_above_its_spawner_loosens_a_rule_that_applies_inside_the_spawner() {
    let catalog = catalog(vec![agent_guard()], vec![]);
    let (agent, esc) = (the_agent(), leaf("esc"));
    let escaping = spawn(&agent, &esc, &the_user());

    let report = admit(&catalog, &[], &escaping);
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::Uncovered(vec![the_user()])]
    );
    assert!(matches!(spawn_finding(&report), TxVerdict::Loosens { .. }));
    // The child that escaped is not placed: it is an unknown actor, not one outside the agent.
    assert_eq!(
        verdict(&catalog, &[escaping, edit_by(&esc)]),
        unknown(GUARD)
    );

    // Under the helper, still below the agent: the child's work is the agent's work.
    let (h2, kept) = (leaf("h2"), spawn(&agent, &leaf("h2"), &the_helper()));
    let report = admit(&catalog, &[], &kept);
    assert_eq!(report.decision, TxDecision::Commit);
    assert_eq!(spawn_finding(&report), &TxVerdict::Neutral);
    assert_eq!(verdict(&catalog, &[kept, edit_by(&h2)]), violated());

    // The helper leaves itself by placing a child under the agent, which no rule reads.
    let (h3, lifted) = (leaf("h3"), spawn(&the_helper(), &leaf("h3"), &agent));
    assert_eq!(admit(&catalog, &[], &lifted).decision, TxDecision::Commit);
    assert_eq!(verdict(&catalog, &[lifted, edit_by(&h3)]), violated());
}

/// UC29, FR73: the shape of a spawn is kept without asking who made it. A child that is already
/// in the hierarchy of actors, a principal of the authority or a leaf, is not added again or moved,
/// and a spawn under a place that is not in it adds nothing.
#[test]
fn a_spawn_adds_a_new_child_under_a_known_place_once() {
    let helper_guard = no_edit_under(OTHER, "the-helper-does-not-edit", the_helper());
    let catalog = catalog(vec![reviewer_guard(), helper_guard], vec![]);
    let (user, r1) = (the_user(), leaf("r1"));
    let placed = spawn(&the_agent(), &r1, &the_reviewer());

    // A leaf is never moved: the user's second spawn of `r1` adds nothing.
    let second = spawn(&user, &r1, &user);
    let report = admit(&catalog, std::slice::from_ref(&placed), &second);
    assert_eq!(report.decision, TxDecision::Commit);
    assert!(report.findings.is_empty());
    assert_eq!(
        verdict(&catalog, &[placed.clone(), second, edit_by(&r1)]),
        violated()
    );

    // A principal of the authority is already in the hierarchy: it is not added, so it stays
    // under the agent, where the second guard reads it.
    let helper = spawn(&user, &the_helper(), &user);
    let report = admit(&catalog, &[], &helper);
    assert!(report.findings.is_empty());
    assert_eq!(
        verdict(&catalog, &[helper, edit_by(&the_helper())]),
        violated_by(OTHER)
    );

    // A place that is not in the hierarchy of actors: nothing is added, so the child stays an
    // unknown actor, which both guards stop.
    let r9 = leaf("r9");
    let nowhere = spawn(&user, &r9, &leaf("nowhere"));
    let report = admit(&catalog, &[], &nowhere);
    assert_eq!(report.decision, TxDecision::Commit);
    assert!(report.findings.is_empty());
    assert_eq!(
        verdict(&catalog, &[nowhere, edit_by(&r9)]),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD)), Cause::Unknown(id(OTHER))])
    );
}

/// UC29, FR73, FR20: an actor the hierarchy does not know is unknown, not "not under", so a
/// stopping rule stops it. So is a sub agent placed after a record that may have been a spawn was
/// lost; one placed before it is as it was.
#[test]
fn an_unknown_actor_and_a_leaf_after_a_lost_spawn_are_stopped_as_unknown() {
    let catalog = catalog(vec![reviewer_guard()], vec![]);
    let (agent, stranger) = (the_agent(), leaf("stranger"));

    assert_eq!(verdict(&catalog, &[edit_by(&stranger)]), unknown(GUARD));

    let lost = unreadable(&[EventKind::Spawn]);
    let late = leaf("late");
    let placing = spawn(&agent, &late, &the_reviewer());
    // The spawn after the lost record takes effect (it only tightens), but the place of the
    // child is not known.
    assert_eq!(
        admit(&catalog, std::slice::from_ref(&lost), &placing).decision,
        TxDecision::Commit
    );
    assert_eq!(
        verdict(&catalog, &[lost.clone(), placing.clone(), edit_by(&late)]),
        unknown(GUARD)
    );
    // The same spawn, with no record lost before it, is known.
    assert_eq!(verdict(&catalog, &[placing, edit_by(&late)]), violated());

    // A leaf placed before the lost record is as it was.
    let early = leaf("early");
    let placed_early = [spawn(&agent, &early, &the_reviewer()), lost];
    assert_eq!(
        verdict(&catalog, &then(&placed_early, edit_by(&early))),
        violated()
    );
    // Losing the record loosens nothing for the actors that are known.
    assert_eq!(
        verdict(&catalog, &then(&placed_early, edit_by(&agent))),
        Verdict::Allow
    );
}

/// UC29, FR73: a rule is checked against the hierarchy when it is accepted: it can name only a
/// principal of the hierarchy, since the name of a spawned leaf is new at every start.
#[test]
fn a_rule_that_names_an_actor_outside_the_hierarchy_is_rejected() {
    let ghost = Principal::new("ghost");
    let mut guard = reviewer_guard();
    guard.when = Some(Pred::All(vec![
        Pred::ActorUnder(the_reviewer()),
        Pred::Not(Box::new(Pred::ActorUnder(ghost.clone()))),
    ]));
    assert_eq!(
        rejected(vec![guard], vec![]),
        vec![AcceptError::UnknownActor {
            policy: id(GUARD),
            principal: ghost,
        }]
    );
}

/// UC29, FR73, UC25: a sub agent is a leaf of the hierarchy of actors, not an author, so what it
/// claims loosens nothing: its exemption of the guard does not take effect, and the guard goes on
/// stopping it.
#[test]
fn a_spawned_leaf_cannot_loosen_by_a_claim() {
    let catalog = catalog(vec![reviewer_guard()], vec![]);
    let r1 = leaf("r1");
    let placed = spawn(&the_agent(), &r1, &the_reviewer());
    let exemption = by(&r1, exempt_n(1, GUARD, None, Lifetime::Next));

    let report = admit(&catalog, std::slice::from_ref(&placed), &exemption);
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.uncovered,
        vec![NotCovered::UnknownPrincipal(r1.clone())]
    );
    assert_eq!(
        verdict(&catalog, &[placed, exemption, edit_by(&r1)]),
        violated()
    );
}

/// UC29, FR73, FR20, UC25: a leaf of unknown place that places a child under itself puts it where
/// the child of its work already is, so the spawn changes how no rule reads the actor, and it
/// takes effect although the leaf covers no author. Above itself, it does not.
#[test]
fn a_leaf_of_unknown_place_may_place_a_child_under_itself_only() {
    let catalog = catalog(vec![agent_guard()], vec![]);
    let (agent, late, sub) = (the_agent(), leaf("late"), leaf("sub"));
    let before = [
        unreadable(&[EventKind::Spawn]),
        spawn(&agent, &late, &the_agent()),
    ];

    let report = admit(&catalog, &before, &spawn(&late, &sub, &late));
    assert_eq!(report.decision, TxDecision::Commit);
    assert_eq!(spawn_finding(&report), &TxVerdict::Neutral);
    // Its child is of unknown place too, and stopped as unknown.
    let placed = then(&before, spawn(&late, &sub, &late));
    assert_eq!(
        verdict(&catalog, &then(&placed, edit_by(&sub))),
        unknown(GUARD)
    );

    let report = admit(&catalog, &before, &spawn(&late, &sub, &the_user()));
    assert_eq!(report.decision, TxDecision::Abort);
}

/// UC29, FR73, FR20, UC25: the child of a spawn that was lost is an unknown actor. When it places
/// a sub agent above the agent, where a rule of the user's applies inside the agent, what it
/// leaves is not read as "nothing": the claim is not from the hierarchy, so it does not take
/// effect, and the sub agent stays unknown and stopped.
#[test]
fn an_unknown_actor_cannot_place_a_child_above_the_agent() {
    let catalog = catalog(vec![agent_guard()], vec![]);
    let (ghost, d) = (leaf("ghost-child"), leaf("d"));
    let lost = unreadable(&[EventKind::Spawn]);
    let placing = spawn(&ghost, &d, &the_user());

    let report = admit(&catalog, std::slice::from_ref(&lost), &placing);
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(report.uncovered, vec![NotCovered::UnknownPrincipal(ghost)]);
    assert!(matches!(spawn_finding(&report), TxVerdict::Loosens { .. }));
    assert_eq!(
        verdict(&catalog, &[lost, placing, edit_by(&d)]),
        unknown(GUARD)
    );
}

/// UC29, FR73, UC25: a policy that reads the actor in a reward is not neutral: a reward's hit is
/// recorded as a judgment that guards read, so its direction is not read, and a placement into the
/// role loosens it. The agent may not place a child there; the user may.
#[test]
fn placing_a_child_loosens_a_reward_that_reads_the_actor() {
    let mut reward = clippy_reward(Level::Advise);
    reward.when = Some(Pred::ActorUnder(the_reviewer()));
    let catalog = catalog(vec![test_guard(Level::Force), reward], vec![]);
    let r4 = leaf("r4");

    let report = admit(&catalog, &[], &spawn(&the_agent(), &r4, &the_reviewer()));
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
                child: r4.clone(),
                under: the_reviewer(),
                loosened: vec![Reader::Policy(id(REWARD))],
            },
        }
    );
    let report = admit(&catalog, &[], &spawn(&the_user(), &r4, &the_reviewer()));
    assert_eq!(report.decision, TxDecision::Commit);
}

/// UC29, FR73, FR72, FR20: the fact of a spawn that did not take effect. The platform has started
/// the sub agent all the same and it acts, but the hierarchy never learned its place: every event
/// of it is by an unknown actor, and a rule that reads the actor stops what it would stop and
/// nothing else: the read of a secret is stopped as unknown, and a harmless read and an edit,
/// which the rule lets through whether the actor is under the role or not, are not.
#[test]
fn the_child_of_a_spawn_that_did_not_take_effect_goes_on_acting_and_is_stopped_for_what_the_rule_stops()
 {
    let catalog = catalog(vec![secret_guard()], vec![]);
    let r3 = leaf("r3");
    let placing = spawn(&the_agent(), &r3, &the_reviewer());
    assert_eq!(admit(&catalog, &[], &placing).decision, TxDecision::Abort);

    let mut events = vec![placing];
    for (event, expected) in [
        (read_by(&r3, "src/a.rs"), Verdict::Allow),
        (read_by(&r3, "secrets/key"), unknown(OTHER)),
        (edit_by(&r3), Verdict::Allow),
    ] {
        events.push(event);
        assert_eq!(verdict(&catalog, &events), expected);
    }
}
