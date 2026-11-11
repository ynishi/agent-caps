//! Scenario S3: an exemption covers what its cover covers for its lifetime, never a meta guard. It is a
//! claim that loosens its guard, so it takes effect only from one who covers the guard's author:
//! the root exempts any guard, the principal below it its own, and nobody one above its own.

use agent_caps_core::domain::adjust::{Inadmissible, Lifetime};
use agent_caps_core::domain::catalog::Capabilities;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Cause, Verdict, judge};
use agent_caps_core::domain::policy::{DefLayer, Level};
use agent_caps_core::domain::predicate::{By, Cond, Lit, Scope, Span};
use agent_caps_core::domain::schema::{At, EventKind, Field};
use agent_caps_core::domain::state::Origin;
use agent_caps_core::domain::tx::{TxDecision, TxPolicy};

use super::common::{
    GUARD, OTHER, agent, at, catalog, edit, exempt_n, exempt_n_by, id, src_edit_guard, test_guard,
    the_agent, the_helper, the_user, unreadable, user, verdict,
};

/// An exemption of `guard` with no cover, for the task; its id is the `n`th.
fn exempt_for_the_task(n: u8, guard: &str) -> Body {
    exempt_n(
        n,
        guard,
        None,
        Lifetime::Within(Scope::Span {
            span: Span::Task,
            by: By::Anyone,
        }),
    )
}

/// FR34, UC6: an exemption from the root covers its target for its lifetime. UC25: one from the
/// principal below it, of the root's guard, is nothing.
#[test]
fn a_users_exemption_covers_its_target_for_its_lifetime() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let exempt = |lifetime| {
        exempt_n(
            1,
            GUARD,
            Some(Cond::Eq(Field::Path, Lit::Text("src/a.rs".to_owned()))),
            lifetime,
        )
    };
    let start = agent(Body::TaskStart);

    // From below the guard's author, an exemption is nothing.
    assert!(matches!(
        verdict(
            &catalog,
            &[
                start.clone(),
                agent(exempt(Lifetime::Next)),
                edit("src/a.rs")
            ]
        ),
        Verdict::Deny(_)
    ));

    // From the root, it covers its target, not another path.
    let next = [
        start.clone(),
        user(exempt(Lifetime::Next)),
        edit("src/a.rs"),
    ];
    assert_eq!(verdict(&catalog, &next), Verdict::Allow);
    assert!(matches!(
        verdict(
            &catalog,
            &[
                start.clone(),
                user(exempt(Lifetime::Next)),
                edit("src/b.rs")
            ]
        ),
        Verdict::Deny(_)
    ));

    // `Next` is used up by the judgment it covered.
    let state = catalog.fold(Origin::Genesis, &next);
    let outcome = judge(&catalog, &state, &next[2], &Capabilities::full());
    let mut events = next.to_vec();
    events.extend(outcome.evidence(At::from_millis(1)));
    events.push(edit("src/a.rs"));
    assert!(matches!(verdict(&catalog, &events), Verdict::Deny(_)));

    // `Within(Task)` lasts until the task starts again.
    let within = user(exempt(Lifetime::Within(Scope::Span {
        span: Span::Task,
        by: By::Anyone,
    })));
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                within.clone(),
                edit("src/a.rs"),
                edit("src/a.rs")
            ]
        ),
        Verdict::Allow
    );
    assert!(matches!(
        verdict(
            &catalog,
            &[start.clone(), within, start.clone(), edit("src/a.rs")]
        ),
        Verdict::Deny(_)
    ));

    // The time it ends by is compared with the time of the judged event.
    let until = at(
        the_user(),
        0,
        exempt_n_by(
            1,
            GUARD,
            Some(Cond::Eq(Field::Path, Lit::Text("src/a.rs".to_owned()))),
            Lifetime::Timed,
            At::from_millis(100),
        ),
    );
    let edit_at = |millis| at(the_agent(), millis, edit("src/a.rs").body);
    assert_eq!(
        verdict(&catalog, &[start.clone(), until.clone(), edit_at(99)]),
        Verdict::Allow
    );
    assert!(matches!(
        verdict(&catalog, &[start.clone(), until, edit_at(100)]),
        Verdict::Deny(_)
    ));

    // A lost record that may have been a judgment may have used the exemption up: it ends.
    assert!(matches!(
        verdict(
            &catalog,
            &[
                start,
                user(exempt(Lifetime::Next)),
                unreadable(&[EventKind::Judged]),
                edit("src/a.rs")
            ]
        ),
        Verdict::Deny(_)
    ));
}

/// UC25, FR34: an exemption of the root's guard from the principal below it is nothing,
/// whatever it asks for: its lifetime, or no target at all. The root's exemption next to it
/// still works.
#[test]
fn an_exemption_from_the_agent_covers_nothing_whatever_its_lifetime() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let exempt = |cover, lifetime| exempt_n(1, GUARD, cover, lifetime);
    let start = agent(Body::TaskStart);
    let lifetimes = [
        Lifetime::Next,
        Lifetime::Within(Scope::Span {
            span: Span::Task,
            by: By::Anyone,
        }),
        Lifetime::Within(Scope::Span {
            span: Span::Session,
            by: By::Anyone,
        }),
        Lifetime::Timed,
    ];
    for lifetime in lifetimes {
        for target in [
            None,
            Some(Cond::Eq(Field::Path, Lit::Text("src/a.rs".to_owned()))),
        ] {
            assert!(
                matches!(
                    verdict(
                        &catalog,
                        &[
                            start.clone(),
                            agent(exempt(target.clone(), lifetime.clone())),
                            edit("src/a.rs")
                        ]
                    ),
                    Verdict::Deny(_)
                ),
                "{lifetime:?} from below, target {target:?}"
            );
        }
    }

    // The same exemption from the root, next to the one from below, covers the edit.
    assert_eq!(
        verdict(
            &catalog,
            &[
                start,
                agent(exempt(
                    None,
                    Lifetime::Within(Scope::Span {
                        span: Span::Task,
                        by: By::Anyone
                    })
                )),
                user(exempt(
                    None,
                    Lifetime::Within(Scope::Span {
                        span: Span::Task,
                        by: By::Anyone
                    })
                )),
                edit("src/a.rs")
            ]
        ),
        Verdict::Allow
    );
}

/// FR34, UC25, UC6: the root exempts any guard; the principal below it exempts the guard it
/// wrote itself, but not the root's; and the one below that does not exempt the guard of the
/// one above it.
#[test]
fn a_principal_exempts_the_guards_it_covers_and_no_other() {
    let mut own = src_edit_guard();
    own.id = id(OTHER);
    own.name = "agent-src-edit".parse().unwrap();
    own.author = the_agent();
    let catalog = catalog(vec![src_edit_guard(), own], vec![]);
    let start = agent(Body::TaskStart);
    let judged = |claims: Vec<_>| {
        let mut events = vec![start.clone()];
        events.extend(claims);
        events.push(edit("src/a.rs"));
        verdict(&catalog, &events)
    };
    let both = Verdict::Deny(vec![Cause::Violated(id(GUARD)), Cause::Violated(id(OTHER))]);
    assert_eq!(judged(vec![]), both);

    // Below the root, its own guard: exempted. The root's: not.
    assert_eq!(
        judged(vec![agent(exempt_for_the_task(2, OTHER))]),
        Verdict::Deny(vec![Cause::Violated(id(GUARD))])
    );
    assert_eq!(judged(vec![agent(exempt_for_the_task(1, GUARD))]), both);

    // Below that, the guard of the one above it: not.
    let helper = |body| at(the_helper(), 0, body);
    assert_eq!(judged(vec![helper(exempt_for_the_task(2, OTHER))]), both);

    // The root: both.
    assert_eq!(
        judged(vec![
            user(exempt_for_the_task(1, GUARD)),
            user(exempt_for_the_task(2, OTHER))
        ]),
        Verdict::Allow
    );
}

/// FR34, FR55, FR45: an exemption whose time to end by the clock has passed when it is claimed
/// (an act at or after it came before) adds nothing: its transaction is aborted as expired, with
/// no finding, and nothing is exempted.
#[test]
fn an_exemption_claimed_after_its_end_by_adds_nothing() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let start = at(the_agent(), 200, Body::TaskStart);
    let late = at(
        the_user(),
        200,
        exempt_n_by(1, GUARD, None, Lifetime::Timed, At::from_millis(100)),
    );
    let report = catalog.admit(
        &catalog.fold(Origin::Genesis, [&start]),
        &late,
        &TxPolicy::standard(),
    );
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(report.inadmissible, Some(Inadmissible::Expired));
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(
        catalog.fold(Origin::Genesis, [&start, &late]),
        catalog.fold(Origin::Genesis, [&start])
    );
}

/// FR14, UC10: no exemption covers a Meta guard.
#[test]
fn no_exemption_covers_a_meta_guard() {
    let mut guard = test_guard(Level::Force);
    guard.layer = DefLayer::Meta;
    let catalog = catalog(vec![guard], vec![]);
    let exempt = user(exempt_n(
        1,
        GUARD,
        None,
        Lifetime::Within(Scope::Span {
            span: Span::Session,
            by: By::Anyone,
        }),
    ));
    let start = agent(Body::TaskStart);
    let report = catalog.admit(
        &catalog.fold(Origin::Genesis, [&start]),
        &exempt,
        &TxPolicy::standard(),
    );
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(report.inadmissible, Some(Inadmissible::Meta(id(GUARD))));
    assert!(matches!(
        verdict(&catalog, &[start, exempt, agent(Body::Stop)]),
        Verdict::Deny(_)
    ));
}
