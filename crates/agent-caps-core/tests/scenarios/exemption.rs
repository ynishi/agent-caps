//! Scenario S3: a user's exemption covers its target for its lifetime, never a meta guard, and
//! an exemption that comes from the agent covers nothing.

use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::exempt::{Exempt, Lifetime};
use agent_caps_core::domain::judge::{Verdict, judge};
use agent_caps_core::domain::policy::{DefLayer, Level};
use agent_caps_core::domain::predicate::{Cond, Lit, Scope};
use agent_caps_core::domain::schema::{At, Field, Origin, Source};

use super::common::{
    GUARD, agent, at, catalog, edit, id, src_edit_guard, test_guard, unreadable, user, verdict,
};

/// FR9, UC6: an exemption from the user covers its target for its lifetime. UC4: one from the
/// agent is nothing.
#[test]
fn a_users_exemption_covers_its_target_for_its_lifetime() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let exempt = |lifetime| {
        Body::Exempt(Exempt {
            guard: id(GUARD),
            target: Some(Cond::Eq(Field::Path, Lit::Text("src/a.rs".to_owned()))),
            lifetime,
            reason: "generated file".parse().unwrap(),
        })
    };
    let start = agent(Body::TaskStart);

    // From the agent, an exemption is nothing.
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

    // From the user, it covers its target, not another path.
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
    let state = catalog.fold(&next);
    let outcome = judge(&catalog, &state, &next[2]);
    let mut events = next.to_vec();
    events.extend(outcome.evidence(At::from_millis(1)));
    events.push(edit("src/a.rs"));
    assert!(matches!(verdict(&catalog, &events), Verdict::Deny(_)));

    // `Within(Task)` lasts until the task starts again.
    let within = user(exempt(Lifetime::Within(Scope::Task)));
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

    // `Until` is compared with the time of the judged event.
    let until = at(
        Origin::User,
        0,
        exempt(Lifetime::Until(At::from_millis(100))),
    );
    let edit_at = |millis| at(Origin::Agent, millis, edit("src/a.rs").body);
    assert_eq!(
        verdict(&catalog, &[start.clone(), until.clone(), edit_at(99)]),
        Verdict::Allow
    );
    assert!(matches!(
        verdict(&catalog, &[start.clone(), until, edit_at(100)]),
        Verdict::Deny(_)
    ));

    // A lost record of the evidence may have used the exemption up: it ends.
    assert!(matches!(
        verdict(
            &catalog,
            &[
                start,
                user(exempt(Lifetime::Within(Scope::Session))),
                unreadable(Source::Evidence),
                edit("src/a.rs")
            ]
        ),
        Verdict::Deny(_)
    ));
}

/// UC4, FR9: an exemption that comes from the agent is nothing, whatever it asks for: its
/// lifetime, or no target at all. A user's exemption next to it still works.
#[test]
fn an_exemption_from_the_agent_covers_nothing_whatever_its_lifetime() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let exempt = |target, lifetime| {
        Body::Exempt(Exempt {
            guard: id(GUARD),
            target,
            lifetime,
            reason: "i said so".parse().unwrap(),
        })
    };
    let start = agent(Body::TaskStart);
    let lifetimes = [
        Lifetime::Next,
        Lifetime::Within(Scope::Task),
        Lifetime::Within(Scope::Session),
        Lifetime::Until(At::from_millis(1_000)),
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
                "{lifetime:?} from the agent, target {target:?}"
            );
        }
    }

    // The same exemption from the user, next to the agent's, covers the edit.
    assert_eq!(
        verdict(
            &catalog,
            &[
                start,
                agent(exempt(None, Lifetime::Within(Scope::Task))),
                user(exempt(None, Lifetime::Within(Scope::Task))),
                edit("src/a.rs")
            ]
        ),
        Verdict::Allow
    );
}

/// FR14, UC10: no exemption covers a Meta guard.
#[test]
fn no_exemption_covers_a_meta_guard() {
    let mut guard = test_guard(Level::Force);
    guard.layer = DefLayer::Meta;
    let catalog = catalog(vec![guard], vec![]);
    let exempt = user(Body::Exempt(Exempt {
        guard: id(GUARD),
        target: None,
        lifetime: Lifetime::Within(Scope::Session),
        reason: "please".parse().unwrap(),
    }));
    assert!(matches!(
        verdict(
            &catalog,
            &[agent(Body::TaskStart), exempt, agent(Body::Stop)]
        ),
        Verdict::Deny(_)
    ));
}
