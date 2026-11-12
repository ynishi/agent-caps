//! A record whose kind could not be read has no kind a rule may name, and no judgment is given
//! one: it is only folded. The type of an event that is judged (`Judgeable`) refuses it, and the
//! catalog refuses a rule that names its kind as a subject, in a filter or in the capabilities.
//! What a lost record does to the rules that read the history is in `unreadable`; that it is not
//! judged ahead by the application is in the application's scenarios.

use agent_caps_core::domain::adjust::{Inadmissible, Lifetime};
use agent_caps_core::domain::catalog::{AcceptError, Capabilities};
use agent_caps_core::domain::event::{Body, Event, Judgeable, NoKind};
use agent_caps_core::domain::policy::{Expect, Level, Rule};
use agent_caps_core::domain::predicate::{
    By, Cmp, Cond, EventFilter, Lit, Pred, PredError, Scope, Span,
};
use agent_caps_core::domain::schema::{EventKind, Field};
use agent_caps_core::domain::state::Origin;
use agent_caps_core::domain::tx::TxPolicy;

use super::common::{
    GUARD, agent, anyone, bash, catalog, edit, exemption, fixture, id, lost_line, rejected,
    src_edit_guard, test_guard, tested_in, verdict, violated,
};

/// The filter of the kind of a record that could not be read.
fn of_lost_records() -> EventFilter {
    EventFilter {
        kind: EventKind::Unreadable,
        cond: None,
    }
}

/// FR71: an event is judged only when its kind is known. A record whose kind could not be read is
/// refused, and given back as it was given; an event of any other kind is taken, and read as the
/// event it is.
#[test]
fn a_record_of_no_kind_is_no_judgeable_event() {
    let lost = lost_line();
    assert_eq!(Judgeable::try_from(lost.clone()), Err(NoKind(lost.clone())));
    let events: Vec<Event> = vec![
        agent(Body::SessionStart),
        agent(Body::TaskStart),
        agent(Body::PromptSubmit),
        agent(Body::Stop),
        bash("cargo test", Some(true)),
        edit("src/a.rs"),
    ];
    for event in events {
        let judgeable = Judgeable::try_from(event.clone()).unwrap();
        assert_eq!(judgeable.event(), &event);
    }
}

/// FR71: a policy whose subject is the kind of a record that could not be read is refused: such a
/// record is judged by no policy, so the policy would never judge anything.
#[test]
fn a_policy_cannot_have_a_lost_record_as_its_subject() {
    let mut guard = test_guard(Level::Advise);
    guard.subject = EventKind::Unreadable;
    guard.fixtures = vec![];
    assert_eq!(
        rejected(vec![guard], vec![]),
        vec![AcceptError::SubjectNotNameable { policy: id(GUARD) }]
    );
}

/// FR71: a selector over the history, and the filter of a `Since` scope, cannot name the kind of a
/// record that could not be read: the fold only makes unknown what such a record may have been,
/// so a selector of it never chooses one, and a `Since` of it would start again on a record that
/// says nothing of what it was.
#[test]
fn a_filter_cannot_name_the_kind_of_a_lost_record() {
    let mut guard = test_guard(Level::Advise);
    guard.fixtures = vec![];
    guard.rule = Rule::Structural(Pred::All(vec![
        Pred::Once {
            select: anyone(of_lost_records()),
            scope: Scope::Span {
                span: Span::Task,
                by: By::Anyone,
            },
        },
        tested_in(Scope::Since(anyone(of_lost_records()))),
        Pred::Count {
            select: anyone(of_lost_records()),
            scope: Scope::Since(anyone(of_lost_records())),
            cmp: Cmp::Ge,
            n: 1,
        },
    ]));
    let error = AcceptError::Predicate {
        policy: id(GUARD),
        error: PredError::NotNameable(EventKind::Unreadable),
    };
    assert_eq!(rejected(vec![guard], vec![]), vec![error; 4]);
}

/// FR71: the capabilities of a platform cannot name the kind of a record that could not be read.
#[test]
fn the_capabilities_cannot_name_the_kind_of_a_lost_record() {
    let good = EventFilter {
        kind: EventKind::Stop,
        cond: None,
    };
    assert_eq!(
        Capabilities::new(
            vec![
                (good.clone(), Level::Force),
                (of_lost_records(), Level::Advise)
            ],
            Level::Force,
        )
        .unwrap_err(),
        vec![PredError::NotNameable(EventKind::Unreadable)]
    );
    assert!(Capabilities::new(vec![(good, Level::Advise)], Level::Force).is_ok());
}

/// FR71, FR2: a fixture judges its last event as any event is judged, so one that ends with a
/// record whose kind could not be read is refused, where it used to pass as not applicable.
#[test]
fn a_fixture_cannot_end_with_a_lost_record() {
    let mut guard = test_guard(Level::Advise);
    guard.fixtures = vec![fixture(
        "lost",
        vec![agent(Body::TaskStart), lost_line()],
        Expect::NotApplicable,
    )];
    assert_eq!(
        rejected(vec![guard], vec![]),
        vec![AcceptError::FixtureNoKind {
            policy: id(GUARD),
            fixture: "lost".to_owned(),
        }]
    );
}

/// FR71, FR34: an exemption that lasts within a `Since` of the kind of a record that could not be
/// read does not take effect, as one with any other filter that does not type-check does not: it
/// is aborted with the error, and the guard it names still judges.
#[test]
fn an_exemption_lasting_since_a_lost_record_takes_no_effect() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let on_a = Cond::Eq(Field::Path, Lit::Text("src/a.rs".to_owned()));
    let since_lost = exemption(
        Some(on_a),
        Lifetime::Within(Scope::Since(anyone(of_lost_records()))),
    );
    assert_eq!(
        verdict(
            &catalog,
            &[agent(Body::TaskStart), since_lost.clone(), edit("src/a.rs")],
        ),
        violated()
    );
    let admitted = catalog
        .admit(
            &catalog.fold(Origin::Genesis, [&agent(Body::TaskStart)]),
            &since_lost,
            &TxPolicy::standard(),
        )
        .unwrap();
    assert_eq!(
        admitted.inadmissible,
        Some(Inadmissible::SinceFilterError(vec![
            PredError::NotNameable(EventKind::Unreadable)
        ]))
    );
}
