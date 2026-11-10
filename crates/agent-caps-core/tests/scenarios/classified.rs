//! A rule that code cannot express, judged by a classifier (UC23): the commit message explains
//! why the change was made.
//!
//! The classifier's answer comes in as a recorded claim, `Classified`, which an ordinary rule
//! reads with `Last`: the last answer of `commit-why@3` since the previous commit is at least 0.5.
//! The answer is a record a rule reads, so it counts only from one who covers the rule's author
//! (FR41): the adapter runs the classifier as the user, and an answer the agent writes counts
//! neither way. The classifier is declared in the policy graph, with the bound its calibration
//! must meet and the last record of it (FR52); the guard that reads it takes effect at Force only
//! while the record meets the bound, and is otherwise Advise and reported (FR26).
//!
//! The fixtures of such a rule carry `Classified` events, folded as a run folds them, so they are
//! written by one who covers the guard's author; an answer by another would be aborted, and the
//! fixture would fail.

use agent_caps_core::domain::authority::Principal;
use agent_caps_core::domain::catalog::{AcceptError, Catalog, Degraded, Effect, Rejected, Target};
use agent_caps_core::domain::change::{ChangeRejected, Loosening};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::name::ClassifierName;
use agent_caps_core::domain::policy::{
    Calibration, CalibrationError, CalibrationRecord, Clash, Classifier, DefLayer, Expect, Level,
    Polarity, PolicyDef, PolicyGraph, Rule, Shortfall,
};
use agent_caps_core::domain::predicate::{Cmp, Cond, EventFilter, Lit, Number, Pred, Scope};
use agent_caps_core::domain::schema::{EventKind, Field};
use agent_caps_core::domain::set::{Source, Sources};
use agent_caps_core::domain::state::Known;
use agent_caps_core::domain::tx::{TxDecision, TxPolicy};

use super::common::{
    GUARD, Written, anyone, at, authority, base_of, bash, commit_filter, fixture, id, listed,
    outcome, set, set_pair, the_agent, the_user, verdict, violated, words, written,
};

/// The classifier of the commit message, by name and version.
fn why() -> ClassifierName {
    "commit-why@3".parse().unwrap()
}

/// What the declaration asks of its calibration: at least 50 cases and at most 2 false stops.
fn bound() -> Calibration {
    Calibration::new(50, 2).unwrap()
}

/// A record that meets the bound, at its edge on the false stops.
fn enough() -> CalibrationRecord {
    CalibrationRecord::new(60, 2).unwrap()
}

/// The declaration of `commit-why@3` by `author`, with the last record of its calibration.
fn declared(author: Principal, record: Option<CalibrationRecord>) -> Classifier {
    Classifier {
        name: why(),
        author,
        bound: bound(),
        record,
    }
}

/// An answer of `commit-why@3`, written by `by`.
fn answer_by(by: Principal, value: f64) -> Event {
    at(
        by,
        0,
        Body::Classified {
            classifier: why(),
            answer: value,
        },
    )
}

/// An answer the adapter recorded, running the classifier as the user.
fn answer(value: f64) -> Event {
    answer_by(the_user(), value)
}

fn commit() -> Event {
    bash("git commit -m x", None)
}

/// The answers of `commit-why@3`.
fn answers() -> EventFilter {
    EventFilter {
        kind: EventKind::Classified,
        cond: Some(Cond::Eq(Field::Classifier, Lit::Text(why().to_string()))),
    }
}

/// The last answer of `filter` since the previous commit is at least 0.5.
fn explained_by(filter: EventFilter) -> Pred {
    Pred::Last {
        select: anyone(filter),
        scope: Scope::Since(anyone(commit_filter(false))),
        test: Cond::Num(Field::Answer, Cmp::Ge, Number::new(0.5).unwrap()),
    }
}

/// The guard on a commit: the message has to be explained, as `commit-why@3` judges it. Its author
/// binds it at `level`. The answers in its fixtures are the user's, who covers the guard's author.
fn why_guard(level: Level) -> Written {
    written(
        PolicyDef {
            id: id(GUARD),
            name: "commit-why".parse().unwrap(),
            layer: DefLayer::Base,
            subject: EventKind::ToolUse,
            when: Some(Pred::Now(Cond::Words(Field::Command, words("git commit")))),
            rule: Rule::Structural(explained_by(answers())),
            polarity: Polarity::Guard,
            fixtures: vec![
                fixture("no answer", vec![commit()], Expect::Violated),
                fixture(
                    "a low answer",
                    vec![answer(0.2), commit()],
                    Expect::Violated,
                ),
                fixture(
                    "a high answer",
                    vec![answer(0.9), commit()],
                    Expect::Satisfied,
                ),
                fixture(
                    "the answer was for the commit before",
                    vec![answer(0.9), commit(), commit()],
                    Expect::Violated,
                ),
            ],
            author: the_user(),
        },
        level,
    )
}

/// The graph of the policies, each with its base binding, and the classifiers.
fn graph(policies: Vec<Written>, classifiers: Vec<Classifier>) -> PolicyGraph {
    let bindings = policies.iter().filter_map(base_of).collect();
    let defs = policies.into_iter().map(|w| w.def).collect();
    PolicyGraph::parse_with(defs, bindings, classifiers).unwrap()
}

/// The user's set named `name`.
fn users(name: &str, policies: Vec<Written>, classifiers: Vec<Classifier>) -> Source {
    set(name, the_user(), graph(policies, classifiers))
}

fn accept(sets: Vec<Source>) -> Result<Catalog, Rejected> {
    Catalog::accept(Sources::new(sets).unwrap(), authority())
}

/// The catalog of the user's guard at `level` and the user's declaration with `record`, in one set.
fn catalog_with(level: Level, record: Option<CalibrationRecord>) -> Catalog {
    accept(vec![users(
        "user",
        vec![why_guard(level)],
        vec![declared(the_user(), record)],
    )])
    .unwrap()
}

fn warned() -> Verdict {
    Verdict::Warn(vec![Cause::Violated(id(GUARD))])
}

/// What the guard comes to under no mode.
fn guard_effect(catalog: &Catalog) -> Effect {
    listed(catalog, Known::Known(None))
        .into_iter()
        .find(|(policy, _)| *policy == id(GUARD))
        .unwrap()
        .1
}

fn uncalibrated(shortfall: Shortfall) -> Degraded {
    Degraded::Uncalibrated {
        guard: id(GUARD),
        classifier: why(),
        shortfall,
        to: Level::Advise,
    }
}

fn loosenings(result: Result<Catalog, ChangeRejected>) -> Vec<Loosening> {
    match result.unwrap_err() {
        ChangeRejected::Loosens(loosenings) => loosenings,
        other => panic!("rejected, but not for loosening: {other:?}"),
    }
}

/// UC23, FR26: the rule reads the last answer since the previous commit. A high answer lets the
/// commit through and a low one stops it; the answer of the commit before does not count for the
/// next one.
#[test]
fn a_high_answer_passes_and_a_low_one_stops() {
    let catalog = catalog_with(Level::Force, Some(enough()));
    assert_eq!(guard_effect(&catalog), Effect::On(Level::Force));
    assert_eq!(verdict(&catalog, &[answer(0.9), commit()]), Verdict::Allow);
    assert_eq!(verdict(&catalog, &[answer(0.5), commit()]), Verdict::Allow);
    assert_eq!(verdict(&catalog, &[answer(0.2), commit()]), violated());
    assert_eq!(
        verdict(&catalog, &[answer(0.2), answer(0.9), commit()]),
        Verdict::Allow
    );
    assert_eq!(
        verdict(&catalog, &[answer(0.9), commit(), commit()]),
        violated()
    );
}

/// UC23, FR26: with no answer the rule is not satisfied, so the guard stops at Force and warns at
/// Advise: not having an answer never lets a commit through.
#[test]
fn no_answer_stops_at_force_and_warns_at_advise() {
    let force = catalog_with(Level::Force, Some(enough()));
    assert_eq!(verdict(&force, &[commit()]), violated());
    let advise = catalog_with(Level::Advise, Some(enough()));
    assert_eq!(verdict(&advise, &[commit()]), warned());
}

/// UC23, FR26: an answer the agent writes is not counted, high or low. The agent does not cover
/// the guard's author, so the claim is aborted and the rule reads what it read before.
#[test]
fn an_answer_the_agent_writes_is_not_counted() {
    let catalog = catalog_with(Level::Force, Some(enough()));
    let forged = answer_by(the_agent(), 0.9);
    assert_eq!(verdict(&catalog, &[forged.clone(), commit()]), violated());
    let report = catalog.admit(&catalog.start(), &forged, &TxPolicy::standard());
    assert_eq!(report.decision, TxDecision::Abort);
    assert!(!report.uncovered.is_empty());
    // A low answer by the agent does not take away the user's high one either.
    let low = answer_by(the_agent(), 0.0);
    assert_eq!(
        verdict(&catalog, &[answer(0.9), low, commit()]),
        Verdict::Allow
    );
}

/// UC23, FR26: a guard bound at Force that reads a classifier with no calibration record is
/// enforced at Advise, and says so. The same answer comes out of the catalog and of the state, and
/// out of the judgment.
#[test]
fn without_a_record_the_force_guard_is_enforced_at_advise_and_reported() {
    let catalog = catalog_with(Level::Force, None);
    let expected = vec![uncalibrated(Shortfall::Missing)];
    assert_eq!(guard_effect(&catalog), Effect::On(Level::Advise));
    assert_eq!(catalog.effective(&Known::Known(None)).degraded, expected);
    assert_eq!(catalog.effective(&Known::Unknown).degraded, expected);
    assert_eq!(catalog.effective_in(&catalog.start()).degraded, expected);

    let out = outcome(&catalog, &[commit()]);
    assert_eq!(out.verdict, warned());
    assert_eq!(out.degraded, expected);
}

/// UC23, FR26: a record with too few cases, or too many false stops, falls short of the bound and
/// is reported with its counts.
#[test]
fn a_short_record_is_reported_with_its_counts() {
    for record in [
        CalibrationRecord::new(49, 0).unwrap(),
        CalibrationRecord::new(60, 3).unwrap(),
    ] {
        let catalog = catalog_with(Level::Force, Some(record));
        assert_eq!(guard_effect(&catalog), Effect::On(Level::Advise));
        assert_eq!(
            catalog.effective(&Known::Known(None)).degraded,
            vec![uncalibrated(Shortfall::Short {
                cases: record.cases(),
                false_stops: record.false_stops(),
            })]
        );
        assert_eq!(outcome(&catalog, &[commit()]).verdict, warned());
    }
}

/// FR26: a bound that asks for no case would admit a guard with no evidence, so it cannot be made
/// and the calibration cannot be emptied by a value; the edge, one case, is made.
#[test]
fn a_bound_without_cases_is_refused() {
    assert_eq!(Calibration::new(0, 0), Err(CalibrationError::NoCases));
    assert_eq!(Calibration::new(0, 5), Err(CalibrationError::NoCases));
    let one = Calibration::new(1, 0).unwrap();
    assert_eq!((one.min_cases(), one.max_false_stops()), (1, 0));
}

/// FR52: the parts of a graph give back every item, the classifiers too, so a graph made again from
/// them is the same graph.
#[test]
fn a_graph_made_again_from_its_parts_keeps_its_classifiers() {
    let graph = graph(
        vec![why_guard(Level::Force)],
        vec![declared(the_user(), Some(enough()))],
    );
    let (policies, bindings, classifiers) = graph.clone().into_parts();
    assert_eq!(classifiers.len(), 1);
    assert_eq!(
        PolicyGraph::parse_with(policies, bindings, classifiers).unwrap(),
        graph
    );
}

/// FR26: a record with more false stops than cases cannot be, so it cannot be made; the edge, every
/// case a false stop, is made.
#[test]
fn a_record_with_more_false_stops_than_cases_is_refused() {
    assert_eq!(
        CalibrationRecord::new(10, 11),
        Err(CalibrationError::FalseStopsExceedCases {
            cases: 10,
            false_stops: 11,
        })
    );
    assert_eq!(
        CalibrationRecord::new(0, 1),
        Err(CalibrationError::FalseStopsExceedCases {
            cases: 0,
            false_stops: 1,
        })
    );
    let all_wrong = CalibrationRecord::new(10, 10).unwrap();
    assert_eq!((all_wrong.cases(), all_wrong.false_stops()), (10, 10));
}

/// UC23, FR26: with a record that meets the bound, at its edge, the guard is Force and nothing is
/// degraded.
#[test]
fn a_sufficient_record_leaves_the_guard_at_force() {
    let catalog = catalog_with(Level::Force, Some(enough()));
    assert_eq!(guard_effect(&catalog), Effect::On(Level::Force));
    assert!(catalog.effective(&Known::Known(None)).degraded.is_empty());
    assert!(catalog.effective_in(&catalog.start()).degraded.is_empty());
    assert_eq!(outcome(&catalog, &[commit()]).verdict, violated());
}

/// FR26, FR52: the record changes only by a permanent change from one who covers the author of the
/// declaration. The agent cannot make the record sufficient, nor take it away; the user can.
#[test]
fn changing_the_record_needs_one_who_covers_the_declarations_author() {
    let with_record = |catalog: &Catalog, record| {
        let source = users(
            "user",
            vec![why_guard(Level::Force)],
            vec![declared(the_user(), record)],
        );
        catalog.sources().replaced(source).unwrap()
    };
    let declaration = Loosening::Uncovered {
        target: Target::Classifier(why()),
    };

    let before = catalog_with(Level::Force, None);
    let raised = with_record(&before, Some(enough()));
    let found = loosenings(before.change(raised.clone(), &the_agent()));
    assert!(found.contains(&declaration));
    let next = before.change(raised, &the_user()).unwrap();
    assert_eq!(guard_effect(&next), Effect::On(Level::Force));

    // Taking the record away loosens the guard too, and the agent cannot do that either.
    let lowered = with_record(&next, None);
    let found = loosenings(next.change(lowered.clone(), &the_agent()));
    assert!(found.contains(&declaration));
    assert!(
        found
            .iter()
            .any(|loosening| matches!(loosening, Loosening::Moves { .. }))
    );
    let back = next.change(lowered, &the_user()).unwrap();
    assert_eq!(guard_effect(&back), Effect::On(Level::Advise));
}

/// FR52, FR26: a policy reads the declaration of its own author or of one above, and not one below:
/// the agent could otherwise set the bound a Force guard of the user is held to.
#[test]
fn a_policy_cannot_read_a_classifier_declared_by_one_below() {
    let by_agent = || set_for_agent(vec![], vec![declared(the_agent(), Some(enough()))]);
    let errors = accept(vec![
        users("user", vec![why_guard(Level::Force)], vec![]),
        by_agent(),
    ])
    .unwrap_err()
    .0;
    assert_eq!(
        errors,
        vec![AcceptError::ReferencesBelow {
            item: Target::Policy(id(GUARD)),
            referenced: Target::Classifier(why()),
        }]
    );

    // The other way round it is accepted: the agent's guard reads the user's declaration.
    let mut agents = why_guard(Level::Force);
    agents.author = the_agent();
    accept(vec![
        users("user", vec![], vec![declared(the_user(), Some(enough()))]),
        set_for_agent(vec![agents], vec![]),
    ])
    .unwrap();
}

/// The agent's own set.
fn set_for_agent(policies: Vec<Written>, classifiers: Vec<Classifier>) -> Source {
    set("agent", the_agent(), graph(policies, classifiers))
}

/// FR52, FR26: a Meta policy is lowered by nothing, and a guard that reads a classifier is lowered
/// while the classifier is not calibrated, so a Meta policy cannot read one.
#[test]
fn a_meta_policy_cannot_read_a_classifier() {
    let mut meta = why_guard(Level::Force);
    meta.layer = DefLayer::Meta;
    let errors = accept(vec![users(
        "user",
        vec![meta],
        vec![declared(the_user(), Some(enough()))],
    )])
    .unwrap_err()
    .0;
    assert_eq!(
        errors,
        vec![AcceptError::MetaReadsClassifier {
            policy: id(GUARD),
            classifier: why(),
        }]
    );
}

/// FR52: a filter of `Classified` events has to narrow to one classifier by its name, and the name
/// has to be declared.
#[test]
fn an_unnamed_or_undeclared_classifier_is_refused() {
    let reading = |cond: Option<Cond>| {
        let mut guard = why_guard(Level::Advise);
        guard.fixtures = vec![];
        guard.rule = Rule::Structural(explained_by(EventFilter {
            kind: EventKind::Classified,
            cond,
        }));
        accept(vec![users(
            "user",
            vec![guard],
            vec![declared(the_user(), Some(enough()))],
        )])
    };
    let name = |text: &str| Cond::Eq(Field::Classifier, Lit::Text(text.to_owned()));
    let answer_ok = Cond::Num(Field::Answer, Cmp::Ge, Number::new(0.1).unwrap());
    let unnamed = vec![AcceptError::UnnamedClassifier { policy: id(GUARD) }];
    for cond in [
        None,
        Some(answer_ok.clone()),
        Some(name("not a name")),
        Some(Cond::All(vec![name("commit-why@3"), name("commit-why@4")])),
        Some(Cond::Not(Box::new(name("commit-why@3")))),
    ] {
        assert_eq!(reading(cond.clone()).unwrap_err().0, unnamed, "{cond:?}");
    }
    assert_eq!(
        reading(Some(name("commit-why@4"))).unwrap_err().0,
        vec![AcceptError::UndeclaredClassifier {
            policy: id(GUARD),
            classifier: "commit-why@4".parse().unwrap(),
        }]
    );
    // A condition on the answer beside the name narrows nothing further, and is accepted.
    reading(Some(Cond::All(vec![name("commit-why@3"), answer_ok]))).unwrap();
}

/// FR52, FR48: two sets that declare the same classifier the same hold one declaration; two that
/// declare it differently (here, by the last record) conflict, whichever set comes first.
#[test]
fn declarations_with_different_content_clash_on_composition() {
    let declare = |name: &str, record| users(name, vec![], vec![declared(the_user(), record)]);
    let same = Sources::new(vec![declare("a", None), declare("b", None)]).unwrap();
    assert_eq!(same.compose().unwrap().classifiers().count(), 1);

    let different = Sources::new(vec![declare("a", None), declare("b", Some(enough()))]).unwrap();
    let conflicts = different.compose().unwrap_err();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].clash(), &Clash::Classifier(why()));
    assert_eq!(conflicts[0].sets(), &set_pair("a", "b"));

    // The catalog refuses the sets for it.
    let errors = Catalog::accept(different, authority()).unwrap_err().0;
    assert!(matches!(errors.as_slice(), [AcceptError::Conflict(_)]));
}

/// A guard that judges the answers themselves: it applies to the answers of `when`'s classifier
/// and wants each at least 0.5. Its author binds it at `level`; the answers in its fixtures are the
/// user's, who covers the guard's author.
fn answer_guard(level: Level, when: Option<Pred>) -> Written {
    written(
        PolicyDef {
            id: id(GUARD),
            name: "answer-high".parse().unwrap(),
            layer: DefLayer::Base,
            subject: EventKind::Classified,
            when,
            rule: Rule::Structural(Pred::Now(Cond::Num(
                Field::Answer,
                Cmp::Ge,
                Number::new(0.5).unwrap(),
            ))),
            polarity: Polarity::Guard,
            fixtures: vec![
                fixture("a low answer", vec![answer(0.2)], Expect::Violated),
                fixture("a high answer", vec![answer(0.9)], Expect::Satisfied),
            ],
            author: the_user(),
        },
        level,
    )
}

/// FR52, FR26: a policy that judges `Classified` events reads the classifier its `when` narrows
/// to, as a filter does, so a `when` that narrows to none is refused, as is a name no set declares.
#[test]
fn a_policy_that_judges_answers_must_narrow_to_a_classifier() {
    let narrows = || Pred::Now(Cond::Eq(Field::Classifier, Lit::Text(why().to_string())));
    let refused = |when: Option<Pred>, classifiers| {
        let mut guard = answer_guard(Level::Advise, when);
        guard.fixtures = vec![];
        accept(vec![users("user", vec![guard], classifiers)])
            .unwrap_err()
            .0
    };
    let declared_why = || vec![declared(the_user(), Some(enough()))];
    let unnamed = vec![AcceptError::UnnamedClassifier { policy: id(GUARD) }];
    for when in [
        None,
        Some(Pred::Now(Cond::Num(
            Field::Answer,
            Cmp::Ge,
            Number::new(0.1).unwrap(),
        ))),
        Some(Pred::Any(vec![narrows()])),
    ] {
        assert_eq!(refused(when.clone(), declared_why()), unnamed, "{when:?}");
    }
    assert_eq!(
        refused(Some(narrows()), vec![]),
        vec![AcceptError::UndeclaredClassifier {
            policy: id(GUARD),
            classifier: why(),
        }]
    );
    // Narrowed, alone or beside another predicate, it is accepted.
    for when in [
        narrows(),
        Pred::All(vec![
            narrows(),
            Pred::Now(Cond::Num(Field::Answer, Cmp::Ge, Number::new(0.1).unwrap())),
        ]),
    ] {
        let guard = answer_guard(Level::Advise, Some(when));
        accept(vec![users("user", vec![guard], declared_why())]).unwrap();
    }
}

/// FR26, FR52: such a policy bound at Force, with no calibration record for the classifier its
/// `when` narrows to, is enforced at Advise and reported, as a guard that reads the classifier
/// with a filter is; with a sufficient record it is Force.
#[test]
fn a_policy_that_judges_answers_is_lowered_while_its_classifier_is_uncalibrated() {
    let when = Pred::Now(Cond::Eq(Field::Classifier, Lit::Text(why().to_string())));
    let catalog_with = |record| {
        accept(vec![users(
            "user",
            vec![answer_guard(Level::Force, Some(when.clone()))],
            vec![declared(the_user(), record)],
        )])
        .unwrap()
    };
    let catalog = catalog_with(None);
    assert_eq!(guard_effect(&catalog), Effect::On(Level::Advise));
    assert_eq!(
        catalog.effective(&Known::Known(None)).degraded,
        vec![uncalibrated(Shortfall::Missing)]
    );
    assert_eq!(
        catalog.effective_in(&catalog.start()).degraded,
        vec![uncalibrated(Shortfall::Missing)]
    );

    let calibrated = catalog_with(Some(enough()));
    assert_eq!(guard_effect(&calibrated), Effect::On(Level::Force));
    assert!(
        calibrated
            .effective(&Known::Known(None))
            .degraded
            .is_empty()
    );
}
