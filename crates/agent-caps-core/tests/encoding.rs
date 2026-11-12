//! The encoding of the records (FR68): `Sources`, `Authority` and the `Event`s behind a state,
//! and how a change loosens (FR66, `Loosening`), encoded behind the `serde` feature. It is a
//! tool for mapping the core's values, not the form a store keeps them in, so nothing here pins
//! a version of it.
//!
//! One sample holds every variant of every enum the encoding reaches, and everything else is
//! checked against it:
//!
//! - The sample is walked by matches with no wildcard, each setting a flag of a struct that
//!   has one field per variant, and the struct is taken apart with no `..` and every field
//!   asserted. A variant added to an enum stops the match compiling until it has an arm, the arm
//!   needs a field, and a field the sample does not reach fails the test.
//! - The sample decodes to what was encoded, a finite number to the bit, and a catalog accepted
//!   from the decoded sources has the graph of one accepted from the originals.
//! - Every value with a checking constructor is refused, with the constructor's own error, when
//!   it is decoded from a form the constructor would refuse, and a field no type has is refused.

use std::fmt::Debug;

use agent_caps_core::domain::adjust::{
    Adjustment, Lifetime, Temporary, TemporaryBinding, TemporaryBound,
};
use agent_caps_core::domain::authority::{Authority, Principal};
use agent_caps_core::domain::catalog::{Catalog, Target};
use agent_caps_core::domain::change::Loosening;
use agent_caps_core::domain::event::{Body, Event, Seen as FieldState};
use agent_caps_core::domain::name::{
    AdjustmentId, BindingId, ClassifierName, CommandWords, GlobPattern, Meter, Mode, PolicyId,
    PolicyName, Reason,
};
use agent_caps_core::domain::policy::{
    Binding, Calibration, CalibrationRecord, Classifier, DefLayer, Expect, Fixture, Level,
    ModeScope, ModeSet, Polarity, PolicyDef, PolicyGraph, Rule,
};
use agent_caps_core::domain::predicate::{
    Amount, By, Cmp, Cond, EventFilter, Lit, Number, Order, Pred, Scope, Selector, Span, Whose,
    Window,
};
use agent_caps_core::domain::schema::{At, EventKind, Field, Judgment, KindSet};
use agent_caps_core::domain::set::{SetId, SetName, Source, Sources};
use agent_caps_core::domain::state::{Lineage, SlotId};
use agent_caps_core::domain::tx::checks::RuleMove;
use agent_caps_core::domain::tx::{FindingDetail, Reader};
use serde::de::value::F64Deserializer;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------------------------
// The sample

/// What the sample holds: the records the encoding is for.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    sources: Sources,
    authority: Authority,
    events: Vec<Event>,
    loosenings: Vec<Loosening>,
}

fn principal(key: &str) -> Principal {
    Principal::new(key)
}

fn user() -> Principal {
    principal("user")
}

fn agent() -> Principal {
    principal("agent")
}

fn helper() -> Principal {
    principal("helper")
}

/// A hierarchy of two levels below the root: the user, the agent below it, the helper below that.
fn authority() -> Authority {
    Authority::new([
        (user(), None),
        (agent(), Some(user())),
        (helper(), Some(agent())),
    ])
    .unwrap()
}

fn id_text(n: u32) -> String {
    format!("00000000-0000-7000-8000-{n:012}")
}

fn policy_id(n: u32) -> PolicyId {
    id_text(n).parse().unwrap()
}

fn binding_id(n: u32) -> BindingId {
    format!("b0000000-0000-7000-8000-{n:012}").parse().unwrap()
}

fn adjustment_id(n: u32) -> AdjustmentId {
    format!("a0000000-0000-7000-8000-{n:012}").parse().unwrap()
}

fn set_id(n: u32) -> SetId {
    format!("5e700000-0000-7000-8000-{n:012}").parse().unwrap()
}

fn mode(name: &str) -> Mode {
    name.parse().unwrap()
}

fn words(text: &str) -> CommandWords {
    CommandWords::new(text.split_whitespace().map(str::to_owned).collect()).unwrap()
}

fn text(value: &str) -> Lit {
    Lit::Text(value.to_owned())
}

fn num(value: f64) -> Number {
    Number::new(value).unwrap()
}

fn amount(value: f64) -> Amount {
    Amount::new(value).unwrap()
}

fn selector(kind: EventKind, cond: Option<Cond>, by: By) -> Selector {
    Selector {
        filter: EventFilter { kind, cond },
        by,
    }
}

fn anyone(kind: EventKind, cond: Option<Cond>) -> Selector {
    selector(kind, cond, By::Anyone)
}

fn event(by: &Principal, millis: i64, body: Body) -> Event {
    Event {
        at: At::from_millis(millis),
        by: by.clone(),
        body,
    }
}

/// A tool use whose command and path are each there or absent (`None`).
fn tool_use(command: Option<&str>, path: Option<&str>, ok: Option<bool>) -> Body {
    Body::ToolUse {
        tool: "Bash".to_owned(),
        command: command.map_or(FieldState::Absent, |text| FieldState::Value(words(text))),
        path: path.map_or(FieldState::Absent, |text| {
            FieldState::Value(text.to_owned())
        }),
        ok,
    }
}

fn fixture(name: &str, events: Vec<Event>, expect: Expect, known_gap: bool) -> Fixture {
    Fixture {
        name: name.to_owned(),
        events,
        expect,
        known_gap,
    }
}

fn binding(n: u32, policy: u32, level: Level, mode: ModeScope, author: Principal) -> Binding {
    Binding {
        id: binding_id(n),
        policy: policy_id(policy),
        level,
        mode,
        author,
    }
}

/// A guard that stops the end of a turn when `cargo test` has not passed within the task.
fn test_guard() -> PolicyDef {
    let tested = Pred::Once {
        select: anyone(
            EventKind::ToolUse,
            Some(Cond::All(vec![
                Cond::Words(Field::Command, words("cargo test")),
                Cond::Eq(Field::Ok, Lit::Bool(true)),
            ])),
        ),
        scope: Scope::Span {
            span: Span::Task,
            by: By::Anyone,
        },
    };
    let lost = Body::Unreadable {
        may_have_been: KindSet::any(),
    };
    PolicyDef {
        id: policy_id(1),
        name: "test-before-stop".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::Stop,
        when: None,
        rule: Rule::Structural(tested),
        polarity: Polarity::Guard,
        fixtures: vec![
            fixture(
                "untested",
                vec![
                    event(&agent(), 1, Body::TaskStart),
                    event(&agent(), 2, Body::Stop),
                ],
                Expect::Violated,
                false,
            ),
            fixture(
                "tested",
                vec![
                    event(&agent(), 1, Body::TaskStart),
                    event(&agent(), 2, tool_use(Some("cargo test"), None, Some(true))),
                    event(&agent(), 3, Body::Stop),
                ],
                Expect::Satisfied,
                false,
            ),
            fixture(
                "an edit is not judged",
                vec![
                    event(&agent(), 1, Body::TaskStart),
                    event(&agent(), 2, tool_use(None, Some("src/a.rs"), None)),
                ],
                Expect::NotApplicable,
                false,
            ),
            fixture(
                "after a lost line",
                vec![
                    event(&agent(), 1, Body::TaskStart),
                    event(&agent(), 2, lost),
                    event(&agent(), 3, Body::Stop),
                ],
                Expect::Unknown,
                false,
            ),
            fixture(
                "a gap kept to show",
                vec![
                    event(&agent(), 1, Body::TaskStart),
                    event(&agent(), 2, Body::Stop),
                ],
                Expect::Satisfied,
                true,
            ),
        ],
        author: user(),
    }
}

/// A guard on an edit that reads the mode, the actor, a count and a limit on the clock.
fn edit_guard() -> PolicyDef {
    let when = Pred::All(vec![
        Pred::Now(Cond::Glob(
            Field::Path,
            GlobPattern::new("src/**/*.rs").unwrap(),
        )),
        Pred::ModeIs(mode("bug-fix")),
        Pred::ActorUnder(agent()),
    ]);
    let edits = Pred::Count {
        select: anyone(
            EventKind::ToolUse,
            Some(Cond::In(Field::Tool, vec![text("Edit"), text("Write")])),
        ),
        scope: Scope::Span {
            span: Span::Session,
            by: By::Under(user()),
        },
        cmp: Cmp::Lt,
        n: 50,
    };
    PolicyDef {
        id: policy_id(2),
        name: "few-edits".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: Some(when),
        rule: Rule::Structural(Pred::Not(Box::new(Pred::Any(vec![Pred::Not(Box::new(
            edits,
        ))])))),
        polarity: Polarity::Guard,
        fixtures: vec![],
        author: user(),
    }
}

/// A guard that reads scores, answers, uses and judgments.
fn measure_guard() -> PolicyDef {
    let bench = Cond::All(vec![
        Cond::Eq(Field::Oracle, text("bench")),
        Cond::Not(Box::new(Cond::Num(Field::Score, Cmp::Lt, num(0.1)))),
        Cond::Any(vec![
            Cond::Num(Field::Score, Cmp::Le, num(1.0)),
            Cond::Num(Field::Score, Cmp::Eq, num(0.1 + 0.2)),
        ]),
    ]);
    let rule = Pred::All(vec![
        Pred::Last {
            select: selector(EventKind::Measured, Some(bench), By::Only(agent())),
            scope: Scope::Mode,
            test: Cond::Num(Field::Score, Cmp::Ge, num(0.8)),
        },
        Pred::Last {
            select: anyone(
                EventKind::Classified,
                Some(Cond::Eq(Field::Classifier, text("commit-why@3"))),
            ),
            scope: Scope::Since(selector(
                EventKind::ModeSwitch,
                Some(Cond::Eq(Field::ModeTo, text("bug-fix"))),
                By::Under(user()),
            )),
            test: Cond::Num(Field::Answer, Cmp::Gt, num(0.5)),
        },
        Pred::Spent {
            meter: "tokens".parse().unwrap(),
            by: Whose::Under(agent()),
            scope: Scope::Every(Window::from_millis(3_600_000).unwrap()),
            order: Order::Lt,
            n: amount(1_000_000.0),
        },
        Pred::Spent {
            meter: "cost-usd".parse().unwrap(),
            by: Whose::Anyone,
            scope: Scope::Span {
                span: Span::Turn,
                by: By::Only(user()),
            },
            order: Order::Le,
            n: amount(0.000_000_1),
        },
        Pred::Spent {
            meter: "tokens".parse().unwrap(),
            by: Whose::Anyone,
            scope: Scope::Mode,
            order: Order::Ge,
            n: amount(0.0),
        },
        Pred::Spent {
            meter: "tokens".parse().unwrap(),
            by: Whose::Anyone,
            scope: Scope::Mode,
            order: Order::Gt,
            n: amount(f64::MAX),
        },
        Pred::Count {
            select: anyone(
                EventKind::Used,
                Some(Cond::Eq(Field::Meter, text("tokens"))),
            ),
            scope: Scope::Span {
                span: Span::Task,
                by: By::Only(user()),
            },
            cmp: Cmp::Eq,
            n: 3,
        },
        Pred::Count {
            select: anyone(
                EventKind::Judged,
                Some(Cond::All(vec![
                    Cond::Eq(Field::Policy, text(&id_text(1))),
                    Cond::In(Field::Judgment, vec![text("denied"), text("warned")]),
                ])),
            ),
            scope: Scope::Mode,
            cmp: Cmp::Le,
            n: 2,
        },
        Pred::Count {
            select: anyone(EventKind::Cancel, None),
            scope: Scope::Mode,
            cmp: Cmp::Ge,
            n: 0,
        },
        Pred::Count {
            select: anyone(EventKind::Spawn, None),
            scope: Scope::Mode,
            cmp: Cmp::Gt,
            n: 0,
        },
    ]);
    PolicyDef {
        id: policy_id(3),
        name: "measured".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::Stop,
        when: Some(Pred::All(vec![])),
        rule: Rule::Structural(rule),
        polarity: Polarity::Guard,
        fixtures: vec![],
        author: user(),
    }
}

/// A meta policy: fixed, by a root.
fn meta_policy() -> PolicyDef {
    PolicyDef {
        id: policy_id(4),
        name: "fixed".parse().unwrap(),
        layer: DefLayer::Meta,
        subject: EventKind::Stop,
        when: None,
        rule: Rule::Structural(Pred::All(vec![])),
        polarity: Polarity::Guard,
        fixtures: vec![],
        author: user(),
    }
}

/// A reward the agent writes within the user's guard.
fn reward() -> PolicyDef {
    PolicyDef {
        id: policy_id(5),
        name: "clippy-before-stop".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::Stop,
        when: None,
        rule: Rule::Structural(Pred::Once {
            select: anyone(
                EventKind::ToolUse,
                Some(Cond::Words(Field::Command, words("cargo clippy"))),
            ),
            scope: Scope::Span {
                span: Span::Task,
                by: By::Anyone,
            },
        }),
        polarity: Polarity::Reward {
            bound_by: policy_id(1),
        },
        fixtures: vec![],
        author: agent(),
    }
}

/// Two sets: the user's, which declares the bound, and the agent's, which does not.
fn sources() -> Sources {
    let shared = PolicyGraph::parse_with(
        vec![test_guard(), edit_guard(), measure_guard(), meta_policy()],
        vec![
            binding(1, 1, Level::Force, ModeScope::Any, user()),
            binding(2, 2, Level::Advise, ModeScope::In(mode("bug-fix")), user()),
            binding(3, 3, Level::Inform, ModeScope::Any, user()),
            binding(4, 4, Level::Advise, ModeScope::Any, user()),
        ],
        vec![Classifier {
            name: "commit-why@3".parse().unwrap(),
            author: user(),
            bound: Calibration::new(20, 2).unwrap(),
            record: Some(CalibrationRecord::new(25, 1).unwrap()),
        }],
        Some(TemporaryBound::from_millis(30 * 86_400_000).unwrap()),
    )
    .unwrap();
    let project = PolicyGraph::parse_with(
        vec![reward()],
        vec![
            binding(5, 5, Level::Advise, ModeScope::Any, agent()),
            binding(
                6,
                3,
                Level::Inform,
                ModeScope::Outside(ModeSet::new(vec![mode("explore"), mode("modeling")]).unwrap()),
                agent(),
            ),
        ],
        vec![Classifier {
            name: "triage@1".parse().unwrap(),
            author: agent(),
            bound: Calibration::new(5, 0).unwrap(),
            record: None,
        }],
        None,
    )
    .unwrap();
    Sources::new(vec![
        Source {
            id: set_id(1),
            name: "shared".parse().unwrap(),
            owner: user(),
            graph: shared,
        },
        Source {
            id: set_id(2),
            name: "project".parse().unwrap(),
            owner: agent(),
            graph: project,
        },
    ])
    .unwrap()
}

/// The numbers a score may be: the ones a JSON number may not carry, and the ones it may carry
/// only if it is written and read exactly.
fn numbers() -> Vec<f64> {
    vec![
        0.1 + 0.2,
        f64::MAX,
        f64::MIN,
        f64::from_bits(1),
        -f64::from_bits(1),
        f64::MIN_POSITIVE,
        0.0,
        -0.0,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ]
}

/// Events with every variant of the body, in the name of the agent and of the user.
fn events() -> Vec<Event> {
    let (user, agent) = (user(), agent());
    let mut events = vec![
        event(&user, 0, Body::SessionStart),
        event(
            &agent,
            1,
            Body::Spawn {
                child: principal("worker-1"),
                under: helper(),
            },
        ),
        event(&agent, 2, Body::TaskStart),
        event(&user, 3, Body::PromptSubmit),
        event(
            &agent,
            4,
            tool_use(Some("cargo test -p a"), None, Some(true)),
        ),
        event(&agent, 5, tool_use(None, Some("src/a b.rs"), Some(false))),
        event(&agent, 6, tool_use(None, None, None)),
        // A command and a path that were there and could not be read.
        event(
            &agent,
            6,
            Body::ToolUse {
                tool: "Bash".to_owned(),
                command: FieldState::Unreadable,
                path: FieldState::Unreadable,
                ok: None,
            },
        ),
        event(&agent, 7, Body::Stop),
        event(
            &agent,
            8,
            Body::Used {
                meter: "tokens".parse().unwrap(),
                amount: Some(amount(0.1 + 0.2)),
            },
        ),
        event(
            &agent,
            9,
            Body::Used {
                meter: "cost-usd".parse().unwrap(),
                amount: None,
            },
        ),
        event(
            &user,
            10,
            Body::ModeSwitch {
                to: mode("bug-fix"),
            },
        ),
        event(
            &agent,
            11,
            Body::Cancel {
                id: adjustment_id(1),
            },
        ),
        event(
            &agent,
            12,
            Body::Unreadable {
                may_have_been: KindSet::any(),
            },
        ),
        event(
            &agent,
            13,
            Body::Unreadable {
                may_have_been: KindSet::new([EventKind::ToolUse, EventKind::Stop]),
            },
        ),
    ];
    for (at, score) in numbers().into_iter().enumerate() {
        let at = 100 + at as i64;
        events.push(event(
            &agent,
            at,
            Body::Measured {
                oracle: "bench".to_owned(),
                score,
            },
        ));
        events.push(event(
            &agent,
            at,
            Body::Classified {
                classifier: "commit-why@3".parse().unwrap(),
                answer: score,
            },
        ));
    }
    for (n, judgment) in [
        Judgment::Allowed,
        Judgment::Warned,
        Judgment::Denied,
        Judgment::Exempted,
        Judgment::Hit,
    ]
    .into_iter()
    .enumerate()
    {
        events.push(event(
            &user,
            200 + n as i64,
            Body::Judged {
                policy: policy_id(1),
                judgment,
                written: [Level::Inform, Level::Advise, Level::Force][n % 3],
                enforced: [Level::Force, Level::Advise, Level::Inform][n % 3],
            },
        ));
    }
    let reason: Reason = "docs only".parse().unwrap();
    let ends_by = At::from_millis(86_400_000);
    for (n, (change, lifetime)) in [
        (
            Temporary::Exempt {
                guard: policy_id(1),
                cover: Some(Cond::Glob(
                    Field::Path,
                    GlobPattern::new("docs/**").unwrap(),
                )),
            },
            Lifetime::Next,
        ),
        (
            Temporary::Exempt {
                guard: policy_id(1),
                cover: None,
            },
            Lifetime::Timed,
        ),
        (
            Temporary::Rebind {
                add: vec![TemporaryBinding {
                    policy: policy_id(2),
                    level: Level::Force,
                }],
                suspend: vec![binding_id(3)],
            },
            Lifetime::Within(Scope::Every(Window::from_millis(60_000).unwrap())),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        events.push(event(
            &user,
            300 + n as i64,
            Body::Adjust(Adjustment {
                id: adjustment_id(n as u32 + 1),
                change,
                lifetime,
                ends_by,
                reason: reason.clone(),
            }),
        ));
    }
    events
}

/// A slot's id, which has no constructor: it is read from its encoded form, its number.
fn slot(n: usize) -> SlotId {
    serde_json::from_str(&n.to_string()).unwrap()
}

/// The ways a change loosens, every variant of each enum on the way once or more: the items of a
/// catalog, the moves of a rule, the details of a finding and the readers a spawn loosens.
fn loosenings() -> Vec<Loosening> {
    let classifier: ClassifierName = "commit-why@3".parse().unwrap();
    let moves = vec![
        RuleMove::Lowered {
            policy: policy_id(1),
            authors: vec![user(), agent()],
        },
        RuleMove::Raised {
            policy: policy_id(2),
        },
        RuleMove::Exempted {
            policy: policy_id(1),
            authors: vec![user()],
        },
        RuleMove::Unexempted {
            policy: policy_id(2),
        },
        RuleMove::Suspended {
            policy: policy_id(3),
            binding: binding_id(1),
            authors: vec![],
        },
    ];
    let uncovered = |target| Loosening::Uncovered { target };
    vec![
        uncovered(Target::Policy(policy_id(1))),
        uncovered(Target::Binding(binding_id(1))),
        uncovered(Target::Classifier(classifier)),
        uncovered(Target::Set(set_id(1))),
        Loosening::Moves {
            mode: Some(mode("strict")),
            authors: vec![user(), agent()],
            detail: FindingDetail::Rules {
                moves,
                reading: vec![policy_id(4)],
            },
        },
        Loosening::Moves {
            mode: None,
            authors: vec![],
            detail: FindingDetail::Mode {
                reading: vec![policy_id(1), policy_id(2)],
            },
        },
        Loosening::Moves {
            mode: Some(mode("relaxed")),
            authors: vec![helper()],
            detail: FindingDetail::Slot {
                slot: slot(2),
                reading: vec![policy_id(3)],
            },
        },
        Loosening::Moves {
            mode: None,
            authors: vec![agent()],
            detail: FindingDetail::Spawn {
                child: principal("child"),
                under: helper(),
                loosened: vec![
                    Reader::Policy(policy_id(1)),
                    Reader::Adjustment(adjustment_id(1)),
                ],
            },
        },
        Loosening::Moves {
            mode: None,
            authors: vec![user()],
            detail: FindingDetail::Described("a check from outside".to_owned()),
        },
    ]
}

fn sample() -> Sample {
    Sample {
        sources: sources(),
        authority: authority(),
        events: events(),
        loosenings: loosenings(),
    }
}

// ---------------------------------------------------------------------------------------------
// What the sample reaches

/// A struct of one flag per variant of an enum (or per arm of an option), and the check that every
/// flag was set. The check takes the struct apart with no `..`.
macro_rules! seen {
    ($($name:ident { $($field:ident),+ $(,)? })+) => {
        $(
            #[derive(Default)]
            struct $name {
                $($field: bool),+
            }

            impl $name {
                fn assert_all(self) {
                    let Self { $($field),+ } = self;
                    $(
                        assert!(
                            $field,
                            "no value of the sample is {}::{}",
                            stringify!($name),
                            stringify!($field)
                        );
                    )+
                }
            }
        )+
    };
}

seen! {
    BodySeen {
        session_start, spawn, task_start, prompt_submit, tool_use, stop, used, mode_switch,
        measured, classified, adjust, cancel, judged, unreadable,
    }
    PredSeen { now, mode_is, actor_under, once, count, last, spent, all, any, not }
    CondSeen { eq, in_, glob, words, num, all, any, not }
    LitSeen { text, bool }
    CmpSeen { lt, le, eq, ge, gt }
    BySeen { anyone, under, only }
    WhoseSeen { anyone, under }
    SpanSeen { session, task, turn }
    ScopeSeen { span, mode, since, every }
    OrderSeen { lt, le, ge, gt }
    FieldSeen {
        tool, command, path, ok, mode_to, oracle, score, classifier, answer, policy, judgment,
        meter,
    }
    KindSeen {
        session_start, spawn, task_start, prompt_submit, tool_use, stop, used, mode_switch,
        measured, classified, adjust, cancel, judged, unreadable,
    }
    LifetimeSeen { next, within, timed }
    TemporarySeen { exempt, rebind }
    ModeScopeSeen { any, in_, outside }
    RuleSeen { structural }
    LevelSeen { inform, advise, force }
    JudgmentSeen { allowed, warned, denied, exempted, hit }
    PolaritySeen { guard, reward }
    DefLayerSeen { meta, base }
    ExpectSeen { violated, satisfied, not_applicable, unknown }
    LooseningSeen { uncovered, moves }
    TargetSeen { policy, binding, classifier, set }
    FindingDetailSeen { rules, mode, slot, spawn, described }
    RuleMoveSeen { lowered, raised, exempted, unexempted, suspended }
    ReaderSeen { policy, adjustment }
    OptionSeen {
        when_some, when_none, filter_cond_some, filter_cond_none, cover_some, cover_none,
        ok_some, ok_none, amount_some,
        amount_none, record_some, record_none, bound_some, bound_none, known_gap_true,
        known_gap_false, moves_mode_some, moves_mode_none,
    }
    FieldStateSeen {
        command_absent, command_value, command_unreadable, path_absent, path_value,
        path_unreadable,
    }
}

#[derive(Default)]
struct Seen {
    body: BodySeen,
    pred: PredSeen,
    cond: CondSeen,
    lit: LitSeen,
    cmp: CmpSeen,
    by: BySeen,
    whose: WhoseSeen,
    span: SpanSeen,
    scope: ScopeSeen,
    order: OrderSeen,
    field: FieldSeen,
    kind: KindSeen,
    lifetime: LifetimeSeen,
    temporary: TemporarySeen,
    mode_scope: ModeScopeSeen,
    rule: RuleSeen,
    level: LevelSeen,
    judgment: JudgmentSeen,
    polarity: PolaritySeen,
    def_layer: DefLayerSeen,
    expect: ExpectSeen,
    loosening: LooseningSeen,
    target: TargetSeen,
    finding_detail: FindingDetailSeen,
    rule_move: RuleMoveSeen,
    reader: ReaderSeen,
    option: OptionSeen,
    field_state: FieldStateSeen,
}

impl Seen {
    fn assert_all(self) {
        let Self {
            body,
            pred,
            cond,
            lit,
            cmp,
            by,
            whose,
            span,
            scope,
            order,
            field,
            kind,
            lifetime,
            temporary,
            mode_scope,
            rule,
            level,
            judgment,
            polarity,
            def_layer,
            expect,
            loosening,
            target,
            finding_detail,
            rule_move,
            reader,
            option,
            field_state,
        } = self;
        body.assert_all();
        pred.assert_all();
        cond.assert_all();
        lit.assert_all();
        cmp.assert_all();
        by.assert_all();
        whose.assert_all();
        span.assert_all();
        scope.assert_all();
        order.assert_all();
        field.assert_all();
        kind.assert_all();
        lifetime.assert_all();
        temporary.assert_all();
        mode_scope.assert_all();
        rule.assert_all();
        level.assert_all();
        judgment.assert_all();
        polarity.assert_all();
        def_layer.assert_all();
        expect.assert_all();
        loosening.assert_all();
        target.assert_all();
        finding_detail.assert_all();
        rule_move.assert_all();
        reader.assert_all();
        option.assert_all();
        field_state.assert_all();
    }
}

fn walk_level(seen: &mut Seen, level: Level) {
    match level {
        Level::Inform => seen.level.inform = true,
        Level::Advise => seen.level.advise = true,
        Level::Force => seen.level.force = true,
    }
}

fn walk_judgment(seen: &mut Seen, judgment: Judgment) {
    match judgment {
        Judgment::Allowed => seen.judgment.allowed = true,
        Judgment::Warned => seen.judgment.warned = true,
        Judgment::Denied => seen.judgment.denied = true,
        Judgment::Exempted => seen.judgment.exempted = true,
        Judgment::Hit => seen.judgment.hit = true,
    }
}

fn walk_kind(seen: &mut Seen, kind: EventKind) {
    let kinds = &mut seen.kind;
    match kind {
        EventKind::SessionStart => kinds.session_start = true,
        EventKind::Spawn => kinds.spawn = true,
        EventKind::TaskStart => kinds.task_start = true,
        EventKind::PromptSubmit => kinds.prompt_submit = true,
        EventKind::ToolUse => kinds.tool_use = true,
        EventKind::Stop => kinds.stop = true,
        EventKind::Used => kinds.used = true,
        EventKind::ModeSwitch => kinds.mode_switch = true,
        EventKind::Measured => kinds.measured = true,
        EventKind::Classified => kinds.classified = true,
        EventKind::Adjust => kinds.adjust = true,
        EventKind::Cancel => kinds.cancel = true,
        EventKind::Judged => kinds.judged = true,
        EventKind::Unreadable => kinds.unreadable = true,
    }
}

fn walk_field(seen: &mut Seen, field: Field) {
    let fields = &mut seen.field;
    match field {
        Field::Tool => fields.tool = true,
        Field::Command => fields.command = true,
        Field::Path => fields.path = true,
        Field::Ok => fields.ok = true,
        Field::ModeTo => fields.mode_to = true,
        Field::Oracle => fields.oracle = true,
        Field::Score => fields.score = true,
        Field::Classifier => fields.classifier = true,
        Field::Answer => fields.answer = true,
        Field::Policy => fields.policy = true,
        Field::Judgment => fields.judgment = true,
        Field::Meter => fields.meter = true,
    }
}

fn walk_lit(seen: &mut Seen, lit: &Lit) {
    match lit {
        Lit::Text(_) => seen.lit.text = true,
        Lit::Bool(_) => seen.lit.bool = true,
    }
}

fn walk_cmp(seen: &mut Seen, cmp: Cmp) {
    match cmp {
        Cmp::Lt => seen.cmp.lt = true,
        Cmp::Le => seen.cmp.le = true,
        Cmp::Eq => seen.cmp.eq = true,
        Cmp::Ge => seen.cmp.ge = true,
        Cmp::Gt => seen.cmp.gt = true,
    }
}

fn walk_order(seen: &mut Seen, order: Order) {
    match order {
        Order::Lt => seen.order.lt = true,
        Order::Le => seen.order.le = true,
        Order::Ge => seen.order.ge = true,
        Order::Gt => seen.order.gt = true,
    }
}

fn walk_by(seen: &mut Seen, by: &By) {
    match by {
        By::Anyone => seen.by.anyone = true,
        By::Under(_) => seen.by.under = true,
        By::Only(_) => seen.by.only = true,
    }
}

fn walk_whose(seen: &mut Seen, whose: &Whose) {
    match whose {
        Whose::Anyone => seen.whose.anyone = true,
        Whose::Under(_) => seen.whose.under = true,
    }
}

fn walk_span(seen: &mut Seen, span: Span) {
    match span {
        Span::Session => seen.span.session = true,
        Span::Task => seen.span.task = true,
        Span::Turn => seen.span.turn = true,
    }
}

fn walk_cond(seen: &mut Seen, cond: &Cond) {
    match cond {
        Cond::Eq(field, lit) => {
            seen.cond.eq = true;
            walk_field(seen, *field);
            walk_lit(seen, lit);
        }
        Cond::In(field, lits) => {
            seen.cond.in_ = true;
            walk_field(seen, *field);
            lits.iter().for_each(|lit| walk_lit(seen, lit));
        }
        Cond::Glob(field, _) => {
            seen.cond.glob = true;
            walk_field(seen, *field);
        }
        Cond::Words(field, _) => {
            seen.cond.words = true;
            walk_field(seen, *field);
        }
        Cond::Num(field, cmp, _) => {
            seen.cond.num = true;
            walk_field(seen, *field);
            walk_cmp(seen, *cmp);
        }
        Cond::All(conds) => {
            seen.cond.all = true;
            conds.iter().for_each(|cond| walk_cond(seen, cond));
        }
        Cond::Any(conds) => {
            seen.cond.any = true;
            conds.iter().for_each(|cond| walk_cond(seen, cond));
        }
        Cond::Not(cond) => {
            seen.cond.not = true;
            walk_cond(seen, cond);
        }
    }
}

fn walk_option_cond(
    seen: &mut Seen,
    cond: &Option<Cond>,
    some: fn(&mut OptionSeen),
    none: fn(&mut OptionSeen),
) {
    match cond {
        Some(cond) => {
            some(&mut seen.option);
            walk_cond(seen, cond);
        }
        None => none(&mut seen.option),
    }
}

fn walk_selector(seen: &mut Seen, selector: &Selector) {
    walk_kind(seen, selector.filter.kind);
    walk_option_cond(
        seen,
        &selector.filter.cond,
        |o| o.filter_cond_some = true,
        |o| o.filter_cond_none = true,
    );
    walk_by(seen, &selector.by);
}

fn walk_scope(seen: &mut Seen, scope: &Scope) {
    match scope {
        Scope::Span { span, by } => {
            seen.scope.span = true;
            walk_span(seen, *span);
            walk_by(seen, by);
        }
        Scope::Mode => seen.scope.mode = true,
        Scope::Since(selector) => {
            seen.scope.since = true;
            walk_selector(seen, selector);
        }
        Scope::Every(_) => seen.scope.every = true,
    }
}

fn walk_pred(seen: &mut Seen, pred: &Pred) {
    match pred {
        Pred::Now(cond) => {
            seen.pred.now = true;
            walk_cond(seen, cond);
        }
        Pred::ModeIs(_) => seen.pred.mode_is = true,
        Pred::ActorUnder(_) => seen.pred.actor_under = true,
        Pred::Once { select, scope } => {
            seen.pred.once = true;
            walk_selector(seen, select);
            walk_scope(seen, scope);
        }
        Pred::Count {
            select,
            scope,
            cmp,
            n: _,
        } => {
            seen.pred.count = true;
            walk_selector(seen, select);
            walk_scope(seen, scope);
            walk_cmp(seen, *cmp);
        }
        Pred::Last {
            select,
            scope,
            test,
        } => {
            seen.pred.last = true;
            walk_selector(seen, select);
            walk_scope(seen, scope);
            walk_cond(seen, test);
        }
        Pred::Spent {
            meter: _,
            by,
            scope,
            order,
            n: _,
        } => {
            seen.pred.spent = true;
            walk_whose(seen, by);
            walk_scope(seen, scope);
            walk_order(seen, *order);
        }
        Pred::All(preds) => {
            seen.pred.all = true;
            preds.iter().for_each(|pred| walk_pred(seen, pred));
        }
        Pred::Any(preds) => {
            seen.pred.any = true;
            preds.iter().for_each(|pred| walk_pred(seen, pred));
        }
        Pred::Not(pred) => {
            seen.pred.not = true;
            walk_pred(seen, pred);
        }
    }
}

fn walk_mode_scope(seen: &mut Seen, scope: &ModeScope) {
    match scope {
        ModeScope::Any => seen.mode_scope.any = true,
        ModeScope::In(_) => seen.mode_scope.in_ = true,
        ModeScope::Outside(_) => seen.mode_scope.outside = true,
    }
}

fn walk_adjustment(seen: &mut Seen, adjustment: &Adjustment) {
    match &adjustment.change {
        Temporary::Exempt { guard: _, cover } => {
            seen.temporary.exempt = true;
            walk_option_cond(
                seen,
                cover,
                |o| o.cover_some = true,
                |o| o.cover_none = true,
            );
        }
        Temporary::Rebind { add, suspend: _ } => {
            seen.temporary.rebind = true;
            add.iter()
                .for_each(|binding| walk_level(seen, binding.level));
        }
    }
    match &adjustment.lifetime {
        Lifetime::Next => seen.lifetime.next = true,
        Lifetime::Within(scope) => {
            seen.lifetime.within = true;
            walk_scope(seen, scope);
        }
        Lifetime::Timed => seen.lifetime.timed = true,
    }
}

fn walk_body(seen: &mut Seen, body: &Body) {
    match body {
        Body::SessionStart => seen.body.session_start = true,
        Body::Spawn { child: _, under: _ } => seen.body.spawn = true,
        Body::TaskStart => seen.body.task_start = true,
        Body::PromptSubmit => seen.body.prompt_submit = true,
        Body::ToolUse {
            tool: _,
            command,
            path,
            ok,
        } => {
            seen.body.tool_use = true;
            match command {
                FieldState::Absent => seen.field_state.command_absent = true,
                FieldState::Value(_) => seen.field_state.command_value = true,
                FieldState::Unreadable => seen.field_state.command_unreadable = true,
            }
            match path {
                FieldState::Absent => seen.field_state.path_absent = true,
                FieldState::Value(_) => seen.field_state.path_value = true,
                FieldState::Unreadable => seen.field_state.path_unreadable = true,
            }
            match ok {
                Some(_) => seen.option.ok_some = true,
                None => seen.option.ok_none = true,
            }
        }
        Body::Stop => seen.body.stop = true,
        Body::Used { meter: _, amount } => {
            seen.body.used = true;
            match amount {
                Some(_) => seen.option.amount_some = true,
                None => seen.option.amount_none = true,
            }
        }
        Body::ModeSwitch { to: _ } => seen.body.mode_switch = true,
        Body::Measured {
            oracle: _,
            score: _,
        } => seen.body.measured = true,
        Body::Classified {
            classifier: _,
            answer: _,
        } => seen.body.classified = true,
        Body::Adjust(adjustment) => {
            seen.body.adjust = true;
            walk_adjustment(seen, adjustment);
        }
        Body::Cancel { id: _ } => seen.body.cancel = true,
        Body::Judged {
            policy: _,
            judgment,
            written,
            enforced,
        } => {
            seen.body.judged = true;
            walk_judgment(seen, *judgment);
            walk_level(seen, *written);
            walk_level(seen, *enforced);
        }
        Body::Unreadable { may_have_been } => {
            seen.body.unreadable = true;
            may_have_been.iter().for_each(|kind| walk_kind(seen, kind));
        }
    }
}

fn walk_policy(seen: &mut Seen, def: &PolicyDef) {
    match def.layer {
        DefLayer::Meta => seen.def_layer.meta = true,
        DefLayer::Base => seen.def_layer.base = true,
    }
    walk_kind(seen, def.subject);
    match &def.when {
        Some(when) => {
            seen.option.when_some = true;
            walk_pred(seen, when);
        }
        None => seen.option.when_none = true,
    }
    match &def.rule {
        Rule::Structural(pred) => {
            seen.rule.structural = true;
            walk_pred(seen, pred);
        }
    }
    match &def.polarity {
        Polarity::Guard => seen.polarity.guard = true,
        Polarity::Reward { bound_by: _ } => seen.polarity.reward = true,
    }
    for fixture in &def.fixtures {
        match fixture.expect {
            Expect::Violated => seen.expect.violated = true,
            Expect::Satisfied => seen.expect.satisfied = true,
            Expect::NotApplicable => seen.expect.not_applicable = true,
            Expect::Unknown => seen.expect.unknown = true,
        }
        if fixture.known_gap {
            seen.option.known_gap_true = true;
        } else {
            seen.option.known_gap_false = true;
        }
        fixture
            .events
            .iter()
            .for_each(|event| walk_body(seen, &event.body));
    }
}

fn walk_sources(seen: &mut Seen, sources: &Sources) {
    for source in sources.iter() {
        let graph = &source.graph;
        match graph.temporary_bound() {
            Some(_) => seen.option.bound_some = true,
            None => seen.option.bound_none = true,
        }
        graph.policies().for_each(|def| walk_policy(seen, def));
        for binding in graph.bindings() {
            walk_level(seen, binding.level);
            walk_mode_scope(seen, &binding.mode);
        }
        for classifier in graph.classifiers() {
            match classifier.record {
                Some(_) => seen.option.record_some = true,
                None => seen.option.record_none = true,
            }
        }
    }
}

fn walk_target(seen: &mut Seen, target: &Target) {
    match target {
        Target::Policy(_) => seen.target.policy = true,
        Target::Binding(_) => seen.target.binding = true,
        Target::Classifier(_) => seen.target.classifier = true,
        Target::Set(_) => seen.target.set = true,
    }
}

fn walk_rule_move(seen: &mut Seen, rule_move: &RuleMove) {
    match rule_move {
        RuleMove::Lowered {
            policy: _,
            authors: _,
        } => seen.rule_move.lowered = true,
        RuleMove::Raised { policy: _ } => seen.rule_move.raised = true,
        RuleMove::Exempted {
            policy: _,
            authors: _,
        } => seen.rule_move.exempted = true,
        RuleMove::Unexempted { policy: _ } => seen.rule_move.unexempted = true,
        RuleMove::Suspended {
            policy: _,
            binding: _,
            authors: _,
        } => seen.rule_move.suspended = true,
    }
}

fn walk_reader(seen: &mut Seen, reader: &Reader) {
    match reader {
        Reader::Policy(_) => seen.reader.policy = true,
        Reader::Adjustment(_) => seen.reader.adjustment = true,
    }
}

fn walk_finding_detail(seen: &mut Seen, detail: &FindingDetail) {
    match detail {
        FindingDetail::Rules { moves, reading: _ } => {
            seen.finding_detail.rules = true;
            moves.iter().for_each(|m| walk_rule_move(seen, m));
        }
        FindingDetail::Mode { reading: _ } => seen.finding_detail.mode = true,
        FindingDetail::Slot {
            slot: _,
            reading: _,
        } => seen.finding_detail.slot = true,
        FindingDetail::Spawn {
            child: _,
            under: _,
            loosened,
        } => {
            seen.finding_detail.spawn = true;
            loosened.iter().for_each(|r| walk_reader(seen, r));
        }
        FindingDetail::Described(_) => seen.finding_detail.described = true,
    }
}

fn walk_loosening(seen: &mut Seen, loosening: &Loosening) {
    match loosening {
        Loosening::Uncovered { target } => {
            seen.loosening.uncovered = true;
            walk_target(seen, target);
        }
        Loosening::Moves {
            mode,
            authors: _,
            detail,
        } => {
            seen.loosening.moves = true;
            match mode {
                Some(_) => seen.option.moves_mode_some = true,
                None => seen.option.moves_mode_none = true,
            }
            walk_finding_detail(seen, detail);
        }
    }
}

/// Every variant of every enum the encoding reaches is in the sample, so the round trip covers
/// all of them.
///
/// FR68, FR66.
#[test]
fn the_sample_reaches_every_variant_the_encoding_has() {
    let sample = sample();
    let mut seen = Seen::default();
    walk_sources(&mut seen, &sample.sources);
    sample
        .events
        .iter()
        .for_each(|event| walk_body(&mut seen, &event.body));
    sample
        .loosenings
        .iter()
        .for_each(|loosening| walk_loosening(&mut seen, loosening));
    seen.assert_all();
}

// ---------------------------------------------------------------------------------------------
// Round trip

/// An event is the same after a round trip, by the domain's equality and, for a finite number,
/// to the bit: `0.1 + 0.2` is not `0.3`.
fn same_event(a: &Event, b: &Event) -> bool {
    let bits = |x: f64, y: f64| (x.is_nan() && y.is_nan()) || x.to_bits() == y.to_bits();
    let body = match (&a.body, &b.body) {
        (
            Body::Measured {
                oracle: o1,
                score: s1,
            },
            Body::Measured {
                oracle: o2,
                score: s2,
            },
        ) => o1 == o2 && bits(*s1, *s2),
        (
            Body::Classified {
                classifier: c1,
                answer: a1,
            },
            Body::Classified {
                classifier: c2,
                answer: a2,
            },
        ) => c1 == c2 && bits(*a1, *a2),
        (
            Body::Used {
                meter: m1,
                amount: a1,
            },
            Body::Used {
                meter: m2,
                amount: a2,
            },
        ) => {
            m1 == m2
                && a1.map(Amount::get).map(f64::to_bits) == a2.map(Amount::get).map(f64::to_bits)
        }
        _ => a.body == b.body,
    };
    a.at == b.at && a.by == b.by && body
}

/// The sample decodes to what was encoded: the same sources, authority and events, a finite
/// number to the bit, and the same text when it is encoded again.
///
/// FR68.
#[test]
fn the_sample_decodes_to_what_was_encoded() {
    let sample = sample();
    let json = serde_json::to_string(&sample).unwrap();
    let back: Sample = serde_json::from_str(&json).unwrap();
    assert_eq!(back.sources, sample.sources);
    assert_eq!(back.authority, sample.authority);
    assert_eq!(back.loosenings, sample.loosenings);
    assert_eq!(back.events.len(), sample.events.len());
    for (before, after) in sample.events.iter().zip(&back.events) {
        assert!(same_event(before, after), "{before:?} came back {after:?}");
    }
    // A text is one number, so the same text again is the same bits for the numbers of the
    // conditions, which the domain's equality compares with `==`.
    assert_eq!(serde_json::to_string(&back).unwrap(), json);
}

/// The numbers a JSON number cannot carry are written as text and read back.
///
/// FR68.
#[test]
fn a_number_that_is_not_finite_is_written_as_text() {
    let score = |score: f64| Body::Measured {
        oracle: "o".to_owned(),
        score,
    };
    for (value, written) in [
        (f64::NAN, "\"NaN\""),
        (f64::INFINITY, "\"inf\""),
        (f64::NEG_INFINITY, "\"-inf\""),
    ] {
        let json = serde_json::to_string(&score(value)).unwrap();
        assert!(json.contains(written), "{json}");
        let back: Body = serde_json::from_str(&json).unwrap();
        assert_eq!(back, score(value));
    }
    let json = serde_json::to_string(&score(-0.0)).unwrap();
    assert!(json.contains("-0.0"), "{json}");
    let Body::Measured { score: back, .. } = serde_json::from_str(&json).unwrap() else {
        panic!("not a measurement");
    };
    assert_eq!(back.to_bits(), (-0.0_f64).to_bits());
}

fn accepted(sources: Sources) -> Catalog {
    Catalog::accept(
        sources,
        authority(),
        Lineage::new("encoded").expect("a lineage"),
    )
    .unwrap_or_else(|rejected| panic!("the sample is not accepted: {rejected:?}"))
}

/// The sources that come back are the sources that were encoded: a catalog accepted from them has
/// the graph of one accepted from the originals.
///
/// FR68.
#[test]
fn a_catalog_accepted_from_decoded_sources_has_the_same_graph() {
    let sources = sources();
    let json = serde_json::to_string(&sources).unwrap();
    let back: Sources = serde_json::from_str(&json).unwrap();
    assert_eq!(accepted(back).graph(), accepted(sources).graph());
}

/// A lineage is written as its text and read back through its constructor.
///
/// FR68.
#[test]
fn a_lineage_and_a_principal_are_their_text() {
    let lineage = Lineage::new("main-line").unwrap();
    assert_eq!(serde_json::to_string(&lineage).unwrap(), "\"main-line\"");
    let back: Lineage = serde_json::from_str("\"main-line\"").unwrap();
    assert_eq!(back, lineage);
    let who: Principal = serde_json::from_str("\"someone else\"").unwrap();
    assert_eq!(who.key(), "someone else");
}

// ---------------------------------------------------------------------------------------------
// What is refused

/// Decoding `json` as a `T` fails, with `why` in the error: the error is the constructor's own,
/// not a failure to read the shape.
fn refused<T: for<'de> Deserialize<'de> + Debug>(json: &str, why: &str) {
    let error = serde_json::from_str::<T>(json)
        .expect_err(&format!(
            "{json} was decoded as {}",
            std::any::type_name::<T>()
        ))
        .to_string();
    assert!(error.contains(why), "{json}: {error}");
}

const EMPTY_GRAPH: &str = r#"{"policies":[],"bindings":[],"classifiers":[],"bound":null}"#;

fn binding_json(id: &str) -> String {
    format!(
        r#"{{"id":"{id}","policy":"{}","level":"Advise","mode":"Any","author":"user"}}"#,
        id_text(1)
    )
}

fn set_json(id: &str, name: &str) -> String {
    format!(r#"{{"id":"{id}","name":"{name}","owner":"user","graph":{EMPTY_GRAPH}}}"#)
}

/// A name, an id, a reason, a pattern, command words and a lineage that their constructors
/// refuse are refused when decoded, with the constructor's error.
///
/// FR68.
#[test]
fn a_text_the_constructor_refuses_is_refused() {
    const NOT_A_UUID: &str = "is not a hyphenated UUID";
    refused::<PolicyId>("\"nope\"", NOT_A_UUID);
    refused::<BindingId>("\"0190a1b2c3d47e5f8a9b0c1d2e3f4a5b\"", NOT_A_UUID);
    refused::<AdjustmentId>("\"\"", NOT_A_UUID);
    refused::<SetId>("\"g0000000-0000-7000-8000-000000000000\"", NOT_A_UUID);
    refused::<PolicyName>("\"\"", "is not a name");
    refused::<SetName>("\"has space\"", "is not a name");
    refused::<Mode>("\"a.b\"", "is not a name");
    refused::<Meter>("\"\"", "is not a name");
    refused::<ClassifierName>("\"a b\"", "is not a classifier name");
    refused::<Reason>("\"  \"", "a reason cannot be empty");
    refused::<GlobPattern>("\"a**b\"", "must be a whole segment");
    refused::<CommandWords>("[]", "command words need");
    refused::<CommandWords>(r#"["cargo",""]"#, "command words need");
    refused::<Lineage>("\"\"", "a lineage cannot be empty");
    // The text that is allowed is read, so the refusal is the rule's and not the shape's.
    assert!(serde_json::from_str::<CommandWords>(r#"["echo","a b"]"#).is_ok());
    assert!(serde_json::from_str::<GlobPattern>("\"a/**/b\"").is_ok());
}

/// A length that is not more than zero, and an amount or a number the constructors refuse, are
/// refused when decoded.
///
/// FR68.
#[test]
fn a_number_the_constructor_refuses_is_refused() {
    refused::<Window>("0", "not positive");
    refused::<Scope>(r#"{"Every":-1}"#, "not positive");
    refused::<TemporaryBound>("-5", "not positive");
    refused::<Amount>("-1.0", "negative amount");
    // A JSON number is finite, so a deserializer that holds NaN stands in for the encoded form of
    // one.
    let nan = || F64Deserializer::<serde::de::value::Error>::new(f64::NAN);
    let inf = || F64Deserializer::<serde::de::value::Error>::new(f64::INFINITY);
    assert!(
        Amount::deserialize(nan())
            .unwrap_err()
            .to_string()
            .contains("not a finite amount")
    );
    assert!(
        Amount::deserialize(inf())
            .unwrap_err()
            .to_string()
            .contains("not a finite amount")
    );
    assert!(
        Number::deserialize(nan())
            .unwrap_err()
            .to_string()
            .contains("not a finite number")
    );
    assert!(serde_json::from_str::<Number>("-2.5").is_ok());
}

/// A hierarchy with no root, an unknown parent or a loop is refused when decoded, and so are a
/// set of modes, a bound and a record that their constructors refuse.
///
/// FR68.
#[test]
fn a_value_of_parts_the_constructor_refuses_is_refused() {
    refused::<Authority>(r#"{"links":[]}"#, "needs at least one root");
    refused::<Authority>(r#"{"links":[["a","b"]]}"#, "is not a principal");
    refused::<Authority>(r#"{"links":[["a","b"],["b","a"]]}"#, "never reach a root");
    refused::<Authority>(r#"{"links":[["a",null],["a",null]]}"#, "is given twice");
    refused::<ModeSet>(r#"{"modes":[]}"#, "needs at least one mode");
    refused::<ModeSet>(r#"{"modes":["a","a"]}"#, "is given twice");
    refused::<Calibration>(
        r#"{"min_cases":0,"max_false_stops":1}"#,
        "needs at least one case",
    );
    refused::<CalibrationRecord>(
        r#"{"cases":1,"false_stops":2}"#,
        "cannot hold 2 false stops",
    );
    // The same shapes that are allowed are read.
    assert!(serde_json::from_str::<Authority>(r#"{"links":[["a",null],["b","a"]]}"#).is_ok());
    assert!(serde_json::from_str::<ModeSet>(r#"{"modes":["a","b"]}"#).is_ok());
    assert!(serde_json::from_str::<CalibrationRecord>(r#"{"cases":2,"false_stops":2}"#).is_ok());
}

/// Two bindings of one id in a graph, and two sets of one id in the sources, are refused when
/// decoded, with every error the constructor found; two sets of one name are read, as a name is
/// no identity.
///
/// FR68, FR67.
#[test]
fn a_graph_and_sources_the_constructor_refuses_are_refused() {
    let id = binding_id(1).to_string();
    let twice = format!(
        r#"{{"policies":[],"bindings":[{0},{0}],"classifiers":[],"bound":null}}"#,
        binding_json(&id)
    );
    refused::<PolicyGraph>(&twice, "two bindings have the id");
    assert!(
        serde_json::from_str::<PolicyGraph>(&format!(
            r#"{{"policies":[],"bindings":[{}],"classifiers":[],"bound":null}}"#,
            binding_json(&id)
        ))
        .is_ok()
    );

    let sets = |first: &str, second: &str| {
        format!(
            r#"{{"sets":[{},{}]}}"#,
            set_json(&set_id(1).to_string(), first),
            set_json(&set_id(2).to_string(), second)
        )
    };
    assert!(serde_json::from_str::<Sources>(&sets("same", "same")).is_ok());
    assert!(serde_json::from_str::<Sources>(&sets("one", "two")).is_ok());
    let twice_id = format!(
        r#"{{"sets":[{0},{1}]}}"#,
        set_json(&set_id(1).to_string(), "one"),
        set_json(&set_id(1).to_string(), "two")
    );
    refused::<Sources>(&twice_id, "two sets have the id");
}

/// A field no type has is refused, in an event, in the struct variant of a body and in the form
/// a type is encoded as: the encoding reads only what it writes, and reading an older or a newer
/// form is the job of a store's DTO.
///
/// FR68.
#[test]
fn a_field_no_type_has_is_refused() {
    let spawn = r#"{"Spawn":{"child":"a","under":"b"}}"#;
    assert!(serde_json::from_str::<Body>(spawn).is_ok());
    refused::<Body>(
        r#"{"Spawn":{"child":"a","under":"b","extra":1}}"#,
        "unknown field `extra`",
    );
    refused::<Body>(
        r#"{"ToolUse":{"tool":"Bash","command":"Absent","path":"Absent","ok":null,"extra":true}}"#,
        "unknown field `extra`",
    );
    refused::<Event>(
        &format!(r#"{{"at":0,"by":"a","body":"Stop","extra":0,"unused":{spawn}}}"#),
        "unknown field `extra`",
    );
    refused::<Authority>(
        r#"{"links":[["a",null]],"extra":1}"#,
        "unknown field `extra`",
    );
    refused::<PolicyGraph>(
        r#"{"policies":[],"bindings":[],"classifiers":[],"bound":null,"extra":1}"#,
        "unknown field `extra`",
    );
}

/// A field that may hold nothing is still written, as `null`, so one that is missing is refused,
/// not read as nothing: an exemption missing its cover would otherwise cover every event, and a
/// filter missing its condition would take every event of its kind.
///
/// FR68.
#[test]
fn a_missing_field_that_may_hold_nothing_is_refused() {
    let exempt = |cover: &str| format!(r#"{{"Exempt":{{"guard":"{}"{cover}}}}}"#, id_text(1));
    refused::<Temporary>(&exempt(""), "missing field `cover`");
    assert!(serde_json::from_str::<Temporary>(&exempt(r#","cover":null"#)).is_ok());
    refused::<EventFilter>(r#"{"kind":"Stop"}"#, "missing field `cond`");
    assert!(serde_json::from_str::<EventFilter>(r#"{"kind":"Stop","cond":null}"#).is_ok());
    refused::<Body>(
        r#"{"ToolUse":{"tool":"Bash","command":"Absent","path":"Absent"}}"#,
        "missing field `ok`",
    );
    refused::<Body>(r#"{"Used":{"meter":"tokens"}}"#, "missing field `amount`");
    refused::<PolicyGraph>(
        r#"{"policies":[],"bindings":[],"classifiers":[]}"#,
        "missing field `bound`",
    );
}

/// A field of an event that is absent, that has a value and that could not be read are written
/// as three different forms and read back as the three states, and a form that is none of them
/// is refused: the `null` that a field which may be absent was once written as is no state of a
/// `Seen`, and a field that is missing is not read as absent.
///
/// FR68, FR69.
#[test]
fn a_field_that_could_not_be_read_is_told_from_one_that_is_absent_in_the_encoding() {
    let tool_use = |command: &str, path: &str| {
        format!(r#"{{"ToolUse":{{"tool":"Bash","command":{command},"path":{path},"ok":null}}}}"#)
    };
    let cases = [
        (r#""Absent""#, FieldState::Absent),
        (
            r#"{"Value":"src/a.rs"}"#,
            FieldState::Value("src/a.rs".to_owned()),
        ),
        (r#""Unreadable""#, FieldState::Unreadable),
    ];
    for (path_json, path) in cases {
        let json = tool_use(r#"{"Value":["cargo","test"]}"#, path_json);
        let decoded: Body = serde_json::from_str(&json).unwrap();
        let expected = Body::ToolUse {
            tool: "Bash".to_owned(),
            command: FieldState::Value(words("cargo test")),
            path,
            ok: None,
        };
        assert_eq!(decoded, expected, "{json}");
        assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
    }
    for json in [
        tool_use("null", r#""Absent""#),
        tool_use(r#""Absent""#, "null"),
    ] {
        assert!(serde_json::from_str::<Body>(&json).is_err(), "{json}");
    }
    refused::<Body>(&tool_use(r#""Missing""#, r#""Absent""#), "unknown variant");
    refused::<Body>(
        r#"{"ToolUse":{"tool":"Bash","command":"Absent","ok":null}}"#,
        "missing field `path`",
    );
}

/// A score that is neither a number nor the text of one that is not finite is refused, and a
/// missing one is too.
///
/// FR68.
#[test]
fn a_score_that_is_not_a_number_is_refused() {
    refused::<Body>(
        r#"{"Measured":{"oracle":"o","score":null}}"#,
        "untagged enum",
    );
    refused::<Body>(
        r#"{"Measured":{"oracle":"o","score":"nan"}}"#,
        "untagged enum",
    );
    refused::<Body>(
        r#"{"Classified":{"classifier":"c"}}"#,
        "missing field `answer`",
    );
    let ok = r#"{"Measured":{"oracle":"o","score":0.5}}"#;
    assert!(serde_json::from_str::<Body>(ok).is_ok());
}

/// Every way a change loosens is the same after a round trip, one by one and as the list a
/// rejected change holds, and the same text again when it is encoded again.
///
/// FR66.
#[test]
fn a_loosening_decodes_to_what_was_encoded() {
    for loosening in loosenings() {
        let json = serde_json::to_string(&loosening).unwrap();
        let back: Loosening = serde_json::from_str(&json).unwrap();
        assert_eq!(back, loosening, "{json}");
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }
    let all = loosenings();
    let json = serde_json::to_string(&all).unwrap();
    assert_eq!(serde_json::from_str::<Vec<Loosening>>(&json).unwrap(), all);
}

/// A slot's id is encoded as its number, as it is, and read back as it was written: it is the
/// fact of the record that names it, and no rule is there to check it.
///
/// FR66.
#[test]
fn a_slot_id_is_its_number() {
    assert_eq!(serde_json::to_string(&slot(7)).unwrap(), "7");
    assert_eq!(serde_json::from_str::<SlotId>("7").unwrap(), slot(7));
    let json = serde_json::to_string(&FindingDetail::Slot {
        slot: slot(3),
        reading: vec![],
    })
    .unwrap();
    assert_eq!(json, r#"{"Slot":{"slot":3,"reading":[]}}"#);
    // Not a number a slot could have.
    refused::<SlotId>("-1", "invalid value");
    refused::<SlotId>("\"3\"", "invalid type");
}

/// A field no type has is refused in every shape a loosening holds, as the encoding reads only
/// what it writes; a field that may hold nothing is refused when it is missing.
///
/// FR66.
#[test]
fn a_loosening_with_a_field_no_type_has_is_refused() {
    let policy = id_text(1);
    let binding = binding_id(1).to_string();
    let adjustment = adjustment_id(1).to_string();
    let target = format!(r#"{{"Policy":"{policy}"}}"#);
    refused::<Loosening>(
        &format!(r#"{{"Uncovered":{{"target":{target},"extra":1}}}}"#),
        "unknown field `extra`",
    );
    let moves = |mode: &str, detail: &str| {
        format!(r#"{{"Moves":{{{mode}"authors":[],"detail":{detail}}}}}"#)
    };
    let mode = r#""mode":null,"#;
    let ok = moves(mode, r#"{"Mode":{"reading":[]}}"#);
    assert!(serde_json::from_str::<Loosening>(&ok).is_ok());
    refused::<Loosening>(
        &moves(r#""mode":null,"extra":1,"#, r#"{"Mode":{"reading":[]}}"#),
        "unknown field `extra`",
    );
    refused::<Loosening>(
        &moves("", r#"{"Mode":{"reading":[]}}"#),
        "missing field `mode`",
    );
    for detail in [
        r#"{"Rules":{"moves":[],"reading":[],"extra":1}}"#.to_owned(),
        r#"{"Mode":{"reading":[],"extra":1}}"#.to_owned(),
        r#"{"Slot":{"slot":1,"reading":[],"extra":1}}"#.to_owned(),
        r#"{"Spawn":{"child":"a","under":"b","loosened":[],"extra":1}}"#.to_owned(),
        format!(
            r#"{{"Rules":{{"moves":[{{"Raised":{{"policy":"{policy}","extra":1}}}}],"reading":[]}}}}"#
        ),
        format!(
            r#"{{"Rules":{{"moves":[{{"Lowered":{{"policy":"{policy}","authors":[],"extra":1}}}}],"reading":[]}}}}"#
        ),
        format!(
            r#"{{"Rules":{{"moves":[{{"Suspended":{{"policy":"{policy}","binding":"{binding}","authors":[],"extra":1}}}}],"reading":[]}}}}"#
        ),
    ] {
        refused::<FindingDetail>(&detail, "unknown field `extra`");
    }
    // A newtype variant is one key: a second key is not read.
    refused::<Reader>(
        &format!(r#"{{"Adjustment":"{adjustment}","extra":1}}"#),
        "expected value",
    );
    refused::<Reader>(
        &format!(r#"{{"Policy":"{policy}","Adjustment":"{adjustment}"}}"#),
        "expected value",
    );
    refused::<Target>(
        &format!(r#"{{"Binding":"{binding}","Policy":"{policy}"}}"#),
        "expected value",
    );
    // Each part is read through its own constructor.
    refused::<Target>(r#"{"Policy":"not an id"}"#, "is not a hyphenated UUID");
    refused::<FindingDetail>(
        r#"{"Spawn":{"child":"a","under":"b","loosened":[{"Policy":"x"}]}}"#,
        "`x` is not a hyphenated UUID",
    );
}
