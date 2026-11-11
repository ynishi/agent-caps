//! The domain's own points of view on a claim, and the default way to combine findings.
//!
//! ```text
//! check        looks at                     finds                                   authors
//! RuleCheck    the whole state before and   loosens when a policy's effect goes     of a lowered policy, the
//!              after: each policy's effect  down, an exemption of it starts or a    bindings that carried what
//!              (Catalog::effective_in),     binding of it is suspended; tightens    was lowered, temporary ones
//!              the bindings suspended and   when one goes up or an exemption ends   included; of an exempted
//!              the exemptions in effect     (rule_moves)                            one, its author and every
//!                                                                                   binding's in the catalog,
//!                                                                                   under any mode; of a
//!                                                                                   suspended binding, its own
//! ModeCheck    Mode { before, after }       loosens when a policy that reads a      each policy that loosens
//!                                           mode with ModeIs sees it left, or
//!                                           entered where its direction cannot
//!                                           be read; tightens when every read
//!                                           mode entered is read as "applies
//!                                           inside"; else neutral
//! SlotCheck    Slot(s)                      loosens: a slot's direction cannot      each policy reading s
//!                                           be read
//! SpawnCheck   ActorAdded { child,          loosens when a reader of the actor      each such policy's
//!              under }                      (a policy, or an adjustment in effect   author, each such
//!                                           whose lifetime chooses by actor) sees   adjustment's maker
//!                                           the child leave a principal, or move
//!                                           where its direction cannot be told;
//!                                           tightens when every move is into a
//!                                           principal read as "applies inside";
//!                                           else neutral
//! RuleCheck, ModeCheck and SpawnCheck also loosen every other policy that reads the judgments of
//! a policy they move, either way, by that reader's author (`verdict_of`). An adjustment writes
//! no judgment, so one that moves spreads to no one.
//! ```
//!
//! The move of a state atom is looked at by one check: [`ModeCheck`] the mode as rules read it
//! with `ModeIs`, [`SlotCheck`] a slot, [`SpawnCheck`] the actor. How the rules take effect, the
//! strength of each policy, the bindings suspended and the exemptions in effect, is
//! [`RuleCheck`]'s, which compares the whole state before and after, once per claim, whichever
//! [`StateChange`] moved it (a mode switch, a temporary adjustment added, used up, run out or
//! cancelled). All four are applied to every claim ([`super::TxPolicy`] cannot leave one out).
//! What a policy reads, a slot, a mode or an actor, is the catalog's one value of it, the same one
//! [`Catalog::accept`] checks references with. A check names the authors; whether the claim's
//! author may loosen their rules is the floor's question, not the check's.
//!
//! # How the rules move
//!
//! `rule_moves` is the one answer to how the rules take effect differently between two points.
//! [`RuleCheck`] reads it for a claim (one catalog, the state before and after, each with its
//! temporary adjustments), and [`Catalog::change`] reads it for a change of the catalog (two
//! catalogs, under each compared mode, with no temporary adjustment).
//!
//! - A policy goes down when its effect ([`Catalog::effective`] for a catalog alone,
//!   [`Catalog::effective_in`] for a state, by the order of [`Effect`]) is lower after than
//!   before. The authors asked are those of the bindings in effect before (in the catalog and not
//!   suspended, and those the temporary adjustments add, by the one who made each) that held or
//!   may have held before ([`ModeScope::holds`] not false) and are stronger than the effect
//!   after: the bindings that carried the strength that was lost, and no others. So cancelling
//!   another's raise asks the one who raised.
//! - An exemption starts for each one held after and not before, told apart by its id, so an
//!   exemption beside a narrower one of the same guard is still one that starts. The authors
//!   asked are the guard's author and the author of every binding of it in the catalog under any
//!   mode: an exemption reaches the guard whatever the mode becomes, so one placed while the guard
//!   is off under the mode still needs those whose bindings turn it on elsewhere. A temporary
//!   binding of the guard is by the guard's author or one below it ([`super::super::adjust`]),
//!   so whoever covers the guard's author covers it, and it adds no one.
//! - A binding of the catalog is suspended for each one that an adjustment which starts suspends,
//!   and that asks the binding's author whether or not the policy goes down. Otherwise one could
//!   hide the loss with an equal temporary binding of one's own, suspend another's binding, and
//!   later cancel one's own: the same rule as a binding kept by [`Catalog::change`]. This holds
//!   under the mark of a lost adjustment too, where the suspension changes no effect.
//! - A policy that goes up, and an exemption that ends, tighten. A suspension that ends is judged
//!   by the result alone. A cancel is no move of its own: it is judged by what ending the
//!   adjustment moves, so cancelling a lowering or an exemption tightens and is open to anyone.
//!   So is a claim that closes the scope an adjustment lasts within: the point after it is the
//!   state as the next event finds it, with such adjustments ended.
//!
//! A mode that is not known is the strongest side by [`Catalog::effective`] alone, and a lost
//! record of an adjustment by [`Catalog::effective_in`] alone, so not knowing either is never a
//! way to loosen a rule.
//!
//! # Which way a move of an atom goes
//!
//! A state atom that policies read, a mode with `ModeIs` or a principal with `ActorUnder`, moves
//! in a claim: it is entered, left, or stays. How that moves a policy is one rule, here, and the
//! spawn check and the mode check each only say how the atom moved; `direction` answers the
//! rest, and the [`Verdict`] is made from the directions of the policies in one place.
//!
//! A policy that applies where an atom holds (the atom in its guard's `when`, under no `not`) is
//! read as `Positive`: it is tightened by an entry and loosened by a leaving. Any other reading of
//! the atom (under a `not`, in a guard's `rule`, in a reward) is `Unreadable`: it cannot be told
//! to move either way, so entering and leaving both loosen. A policy that reads several atoms is
//! loosened when any of them loosens it, else tightened when any entry tightens it.
//!
//! What is not known is never taken for "stays". Where it is not known whether an atom was left,
//! it is taken as left.
//!
//! # What a policy that moves writes
//!
//! A policy that a claim or a change moves, either way, writes other judgments than it did, in
//! its author's name, which always count: one that applies to more or takes effect more strongly
//! writes more of them or stronger ones, one that applies to less or takes effect less strongly
//! writes fewer or weaker ones, and an off one writes none. Every other policy that reads its
//! judgments (a filter that names it, or that narrows to none and sees it) has the slots it reads
//! moved by that, in a direction that cannot be read: it counts more or fewer, or a later record
//! replaces the last. So such a policy is loosened, and its author is among the authors the floor
//! asks, as for a policy loosened by the move itself. This is the same for the rules, a mode and a
//! spawn, and `verdict_of` is where it is decided; who reads whose judgments is the catalog's
//! (`Reads`), not found again here. A change of the catalog asks it of the readers of both the
//! catalog before and after, so a reader that goes and one that comes are both asked.
//!
//! # The spawn check
//!
//! A spawn is judged against a place directly under its spawner (see [`super`]). The place it is
//! judged against and the place it is put are each the ancestors of the child, from the state's
//! one place that walks them; the child itself is in both, so it is in neither difference.
//!
//! The readers of the actor are collected in one place (`actor_readings`), each a [`Reader`]: a
//! policy reads the principals of its `ActorUnder` and of every `By::Under` of its selectors and
//! scopes, by its author; a temporary adjustment in effect reads the `By::Under` of the scope its
//! lifetime lasts within, by the one who made it ([`HeldAdjustment::by`]). A `By::Under` is
//! always read in a direction that cannot be told: a child placed under its principal has its
//! later acts counted, or closing or starting the scope again. A principal that a reader reads is
//!
//! - entered, when the new place has it and the spawner's does not,
//! - left, when the spawner's place has it and the new one does not.
//!
//! When the spawner is not whole in the hierarchy (an actor it does not know, a leaf of unknown
//! place), the principals the walk passed are all that is known of its place: those the new place
//! has beyond them are entered, and every principal the new place lacks may have been left. When
//! the new place is not known, nothing of the difference is, and every reader of the actor is
//! loosened, except where both walks stop at the same leaf (a leaf of unknown place that
//! places a child under itself): what is above that leaf is the same in both, so the principals
//! passed below it tell the difference.
//!
//! # The mode check
//!
//! A mode switch moves each mode a policy reads with `ModeIs` by whether "the mode is `m`"
//! ([`ModeScope::In`] of `m`, [`ModeScope::holds`]) holds before and after:
//!
//! | before | after | the mode `m` |
//! |---|---|---|
//! | true | false | left |
//! | false | true | entered |
//! | true | true | stays |
//! | false | false | stays |
//! | unknown | true | entered (it may have been there already, and is counted as entered: tightens a policy that applies inside it, loosens one read in a way that cannot be told) |
//! | unknown | false | left (it may have been `m`) |
//! | any | unknown | left (where it went is not known) |
//!
//! No mode at all is a value equal to no `m`. How the switch moves the strength of the policies,
//! through the bindings that hold inside or outside a mode, is [`RuleCheck`]'s, not this check's.
//!
//! The polarity of the mode itself is not changed by this: a switch that tightens is open to
//! anyone, and one that loosens is the floor's. An upper rule that reads a slot of the mode's
//! scope, which moves when the mode switches, is [`SlotCheck`]'s to loosen.

use super::{AdjustmentCheck, CheckFinding, CheckName, Combine, Confidence, FindingDetail, Reader};
use super::{TxDecision, TxInput, Verdict};
use crate::domain::authority::Principal;
use crate::domain::catalog::{Catalog, Effect, Effective, InEffect, lowered};
use crate::domain::name::{AdjustmentId, BindingId, Mode, PolicyId};
use crate::domain::policy::ModeScope;
use crate::domain::predicate::{Reading, Truth};
use crate::domain::state::{Ancestry, HeldAdjustment, HeldEffect, Known, State, StateChange};

/// The domain's checks, in the order their findings are reported.
pub(super) fn domain() -> [&'static dyn AdjustmentCheck; 4] {
    [&RuleCheck, &ModeCheck, &SlotCheck, &SpawnCheck]
}

/// Adds `author` to `authors` when it is not there yet.
fn add_author(authors: &mut Vec<Principal>, author: &Principal) {
    if !authors.contains(author) {
        authors.push(author.clone());
    }
}

/// The authors of `policies`, each once.
fn authors_of(catalog: &Catalog, policies: &[PolicyId]) -> Vec<Principal> {
    let mut authors: Vec<Principal> = Vec::new();
    for policy in policies.iter().filter_map(|id| catalog.policy(*id)) {
        add_author(&mut authors, policy.author());
    }
    authors
}

fn finding(name: &str, verdict: Verdict) -> CheckFinding {
    CheckFinding {
        check: CheckName::new(name),
        verdict,
    }
}

/// How a state atom that policies read moved in a claim, as to one policy's reading of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Move {
    /// It is in both, or in neither.
    Stays,
    /// It is entered: it holds after and did not before.
    Enters,
    /// It is left: it held before and does not after, or may have, or nothing of the difference
    /// is known.
    Leaves,
}

/// Which way a policy moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// It holds less, or its direction cannot be read.
    Loosens,
    /// It holds more.
    Tightens,
}

/// The one rule of which way the moves of the atoms a policy reads move it, each with the
/// direction the policy reads the atom in:
///
/// - loosens: an atom left, or entered where the policy reads it in a direction that cannot be
///   told;
/// - else tightens: an atom entered that the policy applies inside of;
/// - else no direction.
fn direction(moves: &[(Move, Reading)]) -> Option<Direction> {
    let loosens = |&(shift, reading): &(Move, Reading)| match (shift, reading) {
        (Move::Leaves, _) | (Move::Enters, Reading::Unreadable) => true,
        (Move::Enters, Reading::Positive) | (Move::Stays, _) => false,
    };
    if moves.iter().any(loosens) {
        Some(Direction::Loosens)
    } else if moves.iter().any(|(shift, _)| *shift == Move::Enters) {
        Some(Direction::Tightens)
    } else {
        None
    }
}

/// One reader that a claim or a change moves, the way it moves, and the authors a loosening
/// asks. Only the spawn check moves a reader that is not a policy.
#[derive(Debug, Clone)]
struct Moved {
    reader: Reader,
    direction: Direction,
    /// Read only when it loosens.
    authors: Vec<Principal>,
}

/// The verdict from the readers that move: it loosens when any loosens, by their authors; else
/// tightens when any tightens; else it is neutral. `detail` says what it loosens, given every
/// loosened reader.
///
/// A policy that moves, either way, writes other judgments than it did; every other policy of
/// `readers` that reads its judgments (the catalog's `Reads`, which is the one owner of who reads
/// whose judgments) has its slots moved by that, in a direction that cannot be read, so it is
/// loosened too, and its author is among the authors. A temporary adjustment writes no
/// judgment, so one that moves spreads to no one. A claim gives one catalog; a change gives the
/// catalogs before and after.
fn verdict_of(
    readers: &[&Catalog],
    moved: &[Moved],
    detail: impl FnOnce(Vec<Reader>) -> FindingDetail,
) -> Verdict {
    let mut loosened: Vec<Reader> = Vec::new();
    let mut authors: Vec<Principal> = Vec::new();
    for m in moved.iter().filter(|m| m.direction == Direction::Loosens) {
        if !loosened.contains(&m.reader) {
            loosened.push(m.reader);
        }
        for author in &m.authors {
            add_author(&mut authors, author);
        }
    }
    let judging: Vec<PolicyId> = moved.iter().filter_map(|m| m.reader.policy()).collect();
    for catalog in readers {
        for (reader, reads) in catalog.reads() {
            let id = reader.id();
            if judging
                .iter()
                .any(|policy| *policy != id && reads.reads_judgments_of(*policy))
            {
                let reader_id = Reader::Policy(id);
                if !loosened.contains(&reader_id) {
                    loosened.push(reader_id);
                }
                add_author(&mut authors, reader.author());
            }
        }
    }
    if !loosened.is_empty() {
        Verdict::Loosens {
            authors,
            detail: detail(loosened),
        }
    } else if moved.iter().any(|m| m.direction == Direction::Tightens) {
        Verdict::Tightens(Confidence::Certain)
    } else {
        Verdict::Neutral
    }
}

/// How one policy takes effect differently between two points (`rule_moves`): a claim's, before
/// and after it, or a change's, under one mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleMove {
    /// Its effect goes down: a loosening.
    Lowered {
        /// The policy.
        policy: PolicyId,
        /// The authors of the bindings that carried the strength it lost.
        authors: Vec<Principal>,
    },
    /// Its effect goes up: a tightening.
    Raised {
        /// The policy.
        policy: PolicyId,
    },
    /// An exemption of it starts: a loosening.
    Exempted {
        /// The guard.
        policy: PolicyId,
        /// Its author, and the author of every binding of it, under any mode.
        authors: Vec<Principal>,
    },
    /// An exemption of it ends: a tightening.
    Unexempted {
        /// The guard.
        policy: PolicyId,
    },
    /// A binding of it is suspended by a temporary adjustment that starts: a loosening as to the
    /// binding's author, whether or not the policy goes down.
    Suspended {
        /// The policy of the binding.
        policy: PolicyId,
        /// The binding.
        binding: BindingId,
        /// The binding's author.
        authors: Vec<Principal>,
    },
}

/// One point the rules are compared at.
#[derive(Debug, Clone, Copy)]
pub(in crate::domain) enum Point<'a> {
    /// A catalog alone, under a mode, with no temporary adjustment: a point of a change of the
    /// catalog.
    Catalog {
        /// The catalog.
        catalog: &'a Catalog,
        /// The mode.
        mode: &'a Known<Option<Mode>>,
    },
    /// A state of a catalog, its temporary adjustments with it: a point of a claim.
    State {
        /// The catalog.
        catalog: &'a Catalog,
        /// The state.
        state: &'a State,
    },
}

impl<'a> Point<'a> {
    fn catalog(&self) -> &'a Catalog {
        match *self {
            Self::Catalog { catalog, .. } | Self::State { catalog, .. } => catalog,
        }
    }

    fn mode(&self) -> &'a Known<Option<Mode>> {
        match *self {
            Self::Catalog { mode, .. } => mode,
            Self::State { state, .. } => state.mode(),
        }
    }

    /// What takes effect with `bindings`, this point's [`Point::bindings`]: [`Catalog::effective`]
    /// for a catalog alone, and [`Catalog::effective_in`] for a state.
    fn effective(&self, bindings: &[InEffect<'_>]) -> Effective<'a> {
        match *self {
            Self::Catalog { catalog, mode } => catalog.effective_with(bindings, mode),
            Self::State { catalog, state } => catalog.effective_in_with(bindings, state),
        }
    }

    /// The bindings in effect, permanent and temporary, each with its author. Made once per
    /// point, and read for the effect and for the authors of a lowering.
    fn bindings(&self) -> Vec<InEffect<'a>> {
        match *self {
            Self::Catalog { catalog, .. } => catalog.bindings().map(InEffect::of).collect(),
            Self::State { catalog, state } => catalog.bindings_in(state),
        }
    }

    /// The temporary adjustments in effect: none for a catalog alone.
    fn held(&self) -> &'a [HeldAdjustment] {
        match *self {
            Self::Catalog { .. } => &[],
            Self::State { state, .. } => state.adjustments(),
        }
    }

    /// What the adjustment in effect with the id does, as it is read
    /// ([`HeldAdjustment::effect`]); none when no adjustment has the id, and for a catalog alone.
    fn effect_of(&self, id: AdjustmentId) -> Option<HeldEffect<'a>> {
        self.held()
            .iter()
            .find(|held| held.adjustment.id == id)
            .map(HeldAdjustment::effect)
    }
}

/// How the rules move from `before` to `after`, policy by policy: the one answer, read by
/// [`RuleCheck`] and by [`Catalog::change`]. See the module doc for the authors of each move. A
/// policy missing from either catalog is not compared; its removal or addition is a question of
/// its own.
pub(in crate::domain) fn rule_moves(before: &Point<'_>, after: &Point<'_>) -> Vec<RuleMove> {
    let carried = before.bindings();
    let from = before.effective(&carried);
    let to = after.effective(&after.bindings());
    let mut moves = Vec::new();
    for down in lowered(&from, &to) {
        let mut authors = Vec::new();
        for b in carried.iter().filter(|b| {
            b.policy == down.policy
                && b.mode.holds(before.mode()) != Truth::False
                && Effect::On(b.level) > down.after
        }) {
            add_author(&mut authors, b.author);
        }
        moves.push(RuleMove::Lowered {
            policy: down.policy,
            authors,
        });
    }
    for up in lowered(&to, &from) {
        moves.push(RuleMove::Raised { policy: up.policy });
    }
    // The adjustments are told apart by their ids, which are unique among those in effect, and
    // each is read as `HeldAdjustment::effect` says: one that may have ended exempts and
    // suspends nothing. So an exemption or a suspension starts where it is in effect after and
    // was not before, and an exemption ends where it was in effect before and is not after.
    for started in after.held() {
        let effect = started.effect();
        let was = before.effect_of(started.adjustment.id);
        if let Some((guard, _)) = effect.exemption
            && was.and_then(|was| was.exemption).is_none()
        {
            moves.push(RuleMove::Exempted {
                policy: guard,
                authors: exemption_authors(after.catalog(), guard),
            });
        }
        for id in effect
            .suspended
            .iter()
            .filter(|id| was.is_none_or(|was| !was.suspended.contains(id)))
        {
            if let Some(b) = after.catalog().graph().binding(*id) {
                moves.push(RuleMove::Suspended {
                    policy: b.policy,
                    binding: b.id,
                    authors: vec![b.author.clone()],
                });
            }
        }
    }
    for ended in before.held() {
        if let Some((guard, _)) = ended.effect().exemption
            && after
                .effect_of(ended.adjustment.id)
                .and_then(|now| now.exemption)
                .is_none()
        {
            moves.push(RuleMove::Unexempted { policy: guard });
        }
    }
    moves
}

/// Who an exemption of `guard` asks: the guard's author, and the author of every binding of it in
/// the catalog, whatever its mode scope. A temporary binding of it is by the guard's author or
/// one below it ([`crate::domain::authority::Authority::within`]), so whoever covers the guard's
/// author covers that one too.
fn exemption_authors(catalog: &Catalog, guard: PolicyId) -> Vec<Principal> {
    let mut authors = authors_of(catalog, &[guard]);
    for b in catalog.bindings().filter(|b| b.policy == guard) {
        add_author(&mut authors, &b.author);
    }
    authors
}

/// The verdict of the rule moves, with every other policy of `readers` that reads the judgments
/// of a policy that moves ([`verdict_of`]). Read by [`RuleCheck`] and by [`Catalog::change`].
pub(in crate::domain) fn rules_verdict(readers: &[&Catalog], moves: Vec<RuleMove>) -> Verdict {
    let moved: Vec<Moved> = moves
        .iter()
        .map(|m| match m {
            RuleMove::Lowered { policy, authors }
            | RuleMove::Exempted { policy, authors }
            | RuleMove::Suspended {
                policy, authors, ..
            } => Moved {
                reader: Reader::Policy(*policy),
                direction: Direction::Loosens,
                authors: authors.clone(),
            },
            RuleMove::Raised { policy } | RuleMove::Unexempted { policy } => Moved {
                reader: Reader::Policy(*policy),
                direction: Direction::Tightens,
                authors: Vec::new(),
            },
        })
        .collect();
    verdict_of(readers, &moved, |loosened| {
        let reading = loosened
            .into_iter()
            .filter(|r| {
                !moved
                    .iter()
                    .any(|m| m.reader == *r && m.direction == Direction::Loosens)
            })
            .filter_map(Reader::policy)
            .collect();
        FindingDetail::Rules { moves, reading }
    })
}

/// How the rules take effect, before and after the claim: each policy's effect
/// ([`Catalog::effective_in`]), the bindings suspended and the exemptions in effect, read from the
/// whole state by `rule_moves`, once per claim, whatever moved them. No finding when nothing
/// moves.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleCheck;

impl AdjustmentCheck for RuleCheck {
    fn judge(&self, input: &TxInput<'_>) -> Vec<CheckFinding> {
        // The state after, as the next event finds it: an adjustment that lasts within a scope the
        // claim closes ends with the claim, so its end is the claim's result. Read where
        // `TxInput::effective_after` reads it.
        let ended = input.after_as_found();
        let (was, is) = (input.before, &*ended);
        // One catalog: the rules move only with the mode or the temporary adjustments. Most
        // claims, a record of a judgment among them, move neither, and need no catalog computed.
        // An adjustment that comes to be possibly ended moves the rules as one that ends would.
        let same_adjustments = was
            .adjustments()
            .iter()
            .map(|h| (h.adjustment.id, h.holding))
            .eq(is
                .adjustments()
                .iter()
                .map(|h| (h.adjustment.id, h.holding)));
        if was.mode() == is.mode()
            && was.may_hold_unseen() == is.may_hold_unseen()
            && same_adjustments
        {
            return Vec::new();
        }
        let point = |state| Point::State {
            catalog: input.catalog,
            state,
        };
        let (before, after) = (point(was), point(is));
        let moves = rule_moves(&before, &after);
        if moves.is_empty() {
            return Vec::new();
        }
        vec![finding("rules", rules_verdict(&[input.catalog], moves))]
    }
}

/// A change of the mode, by who reads the modes with `ModeIs`. How the strength of the policies
/// moves with it is [`RuleCheck`]'s; the mode's scope starting again is a change of its slots,
/// which [`SlotCheck`] sees.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModeCheck;

impl AdjustmentCheck for ModeCheck {
    fn judge(&self, input: &TxInput<'_>) -> Vec<CheckFinding> {
        input
            .changes
            .iter()
            .filter_map(|change| match change {
                StateChange::Mode { before, after } => Some(mode_verdict(input, before, after)),
                StateChange::Slot(_)
                | StateChange::AdjustmentAdded(_)
                | StateChange::AdjustmentEnded(_)
                | StateChange::ActorAdded { .. } => None,
            })
            .map(|verdict| finding("mode", verdict))
            .collect()
    }
}

/// How the mode `read` moved from `before` to `after`, by whether "the mode is `read`" holds
/// ([`ModeScope::holds`]). What is not known is never "stays".
fn mode_move(read: &Mode, before: &Known<Option<Mode>>, after: &Known<Option<Mode>>) -> Move {
    let is = ModeScope::In(read.clone());
    match (is.holds(before), is.holds(after)) {
        (_, Truth::Unknown) | (Truth::True | Truth::Unknown, Truth::False) => Move::Leaves,
        (Truth::False | Truth::Unknown, Truth::True) => Move::Enters,
        (Truth::True, Truth::True) | (Truth::False, Truth::False) => Move::Stays,
    }
}

fn mode_verdict(
    input: &TxInput<'_>,
    before: &Known<Option<Mode>>,
    after: &Known<Option<Mode>>,
) -> Verdict {
    let catalog = input.catalog;
    let moved: Vec<Moved> = catalog
        .reads()
        .filter_map(|(policy, reads)| {
            let moves: Vec<(Move, Reading)> = reads
                .modes()
                .iter()
                .map(|(mode, how)| (mode_move(mode, before, after), *how))
                .collect();
            direction(&moves).map(|direction| Moved {
                reader: Reader::Policy(policy.id()),
                direction,
                authors: vec![policy.author().clone()],
            })
        })
        .collect();
    verdict_of(&[catalog], &moved, |loosened| FindingDetail::Mode {
        reading: loosened.into_iter().filter_map(Reader::policy).collect(),
    })
}

/// A slot that changes, its value or whether its scope closes: which way that moves the rules
/// that read it cannot be read, so it loosens, by the authors of those rules.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlotCheck;

impl AdjustmentCheck for SlotCheck {
    fn judge(&self, input: &TxInput<'_>) -> Vec<CheckFinding> {
        input
            .changes
            .iter()
            .filter_map(|change| match change {
                StateChange::Slot(slot) => {
                    let reading: Vec<PolicyId> = input
                        .catalog
                        .reads()
                        .filter(|(_, reads)| reads.reads_slot(*slot))
                        .map(|(policy, _)| policy.id())
                        .collect();
                    Some(Verdict::Loosens {
                        authors: authors_of(input.catalog, &reading),
                        detail: FindingDetail::Slot {
                            slot: *slot,
                            reading,
                        },
                    })
                }
                StateChange::Mode { .. }
                | StateChange::AdjustmentAdded(_)
                | StateChange::AdjustmentEnded(_)
                | StateChange::ActorAdded { .. } => None,
            })
            .map(|verdict| finding("slot", verdict))
            .collect()
    }
}

/// A child placed in the hierarchy of actors, by where it is put against a place directly under
/// its spawner, and by how the policies read the actor. See the module doc.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpawnCheck;

impl AdjustmentCheck for SpawnCheck {
    fn judge(&self, input: &TxInput<'_>) -> Vec<CheckFinding> {
        input
            .changes
            .iter()
            .filter_map(|change| match change {
                StateChange::ActorAdded { child, under } => {
                    Some(spawn_verdict(input, child, under))
                }
                StateChange::Slot(_)
                | StateChange::Mode { .. }
                | StateChange::AdjustmentAdded(_)
                | StateChange::AdjustmentEnded(_) => None,
            })
            .map(|verdict| finding("spawn", verdict))
            .collect()
    }
}

/// The move as to `principal`, from the ancestors of the child in the spawner's place and in the
/// new one: entered when the child is under it in the new place and not in the spawner's, left
/// when it was in the spawner's and is not in the new one, or may have been (the spawner's place
/// is not whole), or nothing of the difference is known (the new place is not). What is not known
/// is never "stays".
fn movement(spawner: &Ancestry, placed: &Ancestry, principal: &Principal) -> Move {
    let compare = |was: &[Principal], now: &[Principal]| match (
        was.contains(principal),
        now.contains(principal),
    ) {
        (false, true) => Move::Enters,
        (true, false) => Move::Leaves,
        (true, true) | (false, false) => Move::Stays,
    };
    match (spawner, placed) {
        // Both walks stopped at the same leaf of unknown place (a leaf placing a child under
        // itself, or under one below it): what is above that leaf is the same in both places,
        // and no principal above it was passed below it, so the passed ones tell the difference.
        (Ancestry::Unknown { known: was }, Ancestry::Unknown { known: now })
            if was.last() == now.last() =>
        {
            compare(was, now)
        }
        (_, Ancestry::Unknown { .. }) => Move::Leaves,
        (Ancestry::Known(was), Ancestry::Known(now)) => compare(was, now),
        (Ancestry::Unknown { known }, Ancestry::Known(now)) => {
            if !now.contains(principal) {
                Move::Leaves
            } else if known.contains(principal) {
                Move::Stays
            } else {
                Move::Enters
            }
        }
    }
}

/// One reader of the hierarchy of actors: who it is, the principals it reads with the direction
/// it reads each in, and the one a loosening of it asks.
struct ActorReading<'a> {
    reader: Reader,
    actors: Vec<(&'a Principal, Reading)>,
    author: &'a Principal,
}

/// Every reader of the hierarchy of actors in `state` of `catalog`: the one place that collects
/// what a spawn can move. Each policy reads what its `Reads` says (`ActorUnder` and every
/// `By::Under` of its selectors and scopes), by its author; each temporary adjustment in effect
/// reads what its lifetime reads ([`crate::domain::adjust::Lifetime`]), by the one who made it
/// ([`HeldAdjustment::by`]). A reader that reads no principal is left out.
fn actor_readings<'a>(catalog: &'a Catalog, state: &'a State) -> Vec<ActorReading<'a>> {
    let policies = catalog.reads().map(|(policy, reads)| ActorReading {
        reader: Reader::Policy(policy.id()),
        actors: reads.actors().iter().map(|(p, r)| (p, *r)).collect(),
        author: policy.author(),
    });
    let held = state.adjustments().iter().map(|held| ActorReading {
        reader: Reader::Adjustment(held.adjustment.id),
        actors: held.adjustment.lifetime.reading().into_iter().collect(),
        author: &held.by,
    });
    policies
        .chain(held)
        .filter(|reading| !reading.actors.is_empty())
        .collect()
}

fn spawn_verdict(input: &TxInput<'_>, child: &Principal, under: &Principal) -> Verdict {
    let catalog = input.catalog;
    let authority = catalog.authority();
    // The walk of both places is on the state before the spawn: `by` and `under` are in it, and
    // the child, which is not, is in neither.
    let actors = input.before.actors();
    let spawner = actors.ancestry(&input.event.by, authority);
    let placed = actors.ancestry(under, authority);
    let moved: Vec<Moved> = actor_readings(catalog, input.before)
        .into_iter()
        .filter_map(|reading| {
            let moves: Vec<(Move, Reading)> = reading
                .actors
                .iter()
                .map(|(principal, how)| (movement(&spawner, &placed, principal), *how))
                .collect();
            direction(&moves).map(|direction| Moved {
                reader: reading.reader,
                direction,
                authors: vec![reading.author.clone()],
            })
        })
        .collect();
    verdict_of(&[catalog], &moved, |loosened| FindingDetail::Spawn {
        child: child.clone(),
        under: under.clone(),
        loosened,
    })
}

/// All must agree. A finding that tightens, or leaves the rules as they are, agrees; one that
/// loosens agrees when its authors are covered, which is the floor's to judge, not a
/// combination's. So this combination adds nothing to the floor: a claim commits exactly when
/// every loosening finding is covered. It is the combination of [`super::TxPolicy::standard`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AllOk;

impl Combine for AllOk {
    fn combine(&self, _findings: &[CheckFinding]) -> TxDecision {
        TxDecision::Commit
    }
}
