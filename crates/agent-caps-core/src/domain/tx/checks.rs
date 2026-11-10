//! The domain's own points of view on a claim, and the default way to combine findings.
//!
//! ```text
//! check        looks at                     finds                                   authors
//! RuleCheck    the whole state before and   loosens when a policy's effect goes     of a lowered policy, the
//!              after: each policy's effect  down or an exemption of it starts;      bindings that carried what
//!              (Catalog::effective) and     tightens when one goes up or an         was lowered; of an exempted
//!              the exemptions in effect     exemption ends (rule_moves)             one, its author and every
//!                                                                                   binding's, under any mode
//! ModeCheck    Mode { before, after }       loosens when a policy that reads a      each policy that loosens
//!                                           mode with ModeIs sees it left, or
//!                                           entered where its direction cannot
//!                                           be read; tightens when every read
//!                                           mode entered is read as "applies
//!                                           inside"; else neutral
//! SlotCheck    Slot(s)                      loosens: a slot's direction cannot      each policy reading s
//!                                           be read
//! SpawnCheck   ActorAdded { child,          loosens when a policy that reads the    each such policy
//!              under }                      actor sees the child leave a
//!                                           principal, or move where its
//!                                           direction cannot be told; tightens
//!                                           when every move is into a principal
//!                                           read as "applies inside"; else neutral
//! RuleCheck, ModeCheck and SpawnCheck also loosen every other policy that reads the judgments of
//! a policy they move, either way, by that reader's author (`verdict_of`).
//! ```
//!
//! The move of a state atom is looked at by one check: [`ModeCheck`] the mode as rules read it
//! with `ModeIs`, [`SlotCheck`] a slot, [`SpawnCheck`] the actor. How the rules take effect, the
//! strength of each policy and the exemptions in effect, is [`RuleCheck`]'s, which compares the
//! whole state before and after, once per claim, whichever [`StateChange`] moved it (a mode switch,
//! an exemption added or ended). All four are applied to every claim ([`super::TxPolicy`] cannot
//! leave one out). What a policy reads, a slot, a mode or an actor, is the catalog's one value of
//! it, the same one [`Catalog::accept`] checks references with. A check names the authors;
//! whether the claim's author may loosen their rules is the floor's question, not the check's.
//!
//! # How the rules move
//!
//! `rule_moves` is the one answer to how the rules take effect differently between two points,
//! each a catalog, a mode and the exemptions in effect. [`RuleCheck`] reads it for a claim (one
//! catalog, the state before and after), and [`Catalog::change`] reads it for a change of the
//! catalog (two catalogs, under each compared mode, with no exemption).
//!
//! - A policy goes down when its effect ([`Catalog::effective`], by the order of
//!   [`Effect`]) is lower after than before. The authors asked are
//!   those of the bindings, in the catalog before, that held or may have held before
//!   ([`ModeScope::holds`] not false) and are stronger than the effect after: the bindings that
//!   carried the strength that was lost, and no others.
//! - An exemption starts for each one held after and not before, counted one by one, so an
//!   exemption beside a narrower one of the same guard is still one that starts. The authors
//!   asked are the guard's author and the author of every binding of it, under any mode: an
//!   exemption reaches the guard whatever the mode becomes, so one placed while the guard is off
//!   under the mode still needs those whose bindings turn it on elsewhere.
//! - A policy that goes up, and an exemption that ends, tighten.
//!
//! A mode that is not known is the strongest side by [`Catalog::effective`] alone, so not knowing
//! it is never a way to loosen a rule.
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
//! one place that walks them; the child itself is in both, so it is in neither difference. A
//! principal that a policy reads `ActorUnder` of is
//!
//! - entered, when the new place has it and the spawner's does not,
//! - left, when the spawner's place has it and the new one does not.
//!
//! When the spawner is not whole in the hierarchy (an actor it does not know, a leaf of unknown
//! place), the principals the walk passed are all that is known of its place: those the new place
//! has beyond them are entered, and every principal the new place lacks may have been left. When
//! the new place is not known, nothing of the difference is, and every policy that reads the
//! actor is loosened, except where both walks stop at the same leaf (a leaf of unknown place that
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

use super::{AdjustmentCheck, CheckFinding, CheckName, Combine, Confidence, FindingDetail};
use super::{TxDecision, TxInput, Verdict};
use crate::domain::authority::Principal;
use crate::domain::catalog::{Catalog, Effect, lowered};
use crate::domain::exempt::Exempt;
use crate::domain::name::{Mode, PolicyId};
use crate::domain::policy::ModeScope;
use crate::domain::predicate::{Reading, Truth};
use crate::domain::state::{Ancestry, Known, State, StateChange};

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

/// One policy that a claim or a change moves, the way it moves, and the authors a loosening asks.
#[derive(Debug, Clone)]
struct Moved {
    policy: PolicyId,
    direction: Direction,
    /// Read only when it loosens.
    authors: Vec<Principal>,
}

/// The verdict from the policies that move: it loosens when any loosens, by their authors; else
/// tightens when any tightens; else it is neutral. `detail` says what it loosens, given every
/// loosened policy.
///
/// A policy that moves, either way, writes other judgments than it did; every other policy of
/// `readers` that reads its judgments (the catalog's `Reads`, which is the one owner of who reads
/// whose judgments) has its slots moved by that, in a direction that cannot be read, so it is
/// loosened too, and its author is among the authors. A claim gives one catalog; a change gives
/// the catalogs before and after.
fn verdict_of(
    readers: &[&Catalog],
    moved: &[Moved],
    detail: impl FnOnce(Vec<PolicyId>) -> FindingDetail,
) -> Verdict {
    let mut loosened: Vec<PolicyId> = Vec::new();
    let mut authors: Vec<Principal> = Vec::new();
    for m in moved.iter().filter(|m| m.direction == Direction::Loosens) {
        if !loosened.contains(&m.policy) {
            loosened.push(m.policy);
        }
        for author in &m.authors {
            add_author(&mut authors, author);
        }
    }
    for catalog in readers {
        for (reader, reads) in catalog.reads() {
            let id = reader.id();
            if moved
                .iter()
                .any(|m| m.policy != id && reads.reads_judgments_of(m.policy))
            {
                if !loosened.contains(&id) {
                    loosened.push(id);
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
}

/// One point the rules are compared at: a catalog, the mode, and the exemptions in effect, each
/// one as many times as it is held.
#[derive(Debug, Clone, Copy)]
pub(in crate::domain) struct Point<'a> {
    /// The catalog.
    pub(in crate::domain) catalog: &'a Catalog,
    /// The mode in effect.
    pub(in crate::domain) mode: &'a Known<Option<Mode>>,
    /// The exemptions in effect.
    pub(in crate::domain) exemptions: &'a [Exempt],
}

impl<'a> Point<'a> {
    /// The point of a state of `catalog`.
    fn of(catalog: &'a Catalog, state: &'a State) -> Self {
        Self {
            catalog,
            mode: state.mode(),
            exemptions: state.exemptions(),
        }
    }
}

/// How the rules move from `before` to `after`, policy by policy: the one answer, read by
/// [`RuleCheck`] and by [`Catalog::change`]. See the module doc for the authors of each move. A
/// policy missing from either catalog is not compared; its removal or addition is a question of
/// its own.
pub(in crate::domain) fn rule_moves(before: &Point<'_>, after: &Point<'_>) -> Vec<RuleMove> {
    let from = before.catalog.effective(before.mode);
    let to = after.catalog.effective(after.mode);
    let mut moves = Vec::new();
    for down in lowered(&from, &to) {
        let mut authors = Vec::new();
        for b in before.catalog.bindings().iter().filter(|b| {
            b.policy == down.policy
                && b.mode.holds(before.mode) != Truth::False
                && Effect::On(b.level) > down.after
        }) {
            add_author(&mut authors, &b.author);
        }
        moves.push(RuleMove::Lowered {
            policy: down.policy,
            authors,
        });
    }
    for up in lowered(&to, &from) {
        moves.push(RuleMove::Raised { policy: up.policy });
    }
    let mut remaining: Vec<&Exempt> = before.exemptions.iter().collect();
    for exempt in after.exemptions {
        match remaining.iter().position(|kept| *kept == exempt) {
            Some(at) => {
                remaining.remove(at);
            }
            None => moves.push(RuleMove::Exempted {
                policy: exempt.guard,
                authors: exemption_authors(after.catalog, exempt.guard),
            }),
        }
    }
    for ended in remaining {
        moves.push(RuleMove::Unexempted {
            policy: ended.guard,
        });
    }
    moves
}

/// Who an exemption of `guard` asks: the guard's author, and the author of every binding of it,
/// whatever its mode scope.
fn exemption_authors(catalog: &Catalog, guard: PolicyId) -> Vec<Principal> {
    let mut authors = authors_of(catalog, &[guard]);
    for b in catalog.bindings().iter().filter(|b| b.policy == guard) {
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
            RuleMove::Lowered { policy, authors } | RuleMove::Exempted { policy, authors } => {
                Moved {
                    policy: *policy,
                    direction: Direction::Loosens,
                    authors: authors.clone(),
                }
            }
            RuleMove::Raised { policy } | RuleMove::Unexempted { policy } => Moved {
                policy: *policy,
                direction: Direction::Tightens,
                authors: Vec::new(),
            },
        })
        .collect();
    verdict_of(readers, &moved, |loosened| {
        let reading = loosened
            .into_iter()
            .filter(|p| {
                !moved
                    .iter()
                    .any(|m| m.policy == *p && m.direction == Direction::Loosens)
            })
            .collect();
        FindingDetail::Rules { moves, reading }
    })
}

/// How the rules take effect, before and after the claim: each policy's effect and the exemptions
/// in effect, read from the whole state by `rule_moves`, once per claim, whatever moved them.
/// No finding when nothing moves.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleCheck;

impl AdjustmentCheck for RuleCheck {
    fn judge(&self, input: &TxInput<'_>) -> Vec<CheckFinding> {
        let before = Point::of(input.catalog, input.before);
        let after = Point::of(input.catalog, input.after);
        // One catalog: the rules move only with the mode or the exemptions. Most claims, a record
        // of a judgment among them, move neither, and need no catalog computed.
        if before.mode == after.mode && before.exemptions == after.exemptions {
            return Vec::new();
        }
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
                | StateChange::ExemptionAdded(_)
                | StateChange::ExemptionEnded(_)
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
                policy: policy.id(),
                direction,
                authors: vec![policy.author().clone()],
            })
        })
        .collect();
    verdict_of(&[catalog], &moved, |reading| FindingDetail::Mode {
        reading,
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
                | StateChange::ExemptionAdded(_)
                | StateChange::ExemptionEnded(_)
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
                | StateChange::ExemptionAdded(_)
                | StateChange::ExemptionEnded(_) => None,
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

fn spawn_verdict(input: &TxInput<'_>, child: &Principal, under: &Principal) -> Verdict {
    let catalog = input.catalog;
    let authority = catalog.authority();
    // The walk of both places is on the state before the spawn: `by` and `under` are in it, and
    // the child, which is not, is in neither.
    let actors = input.before.actors();
    let spawner = actors.ancestry(&input.event.by, authority);
    let placed = actors.ancestry(under, authority);
    let moved: Vec<Moved> = catalog
        .reads()
        .filter_map(|(policy, reads)| {
            let moves: Vec<(Move, Reading)> = reads
                .actors()
                .iter()
                .map(|(principal, reading)| (movement(&spawner, &placed, principal), *reading))
                .collect();
            direction(&moves).map(|direction| Moved {
                policy: policy.id(),
                direction,
                authors: vec![policy.author().clone()],
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
