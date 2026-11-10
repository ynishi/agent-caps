//! The domain's own points of view on a claim, and the default way to combine findings.
//!
//! ```text
//! check            looks at                 finds                                   authors
//! ExemptionCheck   ExemptionAdded(g)        loosens (the guard is lifted)           g's
//!                  ExemptionEnded(_)        tightens
//! ModeCheck        Mode { before, after }   loosens when a policy goes down, or     each policy that
//!                                           when a policy that reads a mode sees    loosens
//!                                           it left, or entered where its
//!                                           direction cannot be read, or reads the
//!                                           judgments of one that applies to more;
//!                                           tightens when a policy goes up, or when
//!                                           every read mode entered is read as
//!                                           "applies inside"; else neutral
//! SlotCheck        Slot(s)                  loosens: a slot's direction cannot      each policy reading s
//!                                           be read
//! SpawnCheck       ActorAdded { child,      loosens when a policy that reads the    each such policy
//!                  under }                  actor sees the child leave a principal,
//!                                           or move where its direction cannot be
//!                                           told, or reads the judgments of one
//!                                           that applies to more; tightens when
//!                                           every move is into a principal read
//!                                           as "applies inside"; else neutral
//! ```
//!
//! Each [`StateChange`] is looked at by one check only, and all four are applied to every claim
//! ([`super::TxPolicy`] cannot leave one out). What a policy reads, a slot, a mode or an actor, is
//! the catalog's one value of it, the same one [`Catalog::accept`] checks references with. The
//! effects that go down are [`lowered`]'s answer. A check names the authors; whether the claim's
//! author may loosen their rules is the floor's question, not the check's.
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
//! # What a policy that applies to more writes
//!
//! A policy that is tightened by a claim applies to more events, and so writes more judgments
//! than it did, in its author's name, which always count. Every other policy that reads its
//! judgments (a filter that names it, or that narrows to none and sees it) has the slots it reads
//! moved by that, in a direction that cannot be read: it counts more, or a later record
//! replaces the last. So such a policy is loosened by the claim, and its author is among the
//! authors the floor asks, as for a policy loosened by the atom itself. The tightened policy
//! itself stays tightened. This is the same for a mode and for a spawn, and `verdict_of` is
//! where it is decided; who reads whose judgments is the catalog's (`Reads`), not found again
//! here.
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
//! A mode switch moves each mode a policy reads with `ModeIs` by what the mode was and is:
//!
//! | before | after | the mode `m` |
//! |---|---|---|
//! | known `b` | known `a` | entered when `m` is `a` and not `b`; left when `m` is `b` and not `a`; else stays |
//! | unknown | known `a` | entered when `m` is `a` (it may have been there already, and is counted as entered: tightens a policy that applies inside it, loosens one read in a way that cannot be told); else left (it may have been `m`) |
//! | known or unknown | unknown | left (where it went is not known) |
//!
//! No mode at all is a value equal to no `m`. A policy is also loosened when its effect goes down
//! under the switch ([`lowered`]) and tightened when it goes up; for each policy the two are put
//! together by the same rule, so that either one loosening loosens it. The findings that name the
//! policies that read the mode are only those loosened by reading it.
//!
//! The polarity of the mode itself is not changed by this: a switch that tightens is open to
//! anyone, and one that loosens is the floor's. An upper rule that reads a slot of the mode's
//! scope, which moves when the mode switches, is [`SlotCheck`]'s to loosen.

use super::{AdjustmentCheck, CheckFinding, CheckName, Combine, Confidence, FindingDetail};
use super::{TxDecision, TxInput, Verdict};
use crate::domain::authority::Principal;
use crate::domain::catalog::{Catalog, lowered};
use crate::domain::name::{Mode, PolicyId};
use crate::domain::predicate::Reading;
use crate::domain::state::{Ancestry, Known, StateChange};

/// The domain's checks, in the order their findings are reported.
pub(super) fn domain() -> [&'static dyn AdjustmentCheck; 4] {
    [&ExemptionCheck, &ModeCheck, &SlotCheck, &SpawnCheck]
}

/// The authors of `policies`, each once.
fn authors_of(catalog: &Catalog, policies: &[PolicyId]) -> Vec<Principal> {
    let mut authors: Vec<Principal> = Vec::new();
    for policy in policies.iter().filter_map(|id| catalog.policy(*id)) {
        if !authors.contains(policy.author()) {
            authors.push(policy.author().clone());
        }
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

/// The verdict of a claim from the direction of each policy it moves: it loosens, by the authors
/// of the loosened policies, when any loosens; else tightens when any tightens; else it is neutral.
/// `detail` says what it loosens, given the loosened policies.
///
/// A policy that is tightened applies to more events, and so writes more judgments than it did;
/// every other policy that reads its judgments (the catalog's `Reads`, which is the one owner of
/// who reads whose judgments) has its slots moved by that, in a direction that cannot be read,
/// so it is loosened too, and its author is among the authors. The tightened policy itself stays
/// tightened.
fn verdict_of(
    catalog: &Catalog,
    directions: &[(PolicyId, Option<Direction>)],
    detail: impl FnOnce(Vec<PolicyId>) -> FindingDetail,
) -> Verdict {
    let mut loosened: Vec<PolicyId> = directions
        .iter()
        .filter(|(_, direction)| *direction == Some(Direction::Loosens))
        .map(|(policy, _)| *policy)
        .collect();
    let tightened: Vec<PolicyId> = directions
        .iter()
        .filter(|(_, direction)| *direction == Some(Direction::Tightens))
        .map(|(policy, _)| *policy)
        .collect();
    for (reader, reads) in catalog.reads() {
        let id = reader.id();
        if !loosened.contains(&id)
            && tightened
                .iter()
                .any(|policy| *policy != id && reads.reads_judgments_of(*policy))
        {
            loosened.push(id);
        }
    }
    if !loosened.is_empty() {
        Verdict::Loosens {
            authors: authors_of(catalog, &loosened),
            detail: detail(loosened),
        }
    } else if !tightened.is_empty() {
        Verdict::Tightens(Confidence::Certain)
    } else {
        Verdict::Neutral
    }
}

/// An exemption added lifts its guard, so it loosens, by the guard's author; one that ends
/// tightens.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExemptionCheck;

impl AdjustmentCheck for ExemptionCheck {
    fn judge(&self, input: &TxInput<'_>) -> Vec<CheckFinding> {
        input
            .changes
            .iter()
            .filter_map(|change| match change {
                StateChange::ExemptionAdded(guard) => Some(Verdict::Loosens {
                    authors: authors_of(input.catalog, &[*guard]),
                    detail: FindingDetail::ExemptionAdded(*guard),
                }),
                StateChange::ExemptionEnded(_) => Some(Verdict::Tightens(Confidence::Certain)),
                StateChange::Slot(_)
                | StateChange::Mode { .. }
                | StateChange::ActorAdded { .. } => None,
            })
            .map(|verdict| finding("exemption", verdict))
            .collect()
    }
}

/// A change of the mode, by what the catalog comes to before and after it, and by who reads the
/// modes. The mode's scope starting again is a change of its slots, which [`SlotCheck`] sees.
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

/// How the mode `read` moved from `before` to `after`. What is not known is never "stays". No mode
/// at all is equal to no mode that is read.
fn mode_move(read: &Mode, before: &Known<Option<Mode>>, after: &Known<Option<Mode>>) -> Move {
    let is = |mode: &Option<Mode>| mode.as_ref() == Some(read);
    match (before, after) {
        (_, Known::Unknown) => Move::Leaves,
        (Known::Unknown, Known::Known(now)) => {
            if is(now) {
                Move::Enters
            } else {
                Move::Leaves
            }
        }
        (Known::Known(was), Known::Known(now)) => match (is(was), is(now)) {
            (false, true) => Move::Enters,
            (true, false) => Move::Leaves,
            (true, true) | (false, false) => Move::Stays,
        },
    }
}

/// Either one loosening loosens; else either one tightening tightens.
fn together(a: Option<Direction>, b: Option<Direction>) -> Option<Direction> {
    match (a, b) {
        (Some(Direction::Loosens), _) | (_, Some(Direction::Loosens)) => Some(Direction::Loosens),
        (Some(Direction::Tightens), _) | (_, Some(Direction::Tightens)) => {
            Some(Direction::Tightens)
        }
        (None, None) => None,
    }
}

fn mode_verdict(
    input: &TxInput<'_>,
    before: &Known<Option<Mode>>,
    after: &Known<Option<Mode>>,
) -> Verdict {
    let catalog = input.catalog;
    let (from, to) = (catalog.effective(before), catalog.effective(after));
    let down = lowered(&from, &to);
    let up = lowered(&to, &from);
    let mut directions: Vec<(PolicyId, Option<Direction>)> = Vec::new();
    let mut reading: Vec<PolicyId> = Vec::new();
    for (policy, reads) in catalog.reads() {
        let id = policy.id();
        let moves: Vec<(Move, Reading)> = reads
            .modes()
            .iter()
            .map(|(mode, how)| (mode_move(mode, before, after), *how))
            .collect();
        let read = direction(&moves);
        if read == Some(Direction::Loosens) {
            reading.push(id);
        }
        let by_effect = if down.iter().any(|l| l.policy == id) {
            Some(Direction::Loosens)
        } else if up.iter().any(|l| l.policy == id) {
            Some(Direction::Tightens)
        } else {
            None
        };
        directions.push((id, together(by_effect, read)));
    }
    verdict_of(catalog, &directions, |loosened| {
        // Those loosened for reading the judgments of a policy that applies to more are loosened
        // by what they read too.
        for policy in loosened {
            if !reading.contains(&policy) && !down.iter().any(|l| l.policy == policy) {
                reading.push(policy);
            }
        }
        FindingDetail::Mode {
            lowered: down,
            reading,
        }
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
    let directions: Vec<(PolicyId, Option<Direction>)> = catalog
        .reads()
        .map(|(policy, reads)| {
            let moves: Vec<(Move, Reading)> = reads
                .actors()
                .iter()
                .map(|(principal, reading)| (movement(&spawner, &placed, principal), *reading))
                .collect();
            (policy.id(), direction(&moves))
        })
        .collect();
    verdict_of(catalog, &directions, |loosened| FindingDetail::Spawn {
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
