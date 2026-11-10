//! The domain's own points of view on a claim, and the default way to combine findings.
//!
//! ```text
//! check            looks at                 finds                                   authors
//! ExemptionCheck   ExemptionAdded(g)        loosens (the guard is lifted)           g's
//!                  ExemptionEnded(_)        tightens
//! ModeCheck        Mode { before, after }   loosens when a policy goes down, or     each lowered, and each
//!                                           when a policy reads either mode (such   policy reading a mode
//!                                           a rule's direction cannot be read);     before or after (any
//!                                           else tightens or neutral                mode, if one is unknown)
//! SlotCheck        Slot(s)                  loosens: a slot's direction cannot      each policy reading s
//!                                           be read
//! SpawnCheck       ActorAdded { child,      loosens when a policy that reads the    each such policy
//!                  under }                  actor sees the child leave a principal,
//!                                           or move where its direction cannot be
//!                                           told; tightens when every move is into
//!                                           a principal read as "applies inside";
//!                                           else neutral
//! ```
//!
//! Each [`StateChange`] is looked at by one check only, and all four are applied to every claim
//! ([`super::TxPolicy`] cannot leave one out). What a policy reads, a slot, a mode or an actor, is
//! the catalog's one value of it, the same one [`Catalog::accept`] checks references with. The
//! effects that go down are [`lowered`]'s answer. A check names the authors; whether the claim's
//! author may loosen their rules is the floor's question, not the check's.
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
//! A policy that applies inside a principal (the principal in its guard's `when`, under no `not`)
//! is tightened by a child that enters it and loosened by one that leaves it. Any other reading
//! of the principal (under a `not`, in a guard's `rule`, in a reward) cannot be told to move
//! either way, so entering and leaving both loosen.
//!
//! What is not known is never taken for "not left". When the spawner is not whole in the
//! hierarchy (an actor it does not know, a leaf of unknown place), the principals the walk passed
//! are all that is known of its place: those the new place has beyond them are entered, and every
//! principal the new place lacks may have been left. When the new place is not known, nothing of
//! the difference is, and every policy that reads the actor is loosened, except where both walks
//! stop at the same leaf (a leaf of unknown place that places a child under itself): what is
//! above that leaf is the same in both, so the principals passed below it tell the difference.

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

fn mode_verdict(
    input: &TxInput<'_>,
    before: &Known<Option<Mode>>,
    after: &Known<Option<Mode>>,
) -> Verdict {
    let catalog = input.catalog;
    let (from, to) = (catalog.effective(before), catalog.effective(after));
    let down = lowered(&from, &to);
    let unknown = matches!(before, Known::Unknown) || matches!(after, Known::Unknown);
    let named: Vec<&Mode> = [before, after]
        .into_iter()
        .filter_map(|mode| match mode {
            Known::Known(Some(mode)) => Some(mode),
            Known::Known(None) | Known::Unknown => None,
        })
        .collect();
    let reading: Vec<PolicyId> = catalog
        .reads()
        .filter(|(_, reads)| {
            if unknown {
                !reads.modes().is_empty()
            } else {
                reads.modes().iter().any(|mode| named.contains(&mode))
            }
        })
        .map(|(policy, _)| policy.id())
        .collect();
    if down.is_empty() && reading.is_empty() {
        return if lowered(&to, &from).is_empty() {
            Verdict::Neutral
        } else {
            Verdict::Tightens(Confidence::Certain)
        };
    }
    let mut policies: Vec<PolicyId> = down.iter().map(|l| l.policy).collect();
    policies.extend(reading.iter().copied());
    Verdict::Loosens {
        authors: authors_of(catalog, &policies),
        detail: FindingDetail::Mode {
            lowered: down,
            reading,
        },
    }
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

/// How the new place differs from the one directly under the spawner, as to one principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Move {
    /// The child is under it in both places, or in neither.
    Stays,
    /// The child is under it in the new place and not in the spawner's.
    Enters,
    /// The child was under it in the spawner's place and is not in the new one, or may have been
    /// (the spawner's place is not whole), or nothing of the difference is known (the new place
    /// is not).
    Leaves,
}

/// The move as to `principal`, from the ancestors of the child in the spawner's place and in the
/// new one. What is not known is never "stays".
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
    let (mut loosened, mut tightened) = (Vec::new(), Vec::new());
    for (policy, reads) in catalog.reads() {
        let moves: Vec<(Move, Reading)> = reads
            .actors()
            .iter()
            .map(|(principal, reading)| (movement(&spawner, &placed, principal), *reading))
            .collect();
        let loosens = |&(shift, reading): &(Move, Reading)| match (shift, reading) {
            (Move::Leaves, _) | (Move::Enters, Reading::Unreadable) => true,
            (Move::Enters, Reading::Positive) | (Move::Stays, _) => false,
        };
        if moves.iter().any(loosens) {
            loosened.push(policy.id());
        } else if moves.iter().any(|(shift, _)| *shift == Move::Enters) {
            tightened.push(policy.id());
        }
    }
    if !loosened.is_empty() {
        Verdict::Loosens {
            authors: authors_of(catalog, &loosened),
            detail: FindingDetail::Spawn {
                child: child.clone(),
                under: under.clone(),
                loosened,
            },
        }
    } else if !tightened.is_empty() {
        Verdict::Tightens(Confidence::Certain)
    } else {
        Verdict::Neutral
    }
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
