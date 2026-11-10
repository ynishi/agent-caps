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
//! ```
//!
//! Each [`StateChange`] is looked at by one check only, and all three are applied to every claim
//! ([`super::TxPolicy`] cannot leave one out). What a policy reads, a slot or a mode, is the
//! catalog's one value of it, the same one [`Catalog::accept`] checks references with. The
//! effects that go down are [`lowered`]'s answer. A check names the authors; whether the claim's
//! author may loosen their rules is the floor's question, not the check's.

use super::{AdjustmentCheck, CheckFinding, CheckName, Combine, Confidence, FindingDetail};
use super::{TxDecision, TxInput, Verdict};
use crate::domain::authority::Principal;
use crate::domain::catalog::{Catalog, lowered};
use crate::domain::name::{Mode, PolicyId};
use crate::domain::state::{Known, StateChange};

/// The domain's checks, in the order their findings are reported.
pub(super) fn domain() -> [&'static dyn AdjustmentCheck; 3] {
    [&ExemptionCheck, &ModeCheck, &SlotCheck]
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
                StateChange::Slot(_) | StateChange::Mode { .. } => None,
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
                | StateChange::ExemptionEnded(_) => None,
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
                | StateChange::ExemptionEnded(_) => None,
            })
            .map(|verdict| finding("slot", verdict))
            .collect()
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
