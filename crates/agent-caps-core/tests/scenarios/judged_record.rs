//! Scenario: a record of a judgment counts only in the name of the judged policy's author. The
//! record of a judgment is written in that name ([`Outcome::evidence`]), so a record in another
//! name, or of a policy the catalog does not hold, is no judgment any of its rules made: it is not
//! admitted, whether or not a rule reads it, and so nothing that keeps or counts the records takes
//! it in.
//!
//! [`Outcome::evidence`]: agent_caps_core::domain::judge::Outcome::evidence

use agent_caps_core::domain::adjust::Inadmissible;
use agent_caps_core::domain::authority::Principal;
use agent_caps_core::domain::catalog::Catalog;
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::policy::Level;
use agent_caps_core::domain::schema::Judgment;
use agent_caps_core::domain::state::Origin;
use agent_caps_core::domain::tx::{TxDecision, TxPolicy, TxReport};

use super::common::{GUARD, OTHER, at, catalog, id, test_guard, the_agent, the_user};

/// The scenarios' guard, by the user.
fn guarded() -> Catalog {
    catalog(vec![test_guard(Level::Advise)], vec![])
}

/// The record of a judgment of `policy`, in the name of `by`.
fn judged(by: Principal, policy: &str) -> Event {
    at(
        by,
        0,
        Body::Judged {
            policy: id(policy),
            judgment: Judgment::Allowed,
            written: Level::Advise,
            enforced: Level::Advise,
        },
    )
}

fn admit(catalog: &Catalog, event: &Event) -> TxReport {
    catalog
        .admit(
            &catalog.fold(Origin::Genesis, []),
            event,
            &TxPolicy::standard(),
        )
        .unwrap()
}

/// FR59: a record in the name of the judged policy's author is admitted.
#[test]
fn a_record_in_its_authors_name_is_admitted() {
    let report = admit(&guarded(), &judged(the_user(), GUARD));
    assert_eq!(report.decision, TxDecision::Commit);
    assert_eq!(report.inadmissible, None);
}

/// FR59: a record in another's name is not admitted, even where no rule reads it.
#[test]
fn a_record_in_another_name_is_not_admitted() {
    let report = admit(&guarded(), &judged(the_agent(), GUARD));
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.inadmissible,
        Some(Inadmissible::NotTheAuthor {
            policy: id(GUARD),
            author: the_user(),
            by: the_agent(),
        })
    );
}

/// FR59: a record of a policy the catalog does not hold is not admitted.
#[test]
fn a_record_of_a_policy_the_catalog_has_not_is_not_admitted() {
    let report = admit(&guarded(), &judged(the_user(), OTHER));
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.inadmissible,
        Some(Inadmissible::UnknownPolicy(id(OTHER)))
    );
}
