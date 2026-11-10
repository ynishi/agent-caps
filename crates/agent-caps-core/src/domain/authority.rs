//! Who may change whose rules: a hierarchy of principals, and the one question it answers.
//!
//! The module knows nothing of policies, events or catalogs. A [`Principal`] is an opaque key; an
//! [`Authority`] says, for each principal, the one above it. [`Authority::covers`] asks whether
//! an actor is an author or sits above the author, which is what "may loosen what this author
//! wrote" comes to: a principal's work is loosened by itself and by those above it, never by
//! those beside or below it.
//!
//! [`Authority::may_loosen`] is the one question of whether something that loosens may be done:
//! a change of a catalog ([`super::change`]) and a claim in the evidence ([`super::tx`]) both ask
//! it, and nothing else in the domain decides who may do what. (A rule may read where the actor
//! sits in the hierarchy of actors, which is this hierarchy plus the leaves that spawns add, and
//! a spawn is compared with a place under its spawner; neither says who may loosen anything.)
//! Nobody asks it of what only tightens: that is open to anyone.
//!
//! ```text
//! user            root
//!  └─ agent       below the user: its work is covered by the user, the user's is not covered by it
//!      └─ helper  below the agent
//! ```
//!
//! Where principals sit is the caller's arrangement, not a rule of the domain. A person and an
//! agent, a team and its members, or a role and a member are all hierarchies; the policy side
//! only asks `covers`. The hierarchy comes in as a value, read from wherever the application
//! keeps it, and a principal that is trusted here is trusted as the hierarchy says.
//!
//! # Invariants
//!
//! - There is at least one root (a principal with no parent); there may be several, and two
//!   roots do not cover each other.
//! - Every parent is a principal of the hierarchy, and no chain of parents loops: a hierarchy
//!   with a cycle or an unknown parent is never made ([`AuthorityError`]).

use std::collections::BTreeMap;
use std::fmt;

/// An opaque key of one who writes policies. The key carries no meaning: whether it stands for
/// a person, an agent or a team is the arrangement of the [`Authority`] that holds it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal(String);

impl Principal {
    /// The principal with the key.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The key.
    pub fn key(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a hierarchy was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    /// There is no principal, so no root.
    Empty,
    /// The principal is given twice.
    Duplicate(Principal),
    /// The principal's parent is not a principal of the hierarchy.
    UnknownParent {
        /// The principal.
        principal: Principal,
        /// The parent it names.
        parent: Principal,
    },
    /// The chain of parents of the principal loops, and never reaches a root.
    Cycle(Principal),
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a hierarchy needs at least one root"),
            Self::Duplicate(p) => write!(f, "the principal {p} is given twice"),
            Self::UnknownParent { principal, parent } => {
                write!(f, "the parent {parent} of {principal} is not a principal")
            }
            Self::Cycle(p) => write!(f, "the parents of {p} loop and never reach a root"),
        }
    }
}

impl std::error::Error for AuthorityError {}

/// Why a principal may not loosen the work of some authors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotCovered {
    /// The principal is not one of the hierarchy, so it covers nobody's work.
    UnknownPrincipal(Principal),
    /// The authors the principal does not cover, each once, in the order they were given.
    Uncovered(Vec<Principal>),
}

impl fmt::Display for NotCovered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPrincipal(p) => write!(f, "{p} is not in the hierarchy"),
            Self::Uncovered(authors) => {
                f.write_str("not covered:")?;
                authors.iter().try_for_each(|a| write!(f, " {a}"))
            }
        }
    }
}

impl std::error::Error for NotCovered {}

/// Why a principal is not within the work of an owner ([`Authority::within`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotWithin {
    /// The principal is not one of the hierarchy.
    UnknownPrincipal(Principal),
    /// The principal is of the hierarchy, but neither the owner nor below it.
    NotBelow {
        /// The principal.
        principal: Principal,
        /// The owner it is not below.
        owner: Principal,
    },
}

impl fmt::Display for NotWithin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPrincipal(p) => write!(f, "{p} is not in the hierarchy"),
            Self::NotBelow { principal, owner } => {
                write!(f, "{principal} is neither {owner} nor below it")
            }
        }
    }
}

impl std::error::Error for NotWithin {}

/// A hierarchy of principals: each has at most one parent, the principal above it, and a
/// principal without one is a root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    parents: BTreeMap<Principal, Option<Principal>>,
}

impl Authority {
    /// The hierarchy of `links`, each a principal and its parent (`None` for a root), when it has
    /// a root, every parent is a principal of it, and no chain of parents loops.
    pub fn new(
        links: impl IntoIterator<Item = (Principal, Option<Principal>)>,
    ) -> Result<Self, AuthorityError> {
        let mut parents = BTreeMap::new();
        for (principal, parent) in links {
            if parents.contains_key(&principal) {
                return Err(AuthorityError::Duplicate(principal));
            }
            parents.insert(principal, parent);
        }
        if parents.is_empty() {
            return Err(AuthorityError::Empty);
        }
        for (principal, parent) in &parents {
            if let Some(parent) = parent
                && !parents.contains_key(parent)
            {
                return Err(AuthorityError::UnknownParent {
                    principal: principal.clone(),
                    parent: parent.clone(),
                });
            }
        }
        let authority = Self { parents };
        // Every parent exists, so a chain either ends at a root or loops; a chain longer than
        // the number of principals has looped.
        for principal in authority.parents.keys() {
            let bound = authority.parents.len();
            if authority.ancestors(principal).take(bound + 1).count() > bound {
                return Err(AuthorityError::Cycle(principal.clone()));
            }
        }
        Ok(authority)
    }

    /// A hierarchy of one root and nothing else.
    pub fn single(root: Principal) -> Self {
        Self {
            parents: BTreeMap::from([(root, None)]),
        }
    }

    /// Whether the principal is one of the hierarchy.
    pub fn contains(&self, principal: &Principal) -> bool {
        self.parents.contains_key(principal)
    }

    /// Whether the principal is a root: one of the hierarchy, with no parent.
    pub fn is_root(&self, principal: &Principal) -> bool {
        matches!(self.parents.get(principal), Some(None))
    }

    /// The roots.
    pub fn roots(&self) -> impl Iterator<Item = &Principal> {
        self.parents
            .iter()
            .filter(|(_, parent)| parent.is_none())
            .map(|(principal, _)| principal)
    }

    /// The principal above `principal`, when it has one.
    pub fn parent(&self, principal: &Principal) -> Option<&Principal> {
        self.parents.get(principal).and_then(Option::as_ref)
    }

    /// Whether `actor` is `author` or above it, so that what `author` wrote is `actor`'s to
    /// loosen. Reflexive and transitive; two principals that are neither the same nor in one
    /// chain (siblings, two roots) do not cover each other.
    ///
    /// Total on the principals of the hierarchy. For one that is not, nothing is above it and
    /// only it covers it; a caller that must tell the two apart asks [`Authority::contains`]
    /// first, as the catalog does when it accepts a policy graph.
    pub fn covers(&self, actor: &Principal, author: &Principal) -> bool {
        self.ancestors(author).any(|p| p == actor)
    }

    /// Whether `principal` is of the hierarchy and is `owner` or below it: what one may put in
    /// effect on what `owner` wrote, permanently in a catalog or for a while by a claim, is only
    /// what is the owner's own or below it, so the owner can always loosen it. The one answer to
    /// that, asked of a binding of a catalog and of a temporary binding alike.
    pub fn within(&self, principal: &Principal, owner: &Principal) -> Result<(), NotWithin> {
        if !self.contains(principal) {
            Err(NotWithin::UnknownPrincipal(principal.clone()))
        } else if !self.covers(owner, principal) {
            Err(NotWithin::NotBelow {
                principal: principal.clone(),
                owner: owner.clone(),
            })
        } else {
            Ok(())
        }
    }

    /// Whether `by` may loosen what `authors` wrote: `by` is a principal of the hierarchy, and it
    /// covers every one of them. This is the one question of whether a loosening may be done; it
    /// asks [`Authority::contains`] first, then [`Authority::covers`] of each author.
    ///
    /// It is asked only of what loosens, or of what cannot be read as only tightening. What only
    /// tightens is open to anyone, a principal outside the hierarchy included, and nobody asks.
    /// With no author, the answer is whether `by` is of the hierarchy.
    pub fn may_loosen<'a>(
        &self,
        by: &Principal,
        authors: impl IntoIterator<Item = &'a Principal>,
    ) -> Result<(), NotCovered> {
        if !self.contains(by) {
            return Err(NotCovered::UnknownPrincipal(by.clone()));
        }
        let mut uncovered: Vec<Principal> = Vec::new();
        for author in authors {
            if !self.covers(by, author) && !uncovered.contains(author) {
                uncovered.push(author.clone());
            }
        }
        if uncovered.is_empty() {
            Ok(())
        } else {
            Err(NotCovered::Uncovered(uncovered))
        }
    }

    /// `principal` itself, then each principal above it up to the root. Ends only because no
    /// chain of a hierarchy loops; while the hierarchy is being checked, the caller bounds it.
    fn ancestors<'a>(&'a self, principal: &'a Principal) -> impl Iterator<Item = &'a Principal> {
        std::iter::successors(Some(principal), |p| self.parent(p))
    }
}
