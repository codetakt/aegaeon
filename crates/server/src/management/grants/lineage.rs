//! Allocation-free validation of one immutable delegation basis per grant.
//!
//! The persistence adapter loads a current, transaction-consistent leaf-to-root
//! chain. Successful validation alone is not a resource authorization decision.

pub(crate) const MAX_DELEGATION_EDGES: usize = 8;

/// UUID bytes at the storage boundary. Zero is never an authority identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity(pub(crate) [u8; 16]);

impl Identity {
    pub(super) fn is_present(self) -> bool {
        self.0 != [0; 16]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrincipalKind {
    Human,
    Service,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Principal {
    pub(crate) installation: Identity,
    pub(crate) id: Identity,
    pub(crate) kind: PrincipalKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Basis {
    InstallationBootstrap {
        operation: Identity,
    },
    Delegated {
        parent: Identity,
        captured_epoch: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lifetime {
    Until(u64),
    /// Explicit permanent assignment; never inferred from a missing credential expiry.
    Unbounded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialRestriction {
    AnyManagementCredential,
    HumanSession,
    ServiceCredential,
    Exact { id: Identity, kind: PrincipalKind },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Conditions {
    pub(crate) credential: CredentialRestriction,
    pub(crate) maximum_authentication_age_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GrantNode {
    pub(crate) id: Identity,
    pub(crate) principal: Principal,
    pub(crate) basis: Basis,
    pub(crate) revision: u64,
    pub(crate) delegation_epoch: u64,
    pub(crate) revoked: bool,
    pub(crate) valid_from: u64,
    pub(crate) lifetime: Lifetime,
    pub(crate) conditions: Conditions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Authentication {
    pub(crate) principal: Principal,
    pub(crate) credential_id: Identity,
    pub(crate) authenticated_at: u64,
    pub(crate) expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Denial {
    InvalidIdentity,
    InvalidChain,
    DifferentPrincipal,
    Revoked,
    OutsideValidity,
    StaleParent,
    CredentialCondition,
}

/// Borrowed lineage only: the type deliberately exposes no `authorize` method.
#[derive(Debug)]
pub(crate) struct ValidatedLineage<'a> {
    nodes: &'a [GrantNode],
}

impl ValidatedLineage<'_> {
    pub(crate) fn nodes(&self) -> &[GrantNode] {
        self.nodes
    }
}

/// Validate at most nine nodes without allocating or looking up arbitrary IDs.
/// The complete chain must end in an explicit bootstrap operation; truncation,
/// cycles and a newly issued replacement parent all fail closed.
pub(crate) fn validate<'a>(
    nodes: &'a [GrantNode],
    authentication: &Authentication,
    now: u64,
) -> Result<ValidatedLineage<'a>, Denial> {
    if nodes.is_empty() || nodes.len() > MAX_DELEGATION_EDGES + 1 {
        return Err(Denial::InvalidChain);
    }
    if !authentication.principal.installation.is_present()
        || !authentication.principal.id.is_present()
        || !authentication.credential_id.is_present()
    {
        return Err(Denial::InvalidIdentity);
    }
    if authentication.authenticated_at > now
        || authentication.expires_at <= now
        || authentication.expires_at <= authentication.authenticated_at
    {
        return Err(Denial::CredentialCondition);
    }
    if nodes[0].principal != authentication.principal {
        return Err(Denial::DifferentPrincipal);
    }
    for (index, node) in nodes.iter().enumerate() {
        if !node.id.is_present()
            || !node.principal.id.is_present()
            || node.principal.installation != authentication.principal.installation
        {
            return Err(Denial::InvalidIdentity);
        }
        if node.revision == 0
            || node.delegation_epoch == 0
            || nodes[..index].iter().any(|ancestor| ancestor.id == node.id)
        {
            return Err(Denial::InvalidChain);
        }
        if node.revoked {
            return Err(Denial::Revoked);
        }
        if node.valid_from > now
            || matches!(node.lifetime, Lifetime::Until(end) if end <= now || end <= node.valid_from)
        {
            return Err(Denial::OutsideValidity);
        }
        if !conditions_hold(node.conditions, authentication, now) {
            return Err(Denial::CredentialCondition);
        }
        match (node.basis, nodes.get(index + 1)) {
            (Basis::InstallationBootstrap { operation }, None) if operation.is_present() => {}
            (
                Basis::Delegated {
                    parent,
                    captured_epoch,
                },
                Some(current_parent),
            ) if parent == current_parent.id
                && captured_epoch == current_parent.delegation_epoch => {}
            (Basis::Delegated { .. }, Some(_)) => return Err(Denial::StaleParent),
            _ => return Err(Denial::InvalidChain),
        }
    }
    Ok(ValidatedLineage { nodes })
}

fn conditions_hold(conditions: Conditions, authentication: &Authentication, now: u64) -> bool {
    let kind = authentication.principal.kind;
    let credential_matches = match conditions.credential {
        CredentialRestriction::AnyManagementCredential => true,
        CredentialRestriction::HumanSession => kind == PrincipalKind::Human,
        CredentialRestriction::ServiceCredential => kind == PrincipalKind::Service,
        CredentialRestriction::Exact {
            id,
            kind: expected_kind,
        } => id == authentication.credential_id && kind == expected_kind,
    };
    credential_matches
        && conditions
            .maximum_authentication_age_seconds
            .is_none_or(|maximum| {
                now.checked_sub(authentication.authenticated_at)
                    .is_some_and(|age| age <= maximum)
            })
}

#[cfg(test)]
mod tests;
