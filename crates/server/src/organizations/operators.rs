//! Current domain operator permissions, separate from business memberships.
//! The HTTP boundary authenticates the principal; an identifier is not a session.
use super::{repository::RepositoryError, AuthorityError, Scope};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeSet;
use uuid::Uuid;

pub mod mutations;

pub const MAX_OPERATORS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = OrganizationOperatorCapability))]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Configure,
    Provision,
    Reconcile,
    Export,
    Support,
}

/// Current facts in the caller's locked transaction, not a reusable credential.
/// Deliberately not serializable or constructible from request fields.
pub struct OperatorAuthority {
    principal: Uuid,
    grant: Uuid,
    revision: i64,
}

impl OperatorAuthority {
    #[must_use]
    pub fn principal(&self) -> Uuid {
        self.principal
    }

    #[must_use]
    pub fn grant(&self) -> Uuid {
        self.grant
    }

    #[must_use]
    pub fn revision(&self) -> i64 {
        self.revision
    }
}

pub fn validate_capabilities(
    values: &[Capability],
) -> Result<BTreeSet<Capability>, AuthorityError> {
    let set: BTreeSet<_> = values.iter().copied().collect();
    super::model::require(!set.is_empty() && set.len() <= 5 && set.len() == values.len())?;
    Ok(set)
}

/// Lock active topology and a current human Team member before the domain.
/// `authenticated_principal` must come from an authenticated management session.
pub async fn lock_human_scope(
    tx: &mut Transaction<'_, Postgres>,
    team: Uuid,
    environment: Uuid,
    authenticated_principal: Uuid,
    require_owner: bool,
) -> Result<(), RepositoryError> {
    super::model::require(
        !team.is_nil() && !environment.is_nil() && !authenticated_principal.is_nil(),
    )?;
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT a.id FROM aegaeon.administrators a JOIN aegaeon.team_memberships m ON m.administrator_id=a.id JOIN aegaeon.teams t ON t.id=m.team_id JOIN aegaeon.tenants n ON n.team_id=t.id JOIN aegaeon.environments e ON e.tenant_id=n.id WHERE a.id=$1 AND t.id=$2 AND e.id=$3 AND a.status='ACTIVE' AND a.kind='HUMAN' AND t.status='ACTIVE' AND n.status='ACTIVE' AND e.status='ACTIVE' AND (NOT $4 OR m.role='OWNER') FOR SHARE OF a,m,t,n,e",
    ).bind(authenticated_principal).bind(team).bind(environment).bind(require_owner)
        .fetch_optional(&mut **tx).await?;
    if found != Some(authenticated_principal) {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(())
}

/// Check before receipt lookup or resource disclosure, within the mutation/read
/// transaction. Team ownership and same-named organization roles never bypass it.
pub async fn lock_operator_authority(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    authenticated_principal: Uuid,
    capability: Capability,
) -> Result<OperatorAuthority, RepositoryError> {
    scope.validate()?;
    lock_human_scope(
        tx,
        team,
        scope.environment_id,
        authenticated_principal,
        false,
    )
    .await?;
    let enabled: Option<bool> = sqlx::query_scalar("SELECT enabled FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2 AND import_operation_id IS NULL FOR UPDATE")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_optional(&mut **tx).await?;
    match (enabled, capability) {
        (Some(true), _) | (Some(false), Capability::Configure) => {}
        _ => return Err(AuthorityError::Forbidden.into()),
    }
    let row = sqlx::query("SELECT id,revision,capabilities FROM aegaeon.organization_operator_grants WHERE environment_id=$1 AND domain_id=$2 AND administrator_id=$3 AND active FOR UPDATE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(authenticated_principal)
        .fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let id: Uuid = row.try_get("id")?;
    let revision: i64 = row.try_get("revision")?;
    let values: Vec<Capability> = serde_json::from_value(row.try_get("capabilities")?)?;
    let capabilities = validate_capabilities(&values)?;
    if id.is_nil() || revision <= 0 || !capabilities.contains(&capability) {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(OperatorAuthority {
        principal: authenticated_principal,
        grant: id,
        revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_operator_capabilities_are_explicit_unique_and_independent() {
        for capability in [
            Capability::Configure,
            Capability::Provision,
            Capability::Reconcile,
            Capability::Export,
            Capability::Support,
        ] {
            let set = validate_capabilities(&[capability]).unwrap();
            assert_eq!(set, BTreeSet::from([capability]));
            assert!(validate_capabilities(&[capability, capability]).is_err());
        }
        assert!(validate_capabilities(&[]).is_err());
        for invalid in [
            "owner",
            "administrator",
            "*",
            "Configure",
            "organization.members.manage",
        ] {
            assert!(serde_json::from_value::<Capability>(serde_json::json!(invalid)).is_err());
        }
    }
}
