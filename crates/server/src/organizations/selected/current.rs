use super::*;
use operators::mutations::targets::recipients::{self, Recipient};

/// The transaction owner must still authenticate the token, root and sender.
pub(crate) async fn is_current(
    tx: &mut Transaction<'_, Postgres>,
    selected: &SelectedAuthority,
    original: &RootAuthority,
    authenticated: &Binding,
    now: i64,
) -> Result<bool, RepositoryError> {
    match check(tx, selected, original, authenticated, now).await {
        Ok(()) => Ok(true),
        Err(RepositoryError::Authority(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

async fn check(
    tx: &mut Transaction<'_, Postgres>,
    selected: &SelectedAuthority,
    original: &RootAuthority,
    authenticated: &Binding,
    now: i64,
) -> Result<(), RepositoryError> {
    selected.validate_binding(original, authenticated, now)?;
    let decision = &selected.decision;
    let recomputed = authorize(
        tx,
        SelectionInput {
            original,
            authenticated,
            request: &AccessRequest {
                detail_type: ORGANIZATION_ACCESS_TYPE.into(),
                admin_access_grant_id: match decision.authority {
                    AccessAuthority::Membership { .. } => None,
                    AccessAuthority::AdministrativeGrant { grant_id, .. } => Some(grant_id),
                },
                identifier: decision.organization_identifier.clone(),
                privileges: Some(decision.privileges.iter().cloned().collect()),
            },
            audience: &decision.audience,
            parent_expires_at: selected.parent_expires_at,
            now: selected.issued_at,
        },
    )
    .await?;
    // Birth time stays fixed. Every authority row is current; changed revisions,
    // generations, role versions or bindings refuse the existing token.
    require(recomputed == *selected)?;
    Ok(())
}

/// Caller pins this registration to its successfully authenticated runtime projection.
/// Run in the same transaction as the selected authority check.
pub(crate) async fn recipient_current(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    audience: &str,
    authenticated: &Recipient,
) -> Result<bool, RepositoryError> {
    match recipient_check(tx, scope, audience, authenticated).await {
        Ok(()) => Ok(true),
        Err(RepositoryError::Authority(_)) => Ok(false),
        Err(error) => Err(error),
    }
}
async fn recipient_check(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    audience: &str,
    authenticated: &Recipient,
) -> Result<(), RepositoryError> {
    lock_primary_scope(tx, scope).await?;
    repo::lock_domain(tx, scope).await?;
    let value:Option<serde_json::Value>=sqlx::query_scalar("SELECT introspection_clients FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND audience=$3 COLLATE \"C\" FOR SHARE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(audience).fetch_optional(&mut **tx).await?;
    let recipients: Vec<Recipient> =
        serde_json::from_value(value.ok_or(AuthorityError::Forbidden)?)?;
    recipients::validate(&recipients)?;
    require(recipients.contains(authenticated))?;
    require(
        recipients::current(tx, scope, authenticated.client_registration_id).await?
            == *authenticated,
    )?;
    Ok(())
}
