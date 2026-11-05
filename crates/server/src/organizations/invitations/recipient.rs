//! Derive recipient facts only after the HTTP caller authenticates the token and
//! fresh DPoP proof. This module adds the current primary and registration checks.
use super::*;
use crate::authcode::types::{BearerTokenMeta, SenderBinding};

pub(crate) const PRIVILEGE: &str = "organization.invitation.accept";

pub(crate) fn token_deadline(
    meta: &BearerTokenMeta,
    issuer: &str,
    now: i64,
) -> Result<i64, AuthorityError> {
    let epoch = |time| {
        crate::util::unix_epoch_secs(time)
            .ok()
            .and_then(|v| i64::try_from(v).ok())
            .ok_or(AuthorityError::Forbidden)
    };
    let issued = epoch(meta.issued_at)?;
    let expires = epoch(meta.expires_at)?;
    let grant = meta
        .exchange_grant
        .as_ref()
        .ok_or(AuthorityError::Forbidden)?;
    let root = grant.root().ok_or(AuthorityError::Forbidden)?;
    let lifetime = expires
        .checked_sub(issued)
        .ok_or(AuthorityError::Forbidden)?;
    if meta.audience != format!("{issuer}/organization-invitations")
        || meta.granted_scopes != [PRIVILEGE]
        || meta.selected_organization.is_some()
        || meta.authorization_details.is_some()
        || meta.application_grant.is_some()
        || meta.client_credentials_grant.is_some()
        || grant.organization.is_some()
        || !grant.has_client_scope_ceiling()
        || !grant.covers_output(
            &meta.client_id,
            &meta.user_id,
            &meta.audience,
            &meta.granted_scopes,
        )
        || !(1..=300).contains(&lifetime)
        || now < issued
        || now >= expires
        || expires > epoch(root.expires_at)?
        || !matches!(meta.sender_binding, Some(SenderBinding::DPoP { .. }))
    {
        return Err(AuthorityError::Forbidden);
    }
    Ok(expires)
}

pub(crate) async fn current(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
    meta: &BearerTokenMeta,
    issuer: &str,
    now: i64,
    runtime: &delegated::Runtime<'_>,
) -> Result<Recipient, RepositoryError> {
    let expires_at = token_deadline(meta, issuer, now)?;
    // Retain the inviter-human -> domain -> organization -> invitation order.
    // Loading client/user first would invert the ordinary operator lock order.
    let stored = load(tx, scope, invitation).await?;
    super::current_with_runtime(tx, scope, &stored, now, Some(runtime)).await?;
    selected::lock_primary_scope(tx, scope).await?;
    let management: Option<bool> = sqlx::query_scalar("SELECT management FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND audience=$3 COLLATE \"C\" FOR SHARE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(&meta.audience)
        .fetch_optional(&mut **tx).await?;
    let client = consent::client(tx, scope, &meta.client_id, &meta.audience).await?;
    if management != Some(true)
        || !client
            .targets
            .iter()
            .any(|t| t.audience == meta.audience && t.privileges.iter().any(|p| p == PRIVILEGE))
    {
        return Err(AuthorityError::Forbidden.into());
    }
    let user: Option<Uuid> = sqlx::query_scalar("SELECT id FROM aegaeon.end_users WHERE environment_id=$1 AND subject=$2 COLLATE \"C\" AND status='ACTIVE' FOR SHARE")
        .bind(scope.environment_id).bind(&meta.user_id).fetch_optional(&mut **tx).await?;
    let Some(SenderBinding::DPoP { jkt }) = &meta.sender_binding else {
        return Err(AuthorityError::Forbidden.into());
    };
    let auth_time = meta.auth_time_epoch_secs.ok_or(AuthorityError::Forbidden)?;
    if auth_time <= 0 || auth_time > now {
        return Err(AuthorityError::Forbidden.into());
    }
    let user_id = user.ok_or(AuthorityError::Forbidden)?;
    let identity_revision =
        crate::organizations::identity::revision(tx, scope, user_id, &meta.user_id, auth_time)
            .await?;
    let recipient = Recipient {
        identity_revision,
        auth_time,
        binding: Binding {
            scope,
            issuer: issuer.into(),
            client_id: meta.client_id.clone(),
            client_registration_id: client.client_registration_id,
            subject: meta.user_id.clone(),
            user_id,
            root_id: meta
                .exchange_grant
                .as_ref()
                .and_then(|g| g.root())
                .ok_or(AuthorityError::Forbidden)?
                .id
                .clone(),
            dpop_jkt: jkt.clone(),
        },
        expires_at,
    };
    recipient.check(tx, scope, now).await?;
    Ok(recipient)
}
