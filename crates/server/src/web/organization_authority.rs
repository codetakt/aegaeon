//! Current primary authority after token-store authentication. No sender-proof bypass.
use super::AppState;
use crate::authcode::types::BearerTokenMeta;
use crate::organizations::{
    operators::mutations::targets::recipients::Recipient, repository, request_work::Admission,
    selected, Organization,
};
use axum::{http::StatusCode, response::Response};
use sqlx::Connection;

mod selection;
pub(super) use selection::select;

fn unavailable(state: &AppState) -> Response {
    super::oauth_errors::no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("organization authority unavailable"),
        state.issuer.as_str(),
    )
}

pub(super) async fn current(
    state: &AppState,
    meta: &BearerTokenMeta,
    requester: Option<&str>,
) -> Result<bool, Response> {
    let admission = Admission::try_acquire().map_err(|_| unavailable(state))?;
    Ok(current_admitted(state, meta, requester, &admission, false)
        .await?
        .is_some())
}

#[cfg(test)]
pub(super) async fn current_for_resource(
    state: &AppState,
    meta: &BearerTokenMeta,
    admission: &Admission,
) -> Result<bool, Response> {
    Ok(current_organization_for_resource(state, meta, admission)
        .await?
        .is_some())
}

pub(super) async fn current_organization_for_resource(
    state: &AppState,
    meta: &BearerTokenMeta,
    admission: &Admission,
) -> Result<Option<Organization>, Response> {
    current_admitted(state, meta, None, admission, true).await
}

async fn current_admitted(
    state: &AppState,
    meta: &BearerTokenMeta,
    requester: Option<&str>,
    admission: &Admission,
    own_resource: bool,
) -> Result<Option<Organization>, Response> {
    state.require_subject_namespace()?;
    if !state
        .cfg
        .authorization_details_types_supported
        .iter()
        .any(|t| t == crate::organizations::ORGANIZATION_ACCESS_TYPE)
    {
        return Ok(None);
    }
    let Some(authority) = meta.selected_organization.as_ref() else {
        return Ok(None);
    };
    let now = crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| unavailable(state))?;
    let Ok(binding) = authority.token_binding(meta, state.environment_id, &state.issuer, now)
    else {
        return Ok(None);
    };
    let original = meta
        .exchange_grant
        .as_ref()
        .and_then(|grant| grant.organization.as_ref())
        .ok_or_else(|| unavailable(state))?;
    let expected = projection(state)?;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut connection = admission
            .connection(&state.db_pool)
            .await
            .map_err(|_| unavailable(state))?;
        let mut tx = connection
            .as_mut()
            .map_err(|_| unavailable(state))?
            .begin()
            .await
            .map_err(|_| unavailable(state))?;
        if let Some(requester) = requester {
            if !recipient(&mut tx, binding.scope, &meta.audience, requester)
                .await
                .map_err(|_| unavailable(state))?
            {
                return Ok(None);
            }
        }
        if !selected::is_current(&mut tx, authority, original, &binding, now)
            .await
            .map_err(|_| unavailable(state))?
        {
            return Ok(None);
        }
        if own_resource {
            let management: Option<bool> = sqlx::query_scalar("SELECT management FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND audience=$3 COLLATE \"C\" FOR SHARE")
                .bind(binding.scope.environment_id).bind(binding.scope.domain_id).bind(&meta.audience)
                .fetch_optional(&mut *tx).await.map_err(|_| unavailable(state))?;
            if management != Some(true) {
                return Ok(None);
            }
        }
        let organization = repository::lock_organization(
            &mut tx, binding.scope, authority.decision.organization_id,
        ).await.map_err(|_| unavailable(state))?;
        recheck_projection(state, &mut tx, &expected).await?;
        admission.admit_commit().map_err(|_| unavailable(state))?;
        tx.commit().await.map_err(|_| unavailable(state))?;
        connection.release().await;
        Ok(Some(organization))
    })
    .await
    .map_err(|_| unavailable(state))?
}

async fn recipient(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: crate::organizations::Scope,
    audience: &str,
    requester: &str,
) -> Result<bool, crate::organizations::repository::RepositoryError> {
    use crate::organizations::{repository, AuthorityError};
    if let Err(error) = selected::lock_primary_scope(tx, scope).await {
        return match error {
            repository::RepositoryError::Authority(_) => Ok(false),
            other => Err(other),
        };
    }
    if let Err(error) = repository::lock_domain(tx, scope).await {
        return match error {
            repository::RepositoryError::Authority(_) => Ok(false),
            other => Err(other),
        };
    }
    let value:Option<serde_json::Value>=sqlx::query_scalar("SELECT introspection_clients FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND audience=$3 COLLATE \"C\" FOR SHARE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(audience).fetch_optional(&mut **tx).await?;
    let Some(value) = value else {
        return Ok(false);
    };
    let recipients: Vec<Recipient> = serde_json::from_value(value)?;
    if recipients.len() > 8 {
        return Err(AuthorityError::Invalid.into());
    }
    let Some(recipient) = recipients.iter().find(|r| r.client_identifier == requester) else {
        return Ok(false);
    };
    selected::recipient_current(tx, scope, audience, recipient).await
}

pub(super) fn projection(
    state: &AppState,
) -> Result<crate::runtime_configuration::RuntimeAuthorityRevision, Response> {
    let expected = state
        .runtime_authority
        .revision()
        .map_err(|_| unavailable(state))?;
    let fingerprint = state
        .clients
        .try_runtime_snapshot_fingerprint()
        .map_err(|_| unavailable(state))?;
    if fingerprint.as_deref() != Some(expected.active_runtime_client_fingerprint()) {
        return Err(unavailable(state));
    }
    Ok(expected)
}

pub(super) async fn recheck_projection(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    expected: &crate::runtime_configuration::RuntimeAuthorityRevision,
) -> Result<(), Response> {
    let actual = crate::runtime_clients::load_runtime_authority_revision_for_issuer_host_in_tx(
        tx,
        state.runtime_authority.issuer_host(),
    )
    .await
    .map_err(|_| unavailable(state))?;
    if &actual != expected {
        return Err(unavailable(state));
    }
    Ok(())
}
