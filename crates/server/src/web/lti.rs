//! The LTI profile never falls through to ordinary authorization.
pub(super) mod authorize;
pub(super) mod browser;
pub(super) mod producer;
mod rendering;

use super::AppState;
use crate::lti::{intents, store, LtiError};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use sqlx::{Postgres, Row, Transaction};

fn failure(state: &AppState, error: &LtiError) -> Response {
    let (status, code) = match error {
        LtiError::Invalid | LtiError::Mapping(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        LtiError::Denied => (StatusCode::FORBIDDEN, "access_denied"),
        LtiError::Capacity => (StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable"),
        LtiError::Conflict => (StatusCode::CONFLICT, "invalid_request"),
        LtiError::Unavailable | LtiError::Database(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
    };
    super::no_cache_json_error_with_iss(status, code, None, &state.issuer)
}

async fn session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, super::auth_session::AuthSession), Response> {
    let id = super::form_helpers::auth_session_cookie(headers)
        .map_err(|_| failure(state, &LtiError::Invalid))?
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            super::no_cache_json_error_with_iss(
                StatusCode::UNAUTHORIZED,
                "login_required",
                None,
                &state.issuer,
            )
        })?;
    let session = state
        .browser_auth
        .auth_sessions
        .try_get_async(id.clone())
        .await
        .map_err(|_| failure(state, &LtiError::Unavailable))?
        .ok_or_else(|| {
            super::no_cache_json_error_with_iss(
                StatusCode::UNAUTHORIZED,
                "login_required",
                None,
                &state.issuer,
            )
        })?;
    Ok((id, session))
}

async fn current_runtime(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<crate::runtime_configuration::RuntimeAuthorityRevision, LtiError> {
    if state.management.database.is_none() {
        return Err(LtiError::Unavailable);
    }
    crate::lti::database::require_reader(tx)
        .await
        .map_err(|_| LtiError::Unavailable)?;
    store::read_environment(tx, state.environment_id).await?;
    let loaded = state
        .runtime_authority
        .revision()
        .map_err(|_| LtiError::Unavailable)?;
    let current =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host_in_tx(
            tx,
            state.runtime_authority.issuer_host(),
        )
        .await
        .map_err(|_| LtiError::Unavailable)?;
    if !loaded.stable_authority_matches(&current)
        || loaded.active_runtime_client_fingerprint() != current.active_runtime_client_fingerprint()
        || state
            .clients
            .try_runtime_snapshot_fingerprint()
            .map_err(|_| LtiError::Unavailable)?
            .as_deref()
            != Some(current.active_runtime_client_fingerprint())
    {
        return Err(LtiError::Unavailable);
    }
    // Also bind the environment and public issuer to the actual database view.
    let row=sqlx::query("SELECT environment_id,issuer_url FROM aegaeon.active_runtime_environments WHERE environment_id=$1")
        .bind(state.environment_id).fetch_optional(&mut **tx).await?.ok_or(LtiError::Unavailable)?;
    if row.try_get::<String, _>("issuer_url")? != *state.issuer {
        return Err(LtiError::Unavailable);
    }
    Ok(current)
}

async fn current_intent(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    intent: &intents::Intent,
    runtime: &crate::runtime_configuration::RuntimeAuthorityRevision,
) -> Result<store::Registration, Response> {
    let checked = async {
        if intent.runtime_revision != runtime.active_configuration_version_id()
            || intent.runtime_fingerprint != runtime.active_configuration_document_fingerprint()
            || !matches!(
                intent.status.as_str(),
                "pending" | "confirmed" | "initiated"
            )
            || intents::now(tx).await? >= intent.expires_at
        {
            return Err(LtiError::Denied);
        }
        let registration = store::load(tx, state.environment_id, &intent.client_id, true)
            .await?
            .ok_or(LtiError::Denied)?;
        if registration.id != intent.registration_id
            || registration.active_revision != Some(intent.revision)
            || store::current_client(tx, state.environment_id, &intent.client_id).await?
                != registration.client_record_id
            || intents::owner(tx, state.environment_id, intent.owner).await? != intent.subject
        {
            return Err(LtiError::Denied);
        }
        let (deployment, _) = registration
            .configuration
            .placement(&intent.deployment_id, &intent.resource_link_id)?;
        if !deployment.producers.contains(&intent.producer.client_id)
            || !intent.roles.is_subset(&deployment.allowed_roles)
        {
            return Err(LtiError::Denied);
        }
        let grant = intent
            .producer
            .client_credentials_grant
            .as_ref()
            .ok_or(LtiError::Denied)?;
        if store::current_client(tx, state.environment_id, &intent.producer.client_id).await?
            != grant.caller.registration_id
        {
            return Err(LtiError::Denied);
        }
        Ok(registration)
    }
    .await
    .map_err(|error| failure(state, &error))?;
    if !super::client_credentials_authorization::current_in_tx(state, &intent.producer, tx).await? {
        return Err(failure(state, &LtiError::Denied));
    }
    current_application_grant(state, tx, &intent.producer).await?;
    Ok(checked)
}

// Projection and identity locks remain held through the launch transaction.
// Membership authority is independently rechecked; it cannot grant extra roles.
async fn current_application_grant(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    meta: &crate::authcode::types::BearerTokenMeta,
) -> Result<(), Response> {
    let Some(grant) = meta.application_grant.as_ref() else {
        return Ok(());
    };
    let same_client = grant.client_id == meta.client_id;
    let same_subject = grant.subject == meta.user_id;
    if !same_client
        || !same_subject
        || !grant.audiences.contains(&meta.audience)
        || grant.validate().is_err()
    {
        return Err(failure(state, &LtiError::Denied));
    }
    let authority = state
        .application_authority
        .as_ref()
        .ok_or_else(|| failure(state, &LtiError::Unavailable))?;
    if !authority
        .memberships_current(grant)
        .await
        .map_err(|_| failure(state, &LtiError::Unavailable))?
        || !crate::application_authorization::store::lock_current_in_tx(
            tx,
            state.environment_id,
            &state.issuer,
            grant,
        )
        .await
        .map_err(|_| failure(state, &LtiError::Unavailable))?
    {
        return Err(failure(state, &LtiError::Denied));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

pub(super) fn routes() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/lti/launches", post(producer::create))
        .route(
            "/lti/launch/:ticket",
            get(browser::present).post(browser::confirm),
        )
        .route(
            "/lti/authorize",
            get(authorize::authorize).post(authorize::authorize),
        )
        .route("/lti/continue/:ticket", get(authorize::resume))
}
