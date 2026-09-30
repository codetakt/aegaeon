//! Client-credentials authority at issuance and Aegaeon's online use boundaries.
use axum::{http::StatusCode, response::Response};
use std::sync::Arc;

use crate::authcode::types::{AccessToken, BearerTokenMeta};
use crate::policy::client_credentials::{
    AuthorizedClientCredentials, ClientCredentialsAuthorizationError,
    ClientCredentialsGrant, ClientCredentialsRegistration,
};
use crate::runtime_clients::RuntimeClientIdentity;
use super::{AppState, TokenEndpointContext, token_error_response};

/// Authentication must observe the same selected registration snapshot as authority capture.
/// Replay/JWKS state stays shared; only selected registration and secret material is copied.
pub(super) fn request_state(state: &AppState, ids: &[&str]) -> Result<AppState, Response> {
    let mut snapshot = state.clone();
    snapshot.clients = Arc::new(state.clients.try_request_snapshot(ids)
        .map_err(|error| unavailable(state, &error.to_string()))?);
    Ok(snapshot)
}

fn unavailable(state: &AppState, error: &str) -> Response {
    tracing::error!(target: "oauth", error, "client-credentials authority lookup failed");
    super::oauth_errors::no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable",
        Some("client-credentials authority unavailable"), state.issuer.as_str(),
    )
}

async fn identities(
    state: &AppState,
    ids: &[String],
) -> Result<(crate::runtime_configuration::RuntimeAuthorityRevision, Vec<RuntimeClientIdentity>), Response> {
    let revision = state.runtime_authority.revision()
        .map_err(|error| unavailable(state, &error.to_string()))?;
    let fingerprint = state.clients.try_runtime_snapshot_fingerprint()
        .map_err(|error| unavailable(state, &error.to_string()))?;
    if fingerprint.as_deref() != Some(revision.active_runtime_client_fingerprint()) {
        return Err(unavailable(state, "authenticated registration projection changed"));
    }
    let members = crate::runtime_clients::load_client_identities_guarded(
        &state.db_pool, state.runtime_authority.issuer_host(), state.environment_id,
        &revision, ids,
    ).await.map_err(|error| unavailable(state, &error.to_string()))?;
    Ok((revision, members))
}

pub(super) async fn authorize(
    state: &AppState,
    ctx: &TokenEndpointContext,
) -> Result<AuthorizedClientCredentials, Response> {
    let client = state.clients.try_get(&ctx.client_id)
        .map_err(|error| unavailable(state, &error.to_string()))?
        .ok_or_else(|| token_error_response(StatusCode::UNAUTHORIZED, "invalid_client", None))?;
    let selection = state.cfg.client_credentials.authorize(
        &state.cfg.token_exchange, &ctx.client_id, &client.allowed_scopes,
        &ctx.params, ctx.form.scope.as_deref(),
    ).map_err(|error| match error {
        ClientCredentialsAuthorizationError::InvalidTarget =>
            token_error_response(StatusCode::BAD_REQUEST, "invalid_target", Some("client is not authorized for the requested target")),
        ClientCredentialsAuthorizationError::InvalidScope =>
            token_error_response(StatusCode::BAD_REQUEST, "invalid_scope", Some("scope exceeds client-credentials authority or defaults are absent")),
        ClientCredentialsAuthorizationError::InvalidPolicy => unavailable(state, "invalid client-credentials policy"),
    })?;
    let mut ids = selection.introspection_clients.clone();
    ids.push(ctx.client_id.clone());
    ids.sort();
    ids.dedup();
    let (revision, members) = identities(state, &ids).await?;
    let caller = members.iter().find(|member| member.client_id == ctx.client_id)
        .filter(|member| member.allowed_grant_types.iter().any(|grant| grant == "client_credentials")
            && selection.scopes.iter().all(|scope| member.allowed_scopes.contains(scope)))
        .ok_or_else(|| token_error_response(StatusCode::BAD_REQUEST, "unauthorized_client", None))?;
    let introspection_clients = selection.introspection_clients.iter().map(|id| {
        members.iter().find(|member| &member.client_id == id)
            .map(|member| ClientCredentialsRegistration { client_id: id.clone(), registration_id: member.registration_id })
            .ok_or_else(|| token_error_response(StatusCode::BAD_REQUEST, "invalid_target", Some("target introspection registration is inactive")))
    }).collect::<Result<Vec<_>, Response>>()?;
    let mut grant = ClientCredentialsGrant {
        version: 1,
        issuer: state.issuer.to_string(),
        environment_id: state.environment_id,
        configuration_version_id: revision.active_configuration_version_id(),
        configuration_document_fingerprint: revision.active_configuration_document_fingerprint().to_string(),
        runtime_client_fingerprint: revision.active_runtime_client_fingerprint().to_string(),
        caller: ClientCredentialsRegistration { client_id: ctx.client_id.clone(), registration_id: caller.registration_id },
        audience: selection.audience,
        scopes: selection.scopes,
        context_digest: selection.context_digest,
        introspection_clients,
    };
    grant.scopes.sort();
    grant.introspection_clients.sort_by(|left, right| left.client_id.cmp(&right.client_id));
    AuthorizedClientCredentials::new(grant).map_err(|error| unavailable(state, error))
}

/// None denotes a legacy/other-grant token and receives no new authority.
pub(super) async fn current(state: &AppState, meta: &BearerTokenMeta) -> Result<bool, Response> {
    let Some(grant) = meta.client_credentials_grant.as_ref() else { return Ok(true); };
    if !grant.covers(&meta.client_id, &meta.user_id, &meta.audience, &meta.granted_scopes)
        || grant.issuer != *state.issuer || grant.environment_id != state.environment_id
        || meta.refresh_parent.is_some() || meta.exchange_grant.is_some()
    { return Ok(false); }
    let Ok(context) = state.cfg.client_credentials.selected_context(
        &state.cfg.token_exchange, &meta.client_id, &meta.audience,
    ) else { return Ok(false); };
    if context.context_digest != grant.context_digest
        || !grant.scopes.iter().all(|scope| context.scopes.contains(scope))
    { return Ok(false); }
    let mut ids = grant.introspection_clients.iter().map(|identity| identity.client_id.clone()).collect::<Vec<_>>();
    ids.push(meta.client_id.clone());
    ids.sort();
    ids.dedup();
    let (_, members) = identities(state, &ids).await?;
    let valid_caller = members.iter().any(|member| member.client_id == meta.client_id
        && member.registration_id == grant.caller.registration_id
        && member.allowed_grant_types.iter().any(|kind| kind == "client_credentials")
        && grant.scopes.iter().all(|scope| member.allowed_scopes.contains(scope)));
    Ok(valid_caller && grant.introspection_clients.iter().all(|identity| {
        context.introspection_clients.contains(&identity.client_id)
            && members.iter().any(|member| member.client_id == identity.client_id
                && member.registration_id == identity.registration_id)
    }))
}

pub(super) fn metadata_matches(access: &AccessToken, meta: Option<&BearerTokenMeta>) -> bool {
    if access.client_credentials_digest.is_none()
        && meta.is_none_or(|meta| meta.client_credentials_grant.is_none())
    { return true; }
    meta.is_some_and(|meta| crate::authcode::store::bearer_metadata_matches_access_token(access, meta).is_ok())
}

pub(super) async fn introspection_visible(
    state: &AppState, access: &AccessToken, meta: Option<&BearerTokenMeta>, requester: &str,
) -> Result<bool, Response> {
    if !metadata_matches(access, meta) { return Ok(false); }
    let Some(meta) = meta else { return Ok(access.client_id == requester); };
    let Some(grant) = meta.client_credentials_grant.as_ref() else {
        return Ok(access.client_id == requester || meta.client_id == requester || meta.audience == requester);
    };
    if !current(state, meta).await? { return Ok(false); }
    Ok(grant.caller.client_id == requester
        || grant.introspection_clients.iter().any(|identity| identity.client_id == requester))
}
