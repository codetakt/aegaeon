use super::*;
use crate::authcode::{
    types::{BearerTokenMeta, SenderBinding},
    TokenPolicyContext,
};
use crate::lti::model::CreateLaunch;
use crate::middleware::dpop::DpopEndpointRole;
use axum::{
    extract::{ConnectInfo, OriginalUri, State},
    http::{header, Method, Uri},
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::net::SocketAddr;

fn challenge(headers: &HeaderMap) -> &'static str {
    if super::super::oauth_errors::authorization_header(headers)
        .ok()
        .flatten()
        .and_then(|value| value.split_whitespace().next())
        .is_some_and(|value| value.eq_ignore_ascii_case("DPoP"))
    {
        "DPoP"
    } else {
        "Bearer"
    }
}
fn invalid(state: &AppState, challenge: &'static str) -> Response {
    let mut response = super::super::no_cache_json_error_with_iss(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        None,
        &state.issuer,
    );
    super::super::oauth_errors::apply_oauth_authenticate_header(
        &mut response,
        challenge,
        "invalid_token",
    );
    response
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<BearerTokenMeta, Response> {
    let presented = super::super::oauth_errors::authorization_header(headers);
    let challenge = challenge(headers);
    let invalid = || invalid(state, challenge);
    let authorization = presented.map_err(|_| invalid())?.ok_or_else(invalid)?;
    let parts: Vec<_> = authorization.split_whitespace().collect();
    let [scheme, token] = parts.as_slice() else {
        return Err(invalid());
    };
    let dpop = scheme.eq_ignore_ascii_case("DPoP");
    if !dpop && !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(invalid());
    }
    let binding = super::super::dpop_binding_from_request(
        state.dpop.as_ref(),
        DpopEndpointRole::ResourceServer,
        &Method::POST,
        uri,
        headers,
    )
    .map_err(|error| {
        super::super::token_sender_binding::dpop_error_response(
            &state.issuer,
            DpopEndpointRole::ResourceServer,
            error,
        )
    })?;
    let mtls = super::super::trusted_mtls_fingerprint(state, headers).map_err(|_| invalid())?;
    let policy_error = |status, code| {
        let mut response =
            super::super::no_cache_json_error_with_iss(status, code, None, &state.issuer);
        super::super::oauth_errors::apply_oauth_authenticate_header(&mut response, challenge, code);
        response
    };
    let normalized = format!("Bearer {token}");
    let audience = format!("{}/lti/launches", state.issuer.trim_end_matches('/'));
    let (_, meta) = state
        .tokens
        .validator
        .validate_with_policy_async(
            normalized,
            TokenPolicyContext {
                requested_scopes: &["lti:launch"],
                resource_audience: Some(&audience),
                sender_dpop_jkt: binding.as_ref().map(|value| value.jkt.as_str()),
                sender_mtls_fingerprint: mtls.as_deref(),
            },
        )
        .await
        .map_err(|error| {
            if matches!(&error,crate::authcode::TokenPolicyError::Validation(e) if e.is_internal())
                || matches!(
                    &error,
                    crate::authcode::TokenPolicyError::TokenStoreUnavailable(_)
                )
            {
                failure(state, &LtiError::Unavailable)
            } else if matches!(
                error,
                crate::authcode::TokenPolicyError::InsufficientScope { .. }
            ) {
                policy_error(StatusCode::FORBIDDEN, "insufficient_scope")
            } else {
                policy_error(StatusCode::UNAUTHORIZED, "invalid_token")
            }
        })?;
    if !meta
        .granted_scopes
        .iter()
        .any(|scope| scope == "lti:launch")
    {
        return Err(policy_error(StatusCode::FORBIDDEN, "insufficient_scope"));
    }
    if meta.audience != audience {
        return Err(policy_error(StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    if matches!(meta.sender_binding, Some(SenderBinding::DPoP { .. })) != dpop
        || meta.client_credentials_grant.is_none()
        || meta.refresh_parent.is_some()
        || meta.exchange_grant.is_some()
        || !super::super::client_credentials_authorization::current(state, &meta).await?
    {
        return Err(invalid());
    }
    super::super::application_authorization::check_resource(state, &meta, authorization).await?;
    Ok(meta)
}

pub(in crate::web) async fn create(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Json(body): Json<CreateLaunch>,
) -> Response {
    let result=async {
        let _namespace=state.require_subject_namespace()?;
        state.transport.enforce(Some(remote),&headers).map_err(|kind|super::super::transport_rejection(&state,kind))?;
        super::super::request_admission::enforce_no_credentials_in_uri(&uri,&state.issuer)?;
        let meta=authenticate(&state,&headers,&uri).await?;
        let mut tx=state.db_pool.begin().await.map_err(|_|failure(&state, &LtiError::Unavailable))?;
        // Serialize the count-and-insert budget before acquiring shared authority.
        store::lock_environment(&mut tx,state.environment_id).await.map_err(|error|failure(&state, &error))?;
        let runtime=current_runtime(&state,&mut tx).await.map_err(|error|failure(&state, &error))?;
        let registration=store::load(&mut tx,state.environment_id,&body.client_id,true).await.map_err(|error|failure(&state, &error))?
            .ok_or_else(||failure(&state, &LtiError::Denied))?;
        if registration.configuration.security.require_dpop && !matches!(meta.sender_binding,Some(SenderBinding::DPoP {..})) {
            return Err(failure(&state, &LtiError::Denied));
        }
        if store::current_client(&mut tx,state.environment_id,&body.client_id).await.map_err(|error|failure(&state, &error))?!=registration.client_record_id {
            return Err(failure(&state, &LtiError::Denied));
        }
        current_producer(&state, &mut tx, &meta).await?;
        current_application_grant(&state, &mut tx, &meta).await?;
        let ticket=intents::create(&mut tx,state.environment_id,&runtime,&registration,&body,&meta).await.map_err(|error|failure(&state, &error))?;
        tx.commit().await.map_err(|_|failure(&state, &LtiError::Unavailable))?;
        let mut response=(StatusCode::CREATED,Json(json!({"launchUrl":format!("{}/lti/launch/{ticket}",state.issuer.trim_end_matches('/'))}))).into_response();
        crate::util::apply_no_cache_headers(&mut response);
        response.headers_mut().insert(header::REFERRER_POLICY,axum::http::HeaderValue::from_static("no-referrer"));
        Ok::<_,Response>(response)
    }.await;
    match result {
        Ok(response) | Err(response) => response,
    }
}

// Authenticate before admission, then hold the producer row while checking its
// current permission again in the transaction that consumes the intent budget.
async fn current_producer(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    meta: &BearerTokenMeta,
) -> Result<(), Response> {
    let grant = meta
        .client_credentials_grant
        .as_ref()
        .ok_or_else(|| failure(state, &LtiError::Denied))?;
    if store::current_client(tx, state.environment_id, &meta.client_id)
        .await
        .map_err(|error| failure(state, &error))?
        != grant.caller.registration_id
        || !super::super::client_credentials_authorization::current_in_tx(state, meta, tx).await?
    {
        return Err(failure(state, &LtiError::Denied));
    }
    Ok(())
}
