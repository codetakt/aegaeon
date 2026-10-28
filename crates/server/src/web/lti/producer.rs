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

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<BearerTokenMeta, Response> {
    let invalid = || {
        let mut response = super::super::no_cache_json_error_with_iss(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            None,
            &state.issuer,
        );
        super::super::oauth_errors::apply_oauth_authenticate_header(
            &mut response,
            "Bearer",
            "invalid_token",
        );
        response
    };
    let authorization = super::super::oauth_errors::authorization_header(headers)
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
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
    let challenge = if dpop { "DPoP" } else { "Bearer" };
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
    if matches!(meta.sender_binding, Some(SenderBinding::DPoP { .. })) != dpop
        || meta.client_credentials_grant.is_none()
        || meta.refresh_parent.is_some()
        || meta.exchange_grant.is_some()
        || !super::super::client_credentials_authorization::current(state, &meta).await?
    {
        return Err(invalid());
    }
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
        let runtime=current_runtime(&state,&mut tx).await.map_err(|error|failure(&state, &error))?;
        let registration=store::load(&mut tx,state.environment_id,&body.client_id,true).await.map_err(|error|failure(&state, &error))?
            .ok_or_else(||failure(&state, &LtiError::Denied))?;
        if registration.configuration.security.require_dpop && !matches!(meta.sender_binding,Some(SenderBinding::DPoP {..})) {
            return Err(failure(&state, &LtiError::Denied));
        }
        if store::current_client(&mut tx,state.environment_id,&body.client_id).await.map_err(|error|failure(&state, &error))?!=registration.client_record_id {
            return Err(failure(&state, &LtiError::Denied));
        }
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
