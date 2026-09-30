use super::super::oauth_errors::no_cache_json_error_with_iss;
use super::super::{clock_error_response, AppState};
use super::forms::{required_lifecycle_token, IntrospectForm};
use super::jwt_introspection::{build_jwt_introspection_response, wants_jwt_introspection};
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::time::UNIX_EPOCH;

use crate::authcode::types::{AccessToken, BearerTokenMeta, CnfClaim, SenderBinding};
use crate::middleware::tls::mtls_fingerprint_to_x5t_s256;
use crate::util;

pub(super) fn require_introspection_token(
    form: IntrospectForm,
    issuer_base: &str,
) -> Result<String, Response> {
    required_lifecycle_token(form.token, issuer_base)
}

fn apply_introspection_cnf_claim(body: &mut Value, claim: &CnfClaim) {
    match claim {
        CnfClaim::Jkt(jkt) => {
            body["cnf"] = json!({ "jkt": jkt });
        }
        CnfClaim::X5tS256(x5t) => {
            body["cnf"] = json!({ "x5t#S256": x5t });
        }
    }
}

fn augment_introspection_body_with_meta(
    body: &mut Value,
    meta: &BearerTokenMeta,
    issuer_base: &str,
) -> Result<(), Response> {
    body["aud"] = json!(meta.audience);
    let issued_at = util::unix_epoch_secs(meta.issued_at).map_err(|err| {
        util::log_clock_error("introspection issued_at", &err);
        clock_error_response(issuer_base)
    })?;
    let expires_at = util::unix_epoch_secs(meta.expires_at).map_err(|err| {
        util::log_clock_error("introspection expires_at", &err);
        clock_error_response(issuer_base)
    })?;
    body["issued_at"] = json!(issued_at);
    body["expires_at"] = json!(expires_at);
    if !meta.granted_scopes.is_empty() {
        body["granted_scopes"] = json!(meta.granted_scopes);
    }
    if let Some(details) = meta.authorization_details.as_ref() {
        body["authorization_details"] = details.clone();
    }
    if let Some(auth_time) = meta.auth_time_epoch_secs {
        body["auth_time"] = json!(auth_time);
    }
    if let Some(acr) = meta.acr.as_ref() {
        body["acr"] = json!(acr);
    }
    if let Some(binding) = meta.sender_binding.as_ref() {
        match binding {
            SenderBinding::DPoP { jkt } => {
                let thumbprint_uri = util::jwk_thumbprint_uri_from_jkt(jkt);
                body["sender_binding"] = json!({
                    "type": "dpop",
                    "jkt": jkt,
                    "jwk_thumbprint_uri": thumbprint_uri,
                });
                if body.get("cnf").is_none() {
                    body["cnf"] = json!({ "jkt": jkt });
                }
            }
            SenderBinding::Mtls { fingerprint } => {
                body["sender_binding"] = json!({
                    "type": "mtls",
                    "fingerprint": fingerprint,
                });
                if body.get("cnf").is_none() {
                    if let Some(x5t_s256) = mtls_fingerprint_to_x5t_s256(fingerprint) {
                        body["cnf"] = json!({ "x5t#S256": x5t_s256 });
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) async fn introspection_token_visible_to_client(
    state: &AppState,
    access_token: &AccessToken,
    meta: Option<&BearerTokenMeta>,
    requester: Option<&str>,
) -> Result<bool, Response> {
    let Some(requester) = requester else {
        return Ok(false);
    };
    super::super::client_credentials_authorization::introspection_visible(
        state,
        access_token,
        meta,
        requester,
    )
    .await
}

fn access_token_introspection_exp(access_token: &AccessToken) -> Option<u64> {
    let created_at_epoch_secs = access_token
        .created_at
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    created_at_epoch_secs.checked_add(access_token.expires_in)
}

pub(super) async fn active_introspection_body(
    state: &AppState,
    access_token: &AccessToken,
    meta: Option<&BearerTokenMeta>,
) -> Result<Value, Response> {
    let Some(exp) = access_token_introspection_exp(access_token) else {
        return Err(no_cache_json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("access token expiry is outside representable time"),
            state.issuer.as_str(),
        ));
    };
    let mut body = json!({
        "active": true,
        "iss": state.issuer.as_str(),
        "sub": access_token.user_id,
        "scope": access_token.scope.clone(),
        "client_id": access_token.client_id,
        "username": access_token.user_id,
        "token_type": access_token.token_type,
        "exp": exp,
    });
    if let Some(cnf_claim) = access_token.cnf.as_ref() {
        apply_introspection_cnf_claim(&mut body, cnf_claim);
    }
    if let Some(meta) = meta {
        if let Some(grant) = meta.application_grant.as_ref() {
            match super::super::application_authorization::current(state, grant).await {
                Ok(false) => return Ok(json!({"active":false})),
                Err(_) => {
                    return Err(no_cache_json_error_with_iss(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        Some("application authority unavailable"),
                        state.issuer.as_str(),
                    ))
                }
                Ok(true) => {}
            }
            if grant.audiences.contains(&meta.audience) {
                body[crate::application_authorization::inorii::CLAIM_NAME] = json!(grant.claims);
            }
        }
        augment_introspection_body_with_meta(&mut body, meta, state.issuer.as_str())?;
    }
    Ok(body)
}

pub(super) fn finalize_introspection_response(
    state: &AppState,
    headers: &HeaderMap,
    body: Value,
    requesting_client: Option<&str>,
) -> Response {
    if wants_jwt_introspection(headers) && state.cfg.jwt_runtime().introspection_enabled() {
        return build_jwt_introspection_response(state, &body, requesting_client);
    }
    let mut response = (StatusCode::OK, Json(body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}
