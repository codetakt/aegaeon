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

fn bearer_meta_authorizes_introspection(meta: &BearerTokenMeta, requester: &str) -> bool {
    meta.client_id == requester || meta.audience == requester
}

pub(super) async fn introspection_token_visible_to_client(
    state: &AppState,
    token: &str,
    access_token: &AccessToken,
    requester: Option<&str>,
) -> Result<bool, Response> {
    let Some(requester) = requester else {
        return Ok(false);
    };
    if access_token.client_id == requester {
        return Ok(true);
    }
    state
        .tokens
        .store
        .try_get_bearer_meta_async(token.to_string())
        .await
        .map(|meta| meta.is_some_and(|meta| bearer_meta_authorizes_introspection(&meta, requester)))
        .map_err(|err| {
            tracing::error!(
                target: "oauth",
                error = %err,
                "token metadata lookup failed during introspection authorization"
            );
            no_cache_json_error_with_iss(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                Some("token store unavailable"),
                state.issuer.as_str(),
            )
        })
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
    token: &str,
    access_token: &AccessToken,
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
        "scope": access_token.scope.clone(),
        "client_id": access_token.client_id,
        "username": access_token.user_id,
        "token_type": access_token.token_type,
        "exp": exp,
    });
    if let Some(cnf_claim) = access_token.cnf.as_ref() {
        apply_introspection_cnf_claim(&mut body, cnf_claim);
    }
    match state
        .tokens
        .store
        .try_get_bearer_meta_async(token.to_string())
        .await
    {
        Ok(Some(meta)) => {
            augment_introspection_body_with_meta(&mut body, &meta, state.issuer.as_str())?;
        }
        Ok(None) => {}
        Err(err) => {
            tracing::error!(
                target: "oauth",
                error = %err,
                "token metadata lookup failed while building introspection body"
            );
            return Err(no_cache_json_error_with_iss(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                Some("token store unavailable"),
                state.issuer.as_str(),
            ));
        }
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
