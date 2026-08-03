use aegaeon_jose::RequestObjectClaims;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use super::super::authorize_request::{
    request_object_resolution_error_json_response, resolve_authorize_request_object_blocking,
    OwnedRequestObjectAuthorizeDeps, RequestObjectReplayPolicy, ResolvedAuthorizeRequestObject,
};
use super::super::oauth_errors::no_cache_json_error_with_iss;
use super::super::AppState;
use super::form::ParForm;
use crate::util;

pub(in crate::web) struct ParResolvedParameters {
    pub(super) resource: Option<String>,
    pub(super) redirect_uri: String,
    pub(super) response_type: String,
    pub(super) iss: Option<String>,
    pub(super) state: Option<String>,
    pub(super) code_challenge: String,
    pub(super) code_challenge_method: String,
    pub(super) scope: Option<String>,
    pub(super) nonce: Option<String>,
    pub(super) acr_values: Option<String>,
    pub(super) max_age: Option<u64>,
    pub(super) authorization_details: Option<Value>,
    pub(super) request_object: Option<String>,
    pub(super) request_object_claims: Option<RequestObjectClaims>,
}

pub(in crate::web) struct ParResolvedDraft {
    pub(in crate::web) resource: Option<String>,
    pub(in crate::web) redirect_uri: Option<String>,
    pub(in crate::web) response_type: Option<String>,
    pub(in crate::web) iss: Option<String>,
    pub(in crate::web) state: Option<String>,
    pub(in crate::web) code_challenge: Option<String>,
    pub(in crate::web) code_challenge_method: Option<String>,
    pub(in crate::web) scope: Option<String>,
    pub(in crate::web) nonce: Option<String>,
    pub(in crate::web) acr_values: Option<String>,
    pub(in crate::web) max_age: Option<u64>,
    pub(in crate::web) authorization_details: Option<Value>,
    pub(in crate::web) request_object: Option<String>,
    pub(in crate::web) request_object_claims: Option<RequestObjectClaims>,
}

pub(in crate::web) fn finalize_par_resolved_parameters(
    draft: ParResolvedDraft,
    issuer_base: &str,
) -> Result<ParResolvedParameters, Response> {
    let Some(redirect_uri) = draft.redirect_uri else {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            None,
            issuer_base,
        ));
    };
    let response_type = draft.response_type.unwrap_or_else(|| "code".to_string());
    if response_type != "code" {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("response_type must be 'code'"),
            issuer_base,
        ));
    }
    let Some(code_challenge) = draft.code_challenge else {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("code_challenge required"),
            issuer_base,
        ));
    };
    let code_challenge_method = draft
        .code_challenge_method
        .unwrap_or_else(|| "S256".to_string());
    if code_challenge_method != "S256" {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("code_challenge_method must be S256"),
            issuer_base,
        ));
    }

    Ok(ParResolvedParameters {
        resource: draft.resource,
        redirect_uri,
        response_type,
        iss: draft.iss,
        state: draft.state,
        code_challenge,
        code_challenge_method,
        scope: draft.scope,
        nonce: draft.nonce,
        acr_values: draft.acr_values,
        max_age: draft.max_age,
        authorization_details: draft.authorization_details,
        request_object: draft.request_object,
        request_object_claims: draft.request_object_claims,
    })
}

pub(super) async fn resolve_par_parameters(
    state: &AppState,
    form: &ParForm,
    client_id: &str,
    issuer_base: &str,
) -> Result<ParResolvedParameters, Response> {
    let mut resource = if form.request.is_some() {
        if !form.resource.is_empty() {
            return Err(no_cache_json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("resource must not be supplied outside request"),
                issuer_base,
            ));
        }
        None
    } else {
        util::parse_single_resource_indicator(&form.resource).map_err(|description| {
            no_cache_json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                Some(&description),
                issuer_base,
            )
        })?
    };
    let supported_authorization_details =
        state.cfg.authorization_details_types_supported.as_slice();
    let mut redirect_uri = form.redirect_uri.clone();
    let mut response_type = form.response_type.clone();
    let mut iss = form.iss.clone();
    let mut scope = form.scope.clone();
    let mut state_param = form.state.clone();
    let mut nonce = form.nonce.clone();
    let mut acr_values = form.acr_values.clone();
    let mut max_age = form.max_age;
    let mut code_challenge = form.code_challenge.clone();
    let mut code_challenge_method = form.code_challenge_method.clone();
    let mut authorization_details = if form.request.is_some() {
        if form.authorization_details.is_some() {
            return Err(no_cache_json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("authorization_details must not be supplied outside request"),
                issuer_base,
            ));
        }
        None
    } else {
        parse_par_authorization_details(
            form.authorization_details.as_deref(),
            supported_authorization_details,
        )?
    };
    let mut request_object = None;
    let mut request_object_claims = None;

    if let Some(request_jwt) = form.request.as_deref() {
        let resolved = resolve_par_request_object(
            state,
            client_id,
            request_jwt,
            issuer_base,
            supported_authorization_details,
        )
        .await?;
        redirect_uri = Some(resolved.redirect_uri);
        response_type = Some(resolved.response_type);
        iss = merge_par_request_object_issuer(
            form.iss.clone(),
            resolved.request_object_claims.iss.clone(),
            issuer_base,
        )?;
        scope = Some(resolved.scope);
        state_param = resolved.state;
        nonce = resolved.nonce;
        acr_values = resolved.acr_values;
        max_age = resolved.max_age;
        code_challenge = Some(resolved.code_challenge);
        code_challenge_method = Some(resolved.code_challenge_method);
        resource = resolved.resource;
        authorization_details = resolved.authorization_details;
        request_object = Some(resolved.request_object);
        request_object_claims = Some(resolved.request_object_claims);
    }

    finalize_par_resolved_parameters(
        ParResolvedDraft {
            resource,
            redirect_uri,
            response_type,
            iss,
            state: state_param,
            code_challenge,
            code_challenge_method,
            scope,
            nonce,
            acr_values,
            max_age,
            authorization_details,
            request_object,
            request_object_claims,
        },
        issuer_base,
    )
}

fn merge_par_request_object_issuer(
    form_iss: Option<String>,
    request_object_iss: Option<String>,
    issuer_base: &str,
) -> Result<Option<String>, Response> {
    match (form_iss, request_object_iss) {
        (Some(form), Some(request_object)) if form != request_object => {
            Err(no_cache_json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("iss mismatch between PAR request and Request Object"),
                issuer_base,
            ))
        }
        (Some(form), _) => Ok(Some(form)),
        (None, request_object) => Ok(request_object),
    }
}

fn parse_par_authorization_details(
    raw: Option<&str>,
    authorization_details_types_supported: &[String],
) -> Result<Option<Value>, Response> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    util::parse_authorization_details(raw, authorization_details_types_supported)
        .map(Some)
        .map_err(|description| {
            let mut response = (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_authorization_details",
                    "error_description": description,
                })),
            )
                .into_response();
            util::apply_no_cache_headers(&mut response);
            response
        })
}

async fn resolve_par_request_object(
    state: &AppState,
    client_id: &str,
    request_jwt: &str,
    issuer_base: &str,
    authorization_details_types_supported: &[String],
) -> Result<ResolvedAuthorizeRequestObject, Response> {
    let request_object_decryption_key = state.oidc.config.as_deref().and_then(|cfg| {
        cfg.request_object_encryption_key
            .as_ref()
            .map(crate::oidc::config::OidcRequestObjectEncryptionKey::pkcs8_der)
            .map(|der| der.to_vec())
    });
    let request_object_deps = OwnedRequestObjectAuthorizeDeps {
        clients: state.clients.clone(),
        request_object_jti_store: state.protocol.request_object_jti_store.clone(),
        jose_header_max_len: state.cfg.jose_header_max_len,
        request_object_decryption_key_pkcs8_der: request_object_decryption_key,
        crypto_profile: state.cfg.crypto_profile,
        jwt_leeway_secs: state.cfg.jwt_runtime().leeway_secs(),
        request_object_everparse_runtime_enabled: state
            .cfg
            .request_object_everparse_runtime_enabled,
    };
    let authorize_audience = format!("{issuer_base}/authorize");
    resolve_authorize_request_object_blocking(
        request_object_deps,
        client_id.to_string(),
        request_jwt.to_string(),
        authorize_audience,
        authorization_details_types_supported.to_vec(),
        RequestObjectReplayPolicy::Consume,
    )
    .await
    .map_err(|error| request_object_resolution_error_json_response(&error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    #[test]
    fn merge_par_request_object_issuer_accepts_matching_values() -> Result<(), String> {
        let iss = merge_par_request_object_issuer(
            Some("https://issuer.example".to_string()),
            Some("https://issuer.example".to_string()),
            "https://server.example",
        )
        .map_err(|_| "matching iss values should be accepted".to_string())?;

        assert_eq!(iss.as_deref(), Some("https://issuer.example"));
        Ok(())
    }

    #[test]
    fn merge_par_request_object_issuer_rejects_conflicting_values() -> Result<(), String> {
        let response = merge_par_request_object_issuer(
            Some("https://form-issuer.example".to_string()),
            Some("https://request-object-issuer.example".to_string()),
            "https://server.example",
        )
        .err()
        .ok_or_else(|| "conflicting iss values must fail closed".to_string())?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&axum::http::HeaderValue::from_static("no-store"))
        );
        Ok(())
    }
}
