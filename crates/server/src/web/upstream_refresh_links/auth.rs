use crate::middleware::dpop::DpopEndpointRole;
use crate::web::token_sender_binding::dpop_error_response;
use axum::{
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};

use super::super::oauth_errors::{
    apply_oauth_authenticate_header, authorization_header, bearer_header_error,
    bearer_validation_error_response, dpop_invalid_token_response, json_error_with_iss,
};
use super::super::resource_authentication::{
    admit_resource_presentation, resource_invalid_request,
};
use super::super::{
    dpop_binding_from_request, trusted_mtls_fingerprint, AppState, RESOURCE_SCOPES,
    X_FORWARDED_CLIENT_CERT_HEADER,
};
use super::UpstreamRefreshCaller;
use crate::authcode::types::SenderBinding;
use crate::authcode::{BearerTokenValidationError, TokenPolicyContext, TokenPolicyError};
use crate::util;

pub(in crate::web) async fn authenticate_upstream_refresh_caller(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    issuer_base: &str,
) -> Result<UpstreamRefreshCaller, Response> {
    let auth_header = authorization_header(headers)
        .map_err(|err| bearer_header_error(issuer_base, "Authorization", err))?;
    let credentials = admit_resource_presentation(auth_header, issuer_base)?;
    let challenge_scheme = credentials.scheme.as_str();
    let normalized_auth = credentials.normalized_authorization();

    let path = uri
        .path_and_query()
        .map_or(uri.path(), axum::http::uri::PathAndQuery::as_str);
    let uri_for_dpop: Uri = path
        .parse()
        .map_err(|_| dpop_invalid_token_response(issuer_base, "DPoP proof validation failed"))?;
    let binding = dpop_binding_from_request(
        state.dpop.as_ref(),
        DpopEndpointRole::ResourceServer,
        &Method::POST,
        &uri_for_dpop,
        headers,
    )
    .map_err(|error| dpop_error_response(issuer_base, DpopEndpointRole::ResourceServer, error))?;
    let binding_jkt = binding.as_ref().map(|binding| binding.jkt.as_str());
    let mtls_fingerprint = trusted_mtls_fingerprint(state, headers).map_err(|err| {
        resource_invalid_request(
            issuer_base,
            credentials.scheme,
            &err.description(X_FORWARDED_CLIENT_CERT_HEADER),
        )
    })?;

    let (_, meta) = state
        .tokens
        .validator
        .validate_bearer_token_with_meta_async(normalized_auth)
        .await
        .map_err(|err| bearer_validation_error_response(issuer_base, challenge_scheme, &err))?;
    let meta =
        meta.ok_or_else(|| missing_bearer_metadata_response(issuer_base, challenge_scheme))?;
    if !crate::web::client_credentials_authorization::current(state, &meta).await? {
        return Err(upstream_refresh_policy_error(
            &TokenPolicyError::Validation(BearerTokenValidationError::Invalid(
                "client-credentials authority is no longer current".into(),
            )),
            issuer_base,
            challenge_scheme,
        ));
    }
    // RFC 9449 section 7.2: a proof cannot turn Bearer presentation into DPoP.
    if matches!(meta.sender_binding, Some(SenderBinding::DPoP { .. }))
        != (challenge_scheme == "DPoP")
    {
        return Err(upstream_refresh_policy_error(
            &TokenPolicyError::SenderBindingMismatch,
            issuer_base,
            challenge_scheme,
        ));
    }
    let resource_audience = crate::resource_audience::upstream_refresh(issuer_base);
    if let Err(err) = state
        .tokens
        .validator
        .enforce_with_meta_async(
            &meta,
            TokenPolicyContext {
                requested_scopes: &RESOURCE_SCOPES,
                resource_audience: Some(resource_audience.as_str()),
                sender_dpop_jkt: binding_jkt,
                sender_mtls_fingerprint: mtls_fingerprint.as_deref(),
            },
        )
        .await
    {
        return Err(upstream_refresh_policy_error(
            &err,
            issuer_base,
            challenge_scheme,
        ));
    }

    Ok(UpstreamRefreshCaller {
        scheme: credentials.scheme,
        user_id: meta.user_id.clone(),
        caller_client_id: meta.client_id.clone(),
    })
}

fn missing_bearer_metadata_response(issuer_base: &str, challenge_scheme: &'static str) -> Response {
    let mut response = json_error_with_iss(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        Some("bearer token metadata unavailable"),
        issuer_base,
    );
    apply_oauth_authenticate_header(&mut response, challenge_scheme, "invalid_token");
    util::apply_no_cache_headers(&mut response);
    response
}

fn upstream_refresh_policy_error(
    err: &TokenPolicyError,
    issuer_base: &str,
    challenge_scheme: &'static str,
) -> Response {
    let (status, error, description) = match err {
        TokenPolicyError::InsufficientScope { .. } => {
            (StatusCode::FORBIDDEN, "insufficient_scope", err.to_string())
        }
        TokenPolicyError::Validation(BearerTokenValidationError::Internal(_))
        | TokenPolicyError::TokenStoreUnavailable(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            err.public_description(),
        ),
        TokenPolicyError::Validation(BearerTokenValidationError::Invalid(_))
        | TokenPolicyError::BearerMetadataUnavailable
        | TokenPolicyError::ResourceAudienceRequired
        | TokenPolicyError::InvalidAudience
        | TokenPolicyError::SenderBindingMissing
        | TokenPolicyError::SenderBindingMismatch
        | TokenPolicyError::RefreshParentRevoked => {
            (StatusCode::UNAUTHORIZED, "invalid_token", err.to_string())
        }
    };
    let mut response = json_error_with_iss(status, error, Some(&description), issuer_base);
    if !status.is_server_error() {
        apply_oauth_authenticate_header(&mut response, challenge_scheme, error);
    }
    util::apply_no_cache_headers(&mut response);
    response
}

#[cfg(test)]
mod resource_policy_error_tests {
    use super::*;
    #[test]
    fn upstream_refresh_internal_policy_errors_never_challenge() {
        for error in [
            TokenPolicyError::TokenStoreUnavailable("private fixture detail".into()),
            TokenPolicyError::Validation(BearerTokenValidationError::Internal(
                "private fixture detail".into(),
            )),
        ] {
            let response = upstream_refresh_policy_error(&error, "https://issuer.example", "DPoP");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(!response.headers().contains_key("www-authenticate"));
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["pragma"], "no-cache");
        }
    }
}
