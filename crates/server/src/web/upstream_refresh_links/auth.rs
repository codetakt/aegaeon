use axum::{
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};

use super::super::oauth_errors::{
    apply_oauth_authenticate_header, authorization_header, bearer_validation_error_response,
    dpop_invalid_token_response, json_error_with_iss, no_cache_header_error,
};
use super::super::{
    dpop_binding_from_request, trusted_mtls_fingerprint, AppState, RESOURCE_SCOPES,
    X_FORWARDED_CLIENT_CERT_HEADER,
};
use super::UpstreamRefreshCaller;
use crate::authcode::{BearerTokenValidationError, TokenPolicyContext, TokenPolicyError};
use crate::util;

struct RefreshAuthorizationHeader {
    challenge_scheme: &'static str,
    normalized_auth: String,
}

fn malformed_authorization_header_response(issuer_base: &str) -> Response {
    json_error_with_iss(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        Some("malformed authorization header"),
        issuer_base,
    )
}

fn refresh_authorization_header(
    auth_header: &str,
    issuer_base: &str,
) -> Result<RefreshAuthorizationHeader, Response> {
    let mut header_parts = auth_header.split_whitespace();
    let scheme = header_parts
        .next()
        .ok_or_else(|| malformed_authorization_header_response(issuer_base))?;
    let token_part = header_parts
        .next()
        .ok_or_else(|| malformed_authorization_header_response(issuer_base))?;
    if token_part.is_empty() || header_parts.next().is_some() {
        return Err(malformed_authorization_header_response(issuer_base));
    }
    let challenge_scheme = if scheme.eq_ignore_ascii_case("DPoP") {
        "DPoP"
    } else {
        "Bearer"
    };
    let normalized_auth = match scheme.to_ascii_lowercase().as_str() {
        "bearer" | "dpop" => format!("Bearer {token_part}"),
        _ => {
            return Err(json_error_with_iss(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                Some("authorization scheme must be Bearer or DPoP"),
                issuer_base,
            ));
        }
    };
    Ok(RefreshAuthorizationHeader {
        challenge_scheme,
        normalized_auth,
    })
}

pub(in crate::web) async fn authenticate_upstream_refresh_caller(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    issuer_base: &str,
) -> Result<UpstreamRefreshCaller, Response> {
    let auth_header = authorization_header(headers)
        .map_err(|err| {
            let description = err.description("Authorization");
            json_error_with_iss(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                Some(&description),
                issuer_base,
            )
        })?
        .ok_or_else(|| {
            json_error_with_iss(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                Some("bearer token required"),
                issuer_base,
            )
        })?;

    let RefreshAuthorizationHeader {
        challenge_scheme,
        normalized_auth,
    } = refresh_authorization_header(auth_header, issuer_base)?;

    let path = uri
        .path_and_query()
        .map_or(uri.path(), axum::http::uri::PathAndQuery::as_str);
    let uri_for_dpop: Uri = path
        .parse()
        .map_err(|_| dpop_invalid_token_response(issuer_base, "DPoP proof validation failed"))?;
    let binding = dpop_binding_from_request(
        state.dpop.as_ref(),
        &Method::POST,
        &uri_for_dpop,
        headers,
        issuer_base,
    )?;
    let binding_jkt = binding.as_ref().map(|binding| binding.jkt.as_str());
    let mtls_fingerprint = trusted_mtls_fingerprint(state, headers)
        .map_err(|err| no_cache_header_error(issuer_base, X_FORWARDED_CLIENT_CERT_HEADER, err))?;

    let (_, meta) = state
        .tokens
        .validator
        .validate_bearer_token_with_meta_async(normalized_auth)
        .await
        .map_err(|err| bearer_validation_error_response(issuer_base, challenge_scheme, &err))?;
    let meta = meta.ok_or_else(|| {
        let mut response = json_error_with_iss(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            Some("bearer token metadata unavailable"),
            issuer_base,
        );
        apply_oauth_authenticate_header(&mut response, challenge_scheme, "invalid_token");
        util::apply_no_cache_headers(&mut response);
        response
    })?;
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
            if binding_jkt.is_some() {
                "DPoP"
            } else {
                challenge_scheme
            },
        ));
    }

    Ok(UpstreamRefreshCaller {
        user_id: meta.user_id.clone(),
        caller_client_id: meta.client_id.clone(),
    })
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
    apply_oauth_authenticate_header(&mut response, challenge_scheme, error);
    util::apply_no_cache_headers(&mut response);
    response
}
