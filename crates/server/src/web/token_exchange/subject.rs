use axum::{http::StatusCode, response::Response};

use crate::authcode::types::{AccessToken, BearerTokenMeta, SenderBinding};
use crate::util;

use super::super::{token_error_response, AppState, TokenEndpointContext};

pub(super) async fn resolve_token_exchange_subject(
    state: &AppState,
    ctx: &TokenEndpointContext,
    subject_token: &str,
) -> Result<(AccessToken, BearerTokenMeta), Response> {
    let subject_auth_header = format!("Bearer {}", subject_token.trim());
    let (subject_access, subject_meta) = state
        .tokens
        .validator
        .validate_bearer_token_with_meta_async(subject_auth_header)
        .await
        .map_err(|err| {
            if err.is_internal() {
                tracing::error!(
                    target: "oauth",
                    error = %err,
                    "token exchange subject token validation failed internally"
                );
                token_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some(err.public_description()),
                )
            } else {
                token_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    Some("invalid subject_token"),
                )
            }
        })?;
    let subject_meta = subject_meta.ok_or_else(|| {
        token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("subject_token is unacceptable"),
        )
    })?;
    if subject_access.client_id != ctx.client_id || subject_meta.client_id != ctx.client_id {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("subject_token is unacceptable"),
        ));
    }
    if state.cfg.security_policy.retain_refresh_chain() {
        if let Some(parent) = subject_meta.refresh_parent.as_deref() {
            let revoked = state
                .tokens
                .store
                .try_is_refresh_revoked_async(parent.to_string())
                .await
                .map_err(|err| {
                    tracing::error!(
                        target: "oauth",
                        error = %err,
                        "token store refresh-chain lookup failed during token exchange"
                    );
                    token_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        Some("token store unavailable"),
                    )
                })?;
            if revoked {
                return Err(token_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    Some("subject_token is unacceptable"),
                ));
            }
        }
    }
    Ok((subject_access, subject_meta))
}

pub(in crate::web) fn validate_token_exchange_sender_binding(
    ctx: &TokenEndpointContext,
    subject_meta: &BearerTokenMeta,
) -> Result<(), Response> {
    match (&subject_meta.sender_binding, &ctx.sender_binding) {
        (None, _) => Ok(()),
        (Some(SenderBinding::DPoP { jkt: expected }), Some(SenderBinding::DPoP { jkt }))
            if util::jwk_thumbprint_matches(expected, jkt) =>
        {
            Ok(())
        }
        (
            Some(SenderBinding::Mtls {
                fingerprint: expected,
            }),
            Some(SenderBinding::Mtls { fingerprint }),
        ) if expected == fingerprint => Ok(()),
        _ => Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("subject_token sender binding mismatch"),
        )),
    }
}
