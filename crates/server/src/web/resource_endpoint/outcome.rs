use super::super::oauth_errors::{
    apply_oauth_authenticate_header, json_error_with_iss, no_cache_json_error_with_iss,
};
use axum::{http::StatusCode, response::IntoResponse, response::Response, Json};

use crate::authcode::types::BearerTokenMeta;
use crate::authcode::TokenPolicyError;
use crate::util;

pub(in crate::web) struct ResourceOutcome {
    pub(in crate::web) response: Response,
    pub(in crate::web) mode: String,
    pub(in crate::web) success: bool,
    pub(in crate::web) reason: Option<String>,
    pub(in crate::web) validated_metadata: Option<BearerTokenMeta>,
}

impl ResourceOutcome {
    pub(super) async fn check_application(
        self,
        state: &super::AppState,
        authorization: Option<&str>,
    ) -> Self {
        if !self.success {
            return self;
        }
        let (Some(meta), Some(header)) = (self.validated_metadata.as_ref(), authorization) else {
            return Self::failure(
                crate::web::token_internal_error_response("resource_validated_metadata", None),
                self.mode,
                "resource_validated_metadata_missing",
            );
        };
        match crate::web::application_authorization::check_resource(state, meta, header).await {
            Ok(()) => self,
            Err(response) => {
                let reason = if response.status().is_server_error() {
                    "application_authority_unavailable"
                } else {
                    "application_authorization_changed"
                };
                Self::failure(response, self.mode, reason)
            }
        }
    }

    fn success(response: Response, mode: String, meta: &BearerTokenMeta) -> Self {
        Self {
            response,
            mode,
            success: true,
            reason: None,
            validated_metadata: Some(meta.clone()),
        }
    }

    fn failure(response: Response, mode: String, reason: impl Into<String>) -> Self {
        Self {
            response,
            mode,
            success: false,
            reason: Some(reason.into()),
            validated_metadata: None,
        }
    }
}

pub(super) fn resource_success(
    meta: &BearerTokenMeta,
    issuer_base: &str,
    mode: String,
) -> ResourceOutcome {
    let body = serde_json::json!({
        "status": "granted",
        "client_id": meta.client_id,
        "subject": meta.user_id,
        "scopes": meta.granted_scopes,
        "audience": meta.audience,
        "iss": issuer_base,
    });
    let mut response = (StatusCode::OK, Json(body)).into_response();
    util::apply_no_cache_headers(&mut response);
    ResourceOutcome::success(response, mode, meta)
}

pub(super) fn resource_error_with_mode(
    issuer_base: &str,
    status: StatusCode,
    error: &str,
    description: &str,
    mode: String,
) -> ResourceOutcome {
    let mut response = json_error_with_iss(status, error, Some(description), issuer_base);
    let challenge_scheme = if mode == "dpop" { "DPoP" } else { "Bearer" };
    apply_oauth_authenticate_header(&mut response, challenge_scheme, error);
    util::apply_no_cache_headers(&mut response);
    ResourceOutcome::failure(response, mode, description)
}

pub(super) fn resource_internal_error_with_mode(
    issuer_base: &str,
    description: &'static str,
    mode: String,
) -> ResourceOutcome {
    let response = no_cache_json_error_with_iss(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        Some(description),
        issuer_base,
    );
    ResourceOutcome::failure(response, mode, description)
}

pub(super) fn map_policy_error(
    err: &TokenPolicyError,
    issuer_base: &str,
    mode: String,
) -> ResourceOutcome {
    match err {
        TokenPolicyError::Validation(validation_error) if validation_error.is_internal() => {
            resource_internal_error_with_mode(
                issuer_base,
                validation_error.public_description(),
                mode,
            )
        }
        TokenPolicyError::Validation(validation_error) => {
            let description = validation_error.to_string();
            resource_error_with_mode(
                issuer_base,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                &description,
                mode,
            )
        }
        TokenPolicyError::InsufficientScope { .. } => resource_error_with_mode(
            issuer_base,
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            &err.to_string(),
            mode,
        ),
        TokenPolicyError::InvalidAudience => resource_error_with_mode(
            issuer_base,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "invalid_audience",
            mode,
        ),
        TokenPolicyError::SenderBindingMissing => resource_error_with_mode(
            issuer_base,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "sender_binding_missing",
            mode,
        ),
        TokenPolicyError::SenderBindingMismatch => resource_error_with_mode(
            issuer_base,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "sender_binding_mismatch",
            mode,
        ),
        TokenPolicyError::RefreshParentRevoked => resource_error_with_mode(
            issuer_base,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "refresh_parent_revoked",
            mode,
        ),
        TokenPolicyError::TokenStoreUnavailable(_) => {
            resource_internal_error_with_mode(issuer_base, "token store unavailable", mode)
        }
        TokenPolicyError::BearerMetadataUnavailable
        | TokenPolicyError::ResourceAudienceRequired => {
            let description = err.to_string();
            resource_error_with_mode(
                issuer_base,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                &description,
                mode,
            )
        }
    }
}
