use super::super::dcr_response::invalid_client_metadata_response;
use super::super::oauth_errors::no_cache_json_error_with_iss;
use super::super::{AppState, OAUTH_PROFILE_TYPE_DOWNSTREAM};
use axum::{http::StatusCode, response::Response};

use crate::dcr::ClientRegistration;
use crate::oauth_profile;
use crate::policy::SenderConstraint;

fn normalize_dcr_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalize_dcr_response_types(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| oauth_profile::normalize_response_type(value))
        .filter(|value| !value.is_empty())
        .collect()
}

fn declared_sender_methods(meta: &ClientRegistration) -> Vec<String> {
    let mut declared = std::collections::BTreeSet::new();
    if let Some(methods) = meta.sender_constrained_methods.as_ref() {
        for method in methods {
            let normalized = method.trim().to_ascii_lowercase();
            if !normalized.is_empty() {
                declared.insert(normalized);
            }
        }
    }
    if meta.require_dpop == Some(true) {
        declared.insert("dpop".to_string());
    }
    if meta.require_mtls == Some(true) {
        declared.insert("mtls".to_string());
    }
    declared.into_iter().collect()
}

pub(super) struct ProfileRegistrationViolation {
    pub(super) code: &'static str,
    message: &'static str,
}

impl ProfileRegistrationViolation {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

pub(super) fn validate_registration_against_profile(
    meta: &ClientRegistration,
    profile: &oauth_profile::ResolvedProfile,
) -> Result<(), ProfileRegistrationViolation> {
    let grant_types = meta.grant_types.as_ref().map_or_else(
        || {
            vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ]
        },
        |values| normalize_dcr_list(values),
    );
    if grant_types.is_empty() {
        return Err(ProfileRegistrationViolation::new(
            "grant_types_empty",
            "grant_types must not be empty",
        ));
    }
    if grant_types
        .iter()
        .any(|grant| !profile.allowed_grant_types.contains(grant))
    {
        return Err(ProfileRegistrationViolation::new(
            "grant_types_not_allowed",
            "grant_types contains values not allowed by oauth profile",
        ));
    }

    let response_types = meta.response_types.as_ref().map_or_else(
        || vec!["code".to_string()],
        |values| normalize_dcr_response_types(values),
    );
    if response_types.is_empty() {
        return Err(ProfileRegistrationViolation::new(
            "response_types_empty",
            "response_types must not be empty",
        ));
    }
    if response_types.iter().any(|response| response != "code") {
        return Err(ProfileRegistrationViolation::new(
            "response_types_not_allowed",
            "response_types contains values not allowed by oauth profile",
        ));
    }

    let auth_method = meta
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_basic")
        .trim()
        .to_ascii_lowercase();
    if !profile
        .token_endpoint_auth_methods_allowed
        .iter()
        .any(|method| method == &auth_method)
    {
        return Err(ProfileRegistrationViolation::new(
            "token_auth_method_not_allowed",
            "token_endpoint_auth_method is not allowed by oauth profile",
        ));
    }

    if profile.require_pkce && meta.pkce_required == Some(false) {
        return Err(ProfileRegistrationViolation::new(
            "pkce_required",
            "pkce_required must be true for this oauth profile",
        ));
    }

    let declared_methods = declared_sender_methods(meta);
    let requires_sender =
        meta.require_sender_constrained_tokens == Some(true) || !declared_methods.is_empty();
    match profile.sender_constrained {
        SenderConstraint::None => {
            if requires_sender {
                return Err(ProfileRegistrationViolation::new(
                    "sender_constrained_not_allowed",
                    "sender-constrained tokens are not allowed by oauth profile",
                ));
            }
        }
        SenderConstraint::DPoP => {
            if declared_methods.iter().any(|method| method == "mtls") {
                return Err(ProfileRegistrationViolation::new(
                    "sender_constrained_mtls_not_allowed",
                    "mtls sender-constrained method is not allowed",
                ));
            }
        }
        SenderConstraint::Mtls => {
            if declared_methods.iter().any(|method| method == "dpop") {
                return Err(ProfileRegistrationViolation::new(
                    "sender_constrained_dpop_not_allowed",
                    "dpop sender-constrained method is not allowed",
                ));
            }
        }
    }

    Ok(())
}

fn record_dcr_profile_rejection(reason: &'static str) {
    crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
        metrics.record_oauth_profile_rejection(OAUTH_PROFILE_TYPE_DOWNSTREAM, reason, "dcr");
    });
}

pub(super) async fn resolve_dcr_profile(
    state: &AppState,
    issuer_base: &str,
) -> Result<oauth_profile::ResolvedProfile, Response> {
    match oauth_profile::resolve_default_profile(&state.db_pool, issuer_base, "DOWNSTREAM").await {
        Ok(profile) => Ok(profile),
        Err(oauth_profile::ProfileError::MissingProfile) => {
            record_dcr_profile_rejection("profile_missing");
            Err(no_cache_json_error_with_iss(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("oauth profile is required"),
                issuer_base,
            ))
        }
        Err(oauth_profile::ProfileError::InvalidIssuer) => {
            record_dcr_profile_rejection("issuer_invalid");
            Err(no_cache_json_error_with_iss(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("issuer is invalid"),
                issuer_base,
            ))
        }
        Err(oauth_profile::ProfileError::Database(_)) => {
            record_dcr_profile_rejection("lookup_failed");
            Err(no_cache_json_error_with_iss(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("oauth profile lookup failed"),
                issuer_base,
            ))
        }
    }
}

pub(super) fn validate_registration_profile_or_response(
    meta: &ClientRegistration,
    profile: &oauth_profile::ResolvedProfile,
) -> Result<(), Response> {
    crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
        metrics.record_oauth_profile_usage(OAUTH_PROFILE_TYPE_DOWNSTREAM, "dcr");
    });
    validate_registration_against_profile(meta, profile).map_err(|error| {
        record_dcr_profile_rejection(error.code);
        invalid_client_metadata_response(error.message)
    })
}
