use axum::{http::StatusCode, response::Response};

use super::oauth_errors::no_cache_json_error_with_iss;
use super::{AppState, DEVICE_CODE_GRANT_TYPE, OAUTH_PROFILE_TYPE_DOWNSTREAM};
use crate::oauth_profile;
use crate::util;

pub(super) fn record_downstream_profile_rejection(reason: &str, endpoint: &str) {
    crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
        metrics.record_oauth_profile_rejection(OAUTH_PROFILE_TYPE_DOWNSTREAM, reason, endpoint);
    });
}

pub(super) fn record_downstream_profile_usage(
    _profile: &oauth_profile::ResolvedProfile,
    endpoint: &str,
) {
    crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
        metrics.record_oauth_profile_usage(OAUTH_PROFILE_TYPE_DOWNSTREAM, endpoint);
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProfilePolicyViolation {
    pub(super) reason: &'static str,
    status: StatusCode,
    error: &'static str,
    description: &'static str,
}

impl ProfilePolicyViolation {
    const fn invalid_request(reason: &'static str, description: &'static str) -> Self {
        Self {
            reason,
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            description,
        }
    }

    const fn unauthorized_client(reason: &'static str, description: &'static str) -> Self {
        Self {
            reason,
            status: StatusCode::BAD_REQUEST,
            error: "unauthorized_client",
            description,
        }
    }

    const fn invalid_client(reason: &'static str, description: &'static str) -> Self {
        Self {
            reason,
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_client",
            description,
        }
    }
}

fn profile_allows_auth_method(profile: &oauth_profile::ResolvedProfile, method: &str) -> bool {
    profile
        .token_endpoint_auth_methods_allowed
        .iter()
        .any(|allowed| allowed == method)
}

fn profile_allows_grant(profile: &oauth_profile::ResolvedProfile, grant_type: &str) -> bool {
    profile
        .allowed_grant_types
        .iter()
        .any(|allowed| allowed == grant_type)
}

fn profile_allows_response_type(
    _profile: &oauth_profile::ResolvedProfile,
    response_type: &str,
) -> bool {
    oauth_profile::normalize_response_type(response_type) == "code"
}

fn profile_requires_state(profile: &oauth_profile::ResolvedProfile) -> bool {
    profile.require_state_parameter
}

fn validate_profile_iss(
    profile: &oauth_profile::ResolvedProfile,
    iss: Option<&str>,
    issuer_base: &str,
) -> Result<(), ProfilePolicyViolation> {
    if !profile.require_iss_parameter {
        return Ok(());
    }
    match iss.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) if value == issuer_base => Ok(()),
        Some(_) => Err(ProfilePolicyViolation::invalid_request(
            "iss_mismatch",
            "iss must match issuer",
        )),
        None => Err(ProfilePolicyViolation::invalid_request(
            "iss_required",
            "iss is required",
        )),
    }
}

pub(super) fn validate_downstream_par_profile_policy(
    profile: &oauth_profile::ResolvedProfile,
    response_type: &str,
    state: Option<&str>,
    iss: Option<&str>,
    client_auth_method: &str,
    issuer_base: &str,
) -> Result<(), ProfilePolicyViolation> {
    if !profile_allows_response_type(profile, response_type) {
        return Err(ProfilePolicyViolation::unauthorized_client(
            "response_type_not_allowed",
            "response_type is not allowed",
        ));
    }
    if !profile_allows_grant(profile, "authorization_code") {
        return Err(ProfilePolicyViolation::unauthorized_client(
            "grant_type_not_allowed",
            "authorization_code grant is not allowed",
        ));
    }
    if !profile_allows_auth_method(profile, client_auth_method) {
        return Err(ProfilePolicyViolation::invalid_client(
            "token_auth_method_not_allowed",
            "client authentication method is not allowed by oauth profile",
        ));
    }
    if profile_requires_state(profile) && state.map(str::trim).is_none_or(|value| value.is_empty())
    {
        return Err(ProfilePolicyViolation::invalid_request(
            "state_required",
            "state is required",
        ));
    }
    validate_profile_iss(profile, iss, issuer_base)
}

pub(super) fn validate_downstream_device_profile_policy(
    profile: &oauth_profile::ResolvedProfile,
    client_auth_method: &str,
) -> Result<(), ProfilePolicyViolation> {
    if !profile_allows_grant(profile, DEVICE_CODE_GRANT_TYPE) {
        return Err(ProfilePolicyViolation::unauthorized_client(
            "grant_type_not_allowed",
            "device_code grant is not allowed",
        ));
    }
    if !profile_allows_auth_method(profile, client_auth_method) {
        return Err(ProfilePolicyViolation::invalid_client(
            "token_auth_method_not_allowed",
            "client authentication method is not allowed by oauth profile",
        ));
    }
    Ok(())
}

pub(super) fn validate_downstream_endpoint_auth_profile(
    profile: &oauth_profile::ResolvedProfile,
    client_auth_method: &str,
) -> Result<(), ProfilePolicyViolation> {
    if profile_allows_auth_method(profile, client_auth_method) {
        Ok(())
    } else {
        Err(ProfilePolicyViolation::invalid_client(
            "token_auth_method_not_allowed",
            "client authentication method is not allowed by oauth profile",
        ))
    }
}

pub(super) async fn resolve_downstream_profile_for_endpoint(
    state: &AppState,
    issuer_base: &str,
    client_id: &str,
    endpoint: &'static str,
) -> Result<oauth_profile::ResolvedProfile, Response> {
    let profile =
        match oauth_profile::resolve_downstream_profile(&state.db_pool, issuer_base, client_id)
            .await
        {
            Ok(profile) => profile,
            Err(oauth_profile::ProfileError::MissingProfile) => {
                record_downstream_profile_rejection("profile_missing", endpoint);
                return Err(no_cache_json_error_with_iss(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    Some("oauth profile is required"),
                    issuer_base,
                ));
            }
            Err(oauth_profile::ProfileError::InvalidIssuer) => {
                record_downstream_profile_rejection("issuer_invalid", endpoint);
                return Err(no_cache_json_error_with_iss(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some("issuer is invalid"),
                    issuer_base,
                ));
            }
            Err(oauth_profile::ProfileError::Database(_)) => {
                record_downstream_profile_rejection("lookup_failed", endpoint);
                return Err(no_cache_json_error_with_iss(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some("oauth profile lookup failed"),
                    issuer_base,
                ));
            }
        };
    record_downstream_profile_usage(&profile, endpoint);
    Ok(profile)
}

pub(super) fn downstream_profile_violation_response(
    violation: ProfilePolicyViolation,
    endpoint: &'static str,
    realm: &str,
    issuer_base: &str,
) -> Response {
    record_downstream_profile_rejection(violation.reason, endpoint);
    if violation.error == "invalid_client" {
        util::invalid_client_response(realm, violation.description)
    } else {
        no_cache_json_error_with_iss(
            violation.status,
            violation.error,
            Some(violation.description),
            issuer_base,
        )
    }
}
