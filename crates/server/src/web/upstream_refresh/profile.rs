use axum::{http::StatusCode, response::Response};

use super::super::oauth_errors::{json_error_with_iss, no_cache_json_error_with_iss};
use super::super::upstream_refresh_links::UpstreamRefreshLink;
use super::super::{AppState, OAUTH_PROFILE_TYPE_UPSTREAM};
use crate::oauth_profile;
use crate::policy::SenderConstraint;

fn record_upstream_refresh_profile_rejection(reason: &'static str) {
    crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
        metrics.record_oauth_profile_rejection(
            OAUTH_PROFILE_TYPE_UPSTREAM,
            reason,
            "upstream_refresh",
        );
    });
}

pub(in crate::web) fn validate_upstream_refresh_profile_policy(
    profile: &oauth_profile::ResolvedProfile,
    issuer_base: &str,
    auth_method: &str,
) -> Result<(), Response> {
    if !profile
        .allowed_grant_types
        .iter()
        .any(|value| value == "refresh_token")
    {
        record_upstream_refresh_profile_rejection("grant_type_disallowed");
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("refresh_token grant is not allowed"),
            issuer_base,
        ));
    }
    if !profile
        .token_endpoint_auth_methods_allowed
        .iter()
        .any(|value| value.eq_ignore_ascii_case(auth_method))
    {
        record_upstream_refresh_profile_rejection("token_endpoint_auth_disallowed");
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("upstream client auth method not allowed by profile"),
            issuer_base,
        ));
    }
    if profile.sender_constrained != SenderConstraint::None {
        record_upstream_refresh_profile_rejection("sender_constraint_disallowed");
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("sender constrained profiles are not supported upstream"),
            issuer_base,
        ));
    }
    Ok(())
}

pub(super) async fn resolve_upstream_refresh_profile(
    state: &AppState,
    issuer_base: &str,
    link: &UpstreamRefreshLink,
) -> Result<oauth_profile::ResolvedProfile, Response> {
    let profile = match oauth_profile::resolve_upstream_profile(
        &state.db_pool,
        issuer_base,
        &link.upstream_connection_identifier,
    )
    .await
    {
        Ok(profile) => profile,
        Err(oauth_profile::ProfileError::MissingProfile) => {
            record_upstream_refresh_profile_rejection("profile_missing");
            return Err(no_cache_json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("oauth profile is required"),
                issuer_base,
            ));
        }
        Err(oauth_profile::ProfileError::InvalidIssuer) => {
            record_upstream_refresh_profile_rejection("issuer_invalid");
            return Err(no_cache_json_error_with_iss(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("issuer is invalid"),
                issuer_base,
            ));
        }
        Err(oauth_profile::ProfileError::Database(_)) => {
            record_upstream_refresh_profile_rejection("lookup_failed");
            return Err(no_cache_json_error_with_iss(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("oauth profile lookup failed"),
                issuer_base,
            ));
        }
    };
    crate::metrics_integration::MetricsIntegration::with_global(|metrics| {
        metrics.record_oauth_profile_usage(OAUTH_PROFILE_TYPE_UPSTREAM, "upstream_refresh");
    });
    validate_upstream_refresh_profile_policy(&profile, issuer_base, &link.upstream_auth_method)?;
    Ok(profile)
}
