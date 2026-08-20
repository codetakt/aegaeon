use axum::{http::StatusCode, response::Response};

use crate::oauth_profile;
use crate::policy::SenderConstraint;

use super::super::oauth_errors::no_cache_json_error_with_iss;
use super::super::profile_policy::{
    record_downstream_profile_rejection, record_downstream_profile_usage,
};
use super::super::token_response::{token_error_response, token_registry_state_error_response};
use super::super::AppState;

pub(super) struct TokenEndpointPolicyContext {
    pub(super) sender_constraint: SenderConstraint,
    pub(super) enforce_refresh_sender_binding: bool,
    pub(super) authorization_code_grant_allowed: bool,
    pub(super) refresh_grant_allowed: bool,
}

#[expect(
    clippy::too_many_lines,
    reason = "existing token policy workflow; new oversized functions remain gated"
)]
pub(super) async fn token_resolve_policy(
    state: &AppState,
    client_id: &str,
    grant_type: &str,
    issuer_base: &str,
    client_auth_method: &'static str,
) -> Result<TokenEndpointPolicyContext, Response> {
    let profile =
        match oauth_profile::resolve_downstream_profile(&state.db_pool, issuer_base, client_id)
            .await
        {
            Ok(profile) => profile,
            Err(oauth_profile::ProfileError::MissingProfile) => {
                record_downstream_profile_rejection("profile_missing", "token");
                return Err(no_cache_json_error_with_iss(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    Some("oauth profile is required"),
                    issuer_base,
                ));
            }
            Err(oauth_profile::ProfileError::InvalidIssuer) => {
                record_downstream_profile_rejection("issuer_invalid", "token");
                return Err(no_cache_json_error_with_iss(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some("issuer is invalid"),
                    issuer_base,
                ));
            }
            Err(oauth_profile::ProfileError::Database(_)) => {
                record_downstream_profile_rejection("lookup_failed", "token");
                return Err(no_cache_json_error_with_iss(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some("oauth profile lookup failed"),
                    issuer_base,
                ));
            }
        };
    record_downstream_profile_usage(&profile, "token");
    if grant_type == "password" {
        record_downstream_profile_rejection("grant_type_not_allowed", "token");
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            None,
        ));
    }
    let current_grant_allowed = state
        .clients
        .try_allows_grant(client_id, grant_type)
        .map_err(|error| token_registry_state_error_response("token_policy_allows_grant", error))?;
    if grant_type == "refresh_token" && !current_grant_allowed {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            None,
        ));
    }
    let grant_allowed = profile
        .allowed_grant_types
        .iter()
        .any(|allowed_grant| allowed_grant == grant_type);
    if !grant_allowed && grant_type != "authorization_code" {
        record_downstream_profile_rejection("grant_type_not_allowed", "token");
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            None,
        ));
    }
    if !profile
        .token_endpoint_auth_methods_allowed
        .iter()
        .any(|method| method == client_auth_method)
    {
        record_downstream_profile_rejection("token_auth_method_not_allowed", "token");
        return Err(token_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            None,
        ));
    }
    let sender_constraint = oauth_profile::merge_sender_constraints(
        state.cfg.security_policy.sender_constrained,
        profile.sender_constrained,
    );
    let enforce_refresh_sender_binding = state.cfg.security_policy.enforce_sender_binding()
        || profile.enforce_refresh_sender_binding;
    let authorization_code_grant_allowed = state
        .clients
        .try_allows_grant(client_id, "authorization_code")
        .map_err(|error| {
            token_registry_state_error_response(
                "token_policy_authorization_code_allows_grant",
                error,
            )
        })?
        && profile
            .allowed_grant_types
            .iter()
            .any(|grant| grant == "authorization_code");
    let refresh_grant_allowed = state
        .clients
        .try_allows_grant(client_id, "refresh_token")
        .map_err(|error| {
            token_registry_state_error_response("token_policy_refresh_allows_grant", error)
        })?
        && profile
            .allowed_grant_types
            .iter()
            .any(|grant| grant == "refresh_token");
    Ok(TokenEndpointPolicyContext {
        sender_constraint,
        enforce_refresh_sender_binding,
        authorization_code_grant_allowed,
        refresh_grant_allowed,
    })
}
