use super::super::oauth_errors::json_error_with_iss;
use super::super::upstream_logout_incidents::load_active_logout_recovery_policy_for_connection;
use super::super::{normalize_issuer, AppState};
use super::connection::{
    load_upstream_connection, upstream_authorize_auth_material, UpstreamConnection,
};
use super::profile::resolve_upstream_authorize_profile;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

use crate::oauth_profile;

pub(super) struct UpstreamAuthorizeContext {
    pub(super) connection: UpstreamConnection,
    pub(super) issuer: String,
    pub(super) auth_method: String,
    pub(super) profile: oauth_profile::ResolvedProfile,
    pub(super) active_logout_recovery_policy: Option<crate::upstream::UpstreamLogoutRecoveryPolicy>,
}

pub(super) async fn load_upstream_authorize_context(
    state: &AppState,
    pool: &PgPool,
    issuer_base: &str,
    connection_id: &str,
) -> Result<UpstreamAuthorizeContext, Response> {
    let connection = load_upstream_connection(pool, issuer_base, connection_id)
        .await
        .map_err(|message| {
            json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(&message),
                issuer_base,
            )
        })?;
    if !connection.connection_type.eq_ignore_ascii_case("oidc") {
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("connection type must be oidc"),
            issuer_base,
        ));
    }
    let auth_method = upstream_authorize_auth_material(&connection, issuer_base)?;
    let issuer = normalize_issuer(&connection.issuer_url).ok_or_else(|| {
        json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("upstream issuer invalid"),
            issuer_base,
        )
    })?;
    let profile = resolve_upstream_authorize_profile(
        state,
        issuer_base,
        &connection.connection_identifier,
        &auth_method,
    )
    .await?;
    let active_logout_recovery_policy =
        load_active_logout_recovery_policy_for_connection(pool, connection.id)
            .await
            .map_err(|message| {
                json_error_with_iss(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    Some(&message),
                    issuer_base,
                )
            })?;
    if matches!(
        active_logout_recovery_policy,
        Some(crate::upstream::UpstreamLogoutRecoveryPolicy::DisableConnection)
    ) {
        return Err(json_error_with_iss(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            Some("upstream connection requires operator remediation before reuse"),
            issuer_base,
        ));
    }

    Ok(UpstreamAuthorizeContext {
        connection,
        issuer,
        auth_method,
        profile,
        active_logout_recovery_policy,
    })
}
