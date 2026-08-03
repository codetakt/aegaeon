#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/credentials",
    tag = "users",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "User credential state", body = UserCredentialsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn get_user_credentials() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/activationTokens",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    request_body = IssueRecoveryTokenRequest,
    responses(
        (status = 200, description = "Activation token issued", body = IssueRecoveryTokenResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn issue_activation_token() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/passwordResetTokens",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    request_body = IssueRecoveryTokenRequest,
    responses(
        (status = 200, description = "Password reset token issued", body = IssueRecoveryTokenResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn issue_password_reset_token() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/credentials/password/revoke",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Password credential revoked", body = UserCredentialsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Active password credential not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn revoke_user_password_credential() {}

#[utoipa::path(
    post,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/recoveryTokens/{tokenId}/revoke",
    tag = "users",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)"),
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("userId" = String, Path, description = "User identifier (UUIDv4)"),
        ("tokenId" = String, Path, description = "Recovery token identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Recovery token revoked", body = UserCredentialsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 404, description = "Active recovery token not found", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn revoke_user_recovery_token() {}
