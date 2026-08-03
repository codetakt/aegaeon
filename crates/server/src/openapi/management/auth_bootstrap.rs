#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    post,
    path = "/api/v1/authentication/sessions",
    tag = "authentication",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)")
    ),
    request_body = CreateSessionRequest,
    responses(
        (status = 204, description = "Session created (cookie-based)", headers(
            ("Set-Cookie" = String, description = "Sets the management session cookie and CSRF cookie")
        )),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse)
    )
)]
pub(super) fn create_authentication_session() {}

#[utoipa::path(
    delete,
    path = "/api/v1/authentication/sessions/current",
    tag = "authentication",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)")
    ),
    responses(
        (status = 204, description = "Logged out"),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse)
    )
)]
pub(super) fn delete_current_authentication_session() {}

#[utoipa::path(
    post,
    path = "/api/v1/bootstrapping/owners",
    tag = "bootstrapping",
    params(
        ("Origin" = String, Header, description = "Origin header (must match admin console origin)")
    ),
    request_body = BootstrapOwnerRequest,
    responses(
        (status = 204, description = "Owner bootstrapped (one-time)"),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Forbidden (CSRF/origin check failed)", body = ErrorResponse),
        (status = 409, description = "Bootstrap already completed", body = ErrorResponse)
    )
)]
pub(super) fn bootstrap_owner() {}
