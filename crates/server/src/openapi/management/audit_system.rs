#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::wildcard_imports)] // OpenAPI DTO modules intentionally import the shared schema prelude.
use crate::openapi::types::*;

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/auditEvents",
    tag = "audit",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Audit events list (team scope)", body = ListAuditEventsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(super) fn list_team_audit_events() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/environments/{environmentId}/auditEvents",
    tag = "audit",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("environmentId" = String, Path, description = "Environment identifier (UUIDv4)"),
        ("pageSize" = Option<u32>, Query, description = "Page size (max 200)"),
        ("pageToken" = Option<String>, Query, description = "Opaque pagination token")
    ),
    responses(
        (status = 200, description = "Audit events list (environment scope)", body = ListAuditEventsResponse),
        (status = 401, description = "Unauthenticated", body = ErrorResponse)
    )
)]
pub(super) fn list_environment_audit_events() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{teamId}/auditEvents/{auditEventId}",
    tag = "audit",
    params(
        ("teamId" = String, Path, description = "Team identifier (UUIDv4)"),
        ("auditEventId" = String, Path, description = "Audit event identifier (UUIDv4)")
    ),
    responses(
        (status = 200, description = "Audit event", body = AuditEvent),
        (status = 401, description = "Unauthenticated", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse)
    )
)]
pub(super) fn get_audit_event() {}

#[utoipa::path(
    get,
    path = "/api/v1/system/health",
    tag = "system",
    responses(
        (status = 200, description = "Control plane is healthy", body = String, content_type = "text/plain")
    )
)]
pub(super) fn system_health() {}

#[utoipa::path(
    get,
    path = "/api/v1/system/version",
    tag = "system",
    responses(
        (status = 200, description = "Control plane version", body = SystemVersionResponse)
    )
)]
pub(super) fn system_version() {}
