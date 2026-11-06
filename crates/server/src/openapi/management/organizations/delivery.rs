#![allow(dead_code)] // OpenAPI metadata markers.
use crate::openapi::types::ErrorResponse;
use crate::organizations::operators::mutations::delivery::Configuration;

#[utoipa::path(get, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/invitation-delivery", operation_id = "organization_domain_get_by_domain_invitation_delivery", tag="organizations",
    description="Explicit domain delivery configuration. Current configure capability; credentials are never stored. Disable uses reserved cancellation admission.",
    security(("managementSessionCookie" = [])), params(("team" = String, Path, format="uuid"), ("environment" = String, Path, format="uuid"), ("domain" = String, Path, format="uuid")),
    responses((status=200, description="No-store; strong domain ETag", body=Configuration, headers(("ETag"=String))),
        (status=400, description="Invalid or ambiguous input", body=ErrorResponse),
        (status=401, description="Current human session required", body=ErrorResponse),
        (status=403, description="Current scope/CSRF/capability refused", body=ErrorResponse),
        (status=409, description="Conflict or finite capacity exhausted", body=ErrorResponse),
        (status=412, description="Stale precondition", body=ErrorResponse),
        (status=428, description="Precondition required", body=ErrorResponse),
        (status=503, description="Store or admission unavailable", body=ErrorResponse))
)]
pub(in crate::openapi::management) fn read() {}

#[utoipa::path(head, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/invitation-delivery", operation_id = "organization_domain_head_by_domain_invitation_delivery", tag="organizations",
    description="Explicit domain delivery configuration. Current configure capability; credentials are never stored. Disable uses reserved cancellation admission.",
    security(("managementSessionCookie" = [])), params(("team" = String, Path, format="uuid"), ("environment" = String, Path, format="uuid"), ("domain" = String, Path, format="uuid")),
    responses((status=200, description="No-store; strong domain ETag",  headers(("ETag"=String))),
        (status=400, description="Invalid or ambiguous input", body=ErrorResponse),
        (status=401, description="Current human session required", body=ErrorResponse),
        (status=403, description="Current scope/CSRF/capability refused", body=ErrorResponse),
        (status=409, description="Conflict or finite capacity exhausted", body=ErrorResponse),
        (status=412, description="Stale precondition", body=ErrorResponse),
        (status=428, description="Precondition required", body=ErrorResponse),
        (status=503, description="Store or admission unavailable", body=ErrorResponse))
)]
pub(in crate::openapi::management) fn head() {}

#[utoipa::path(put, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/invitation-delivery", operation_id = "organization_domain_put_by_domain_invitation_delivery", tag="organizations",
    description="Explicit domain delivery configuration. Current configure capability; credentials are never stored. Disable uses reserved cancellation admission.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])), params(("team" = String, Path, format="uuid"), ("environment" = String, Path, format="uuid"), ("domain" = String, Path, format="uuid"), ("Origin" = String, Header), ("Idempotency-Key" = String, Header), ("If-Match" = String, Header, description="Exact current domain ETag")),
    request_body=crate::organizations::http_input::delivery::ConfigureInvitationDeliveryRequest,
    responses((status=200, description="No-store; strong domain ETag", body=Configuration, headers(("ETag"=String))),
        (status=400, description="Invalid or ambiguous input", body=ErrorResponse),
        (status=401, description="Current human session required", body=ErrorResponse),
        (status=403, description="Current scope/CSRF/capability refused", body=ErrorResponse),
        (status=409, description="Conflict or finite capacity exhausted", body=ErrorResponse),
        (status=412, description="Stale precondition", body=ErrorResponse),
        (status=428, description="Precondition required", body=ErrorResponse),
        (status=503, description="Store or admission unavailable", body=ErrorResponse))
)]
pub(in crate::openapi::management) fn configure() {}

#[utoipa::path(post, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/invitation-delivery/disable", operation_id = "organization_domain_post_by_domain_invitation_delivery_disable", tag="organizations",
    description="Explicit domain delivery configuration. Current configure capability; credentials are never stored. Disable uses reserved cancellation admission.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])), params(("team" = String, Path, format="uuid"), ("environment" = String, Path, format="uuid"), ("domain" = String, Path, format="uuid"), ("Origin" = String, Header), ("Idempotency-Key" = String, Header), ("If-Match" = String, Header, description="Exact current domain ETag")),
    request_body=crate::organizations::http_input::ConfigurationReason,
    responses((status=200, description="No-store; strong domain ETag", body=Configuration, headers(("ETag"=String))),
        (status=400, description="Invalid or ambiguous input", body=ErrorResponse),
        (status=401, description="Current human session required", body=ErrorResponse),
        (status=403, description="Current scope/CSRF/capability refused", body=ErrorResponse),
        (status=409, description="Conflict or finite capacity exhausted", body=ErrorResponse),
        (status=412, description="Stale precondition", body=ErrorResponse),
        (status=428, description="Precondition required", body=ErrorResponse),
        (status=503, description="Store or admission unavailable", body=ErrorResponse))
)]
pub(in crate::openapi::management) fn disable() {}
