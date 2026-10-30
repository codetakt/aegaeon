#![allow(dead_code)] // OpenAPI metadata markers.
use crate::openapi::types::ErrorResponse;
use crate::organizations::operators::mutations::support_policy::Configuration;

#[utoipa::path(get, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/support-policy", operation_id = "organization_domain_get_by_domain_support_policy", tag="organizations",
    description="Explicit domain support policy. Requires current human Team owner and explicit configure capability. Strong version is an opaque support-policy.<domain UUID>.<revision> entity tag. Disabled by default; disable has reserved admission.",
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

#[utoipa::path(head, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/support-policy", operation_id = "organization_domain_head_by_domain_support_policy", tag="organizations",
    description="Explicit domain support policy. Requires current human Team owner and explicit configure capability. Strong version is an opaque support-policy.<domain UUID>.<revision> entity tag. Disabled by default; disable has reserved admission.",
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

#[utoipa::path(put, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/support-policy", operation_id = "organization_domain_put_by_domain_support_policy", tag="organizations",
    description="Explicit domain support policy. Requires current human Team owner and explicit configure capability. Strong version is an opaque support-policy.<domain UUID>.<revision> entity tag. Disabled by default; disable has reserved admission.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])), params(("team" = String, Path, format="uuid"), ("environment" = String, Path, format="uuid"), ("domain" = String, Path, format="uuid"), ("Origin" = String, Header), ("Idempotency-Key" = String, Header), ("If-Match" = String, Header, description="Exact current domain support-policy ETag")),
    request_body=crate::organizations::http_input::support_policy::ConfigureSupportPolicyRequest,
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

#[utoipa::path(post, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/support-policy/disable", operation_id = "organization_domain_post_by_domain_support_policy_disable", tag="organizations",
    description="Explicit domain support policy. Requires current human Team owner and explicit configure capability. Strong version is an opaque support-policy.<domain UUID>.<revision> entity tag. Disabled by default; disable has reserved admission.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])), params(("team" = String, Path, format="uuid"), ("environment" = String, Path, format="uuid"), ("domain" = String, Path, format="uuid"), ("Origin" = String, Header), ("Idempotency-Key" = String, Header), ("If-Match" = String, Header, description="Exact current domain support-policy ETag")),
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
