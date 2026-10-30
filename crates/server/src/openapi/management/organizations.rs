#![allow(dead_code)] // Utoipa path marker functions are referenced by generated metadata.
pub(in crate::openapi::management) mod delivery;
pub(in crate::openapi::management) mod identity_policy;
pub(super) mod invitations;
pub(in crate::openapi::management) mod support_policy;
use crate::openapi::types::ErrorResponse;
use crate::organizations::http_input::{
    ConfigurationReason, CreateOperatorRequest, UpdateOperatorRequest,
};
use crate::organizations::http_input::{DefaultDomainResponse, OperatorGrantResponse};

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/default", tag = "organizations",
    description = "Explicit owner bootstrap: disabled default domain and configure grant only. Replays recheck current ownership and grant.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID")),
    request_body = ConfigurationReason,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = DefaultDomainResponse, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn bootstrap() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/operators", tag = "organizations",
    description = "Create an explicit operator grant for a current human Team member. No implicit business membership.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID")),
    request_body = CreateOperatorRequest,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = OperatorGrantResponse, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn create() {}

#[utoipa::path(
    patch, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/operators/{grant}", tag = "organizations",
    description = "Update the exact grant revision after current configure authorization; retries recheck authority before receipt lookup.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("grant" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("If-Match" = String, Header, description = "One strong exact tag: quoted canonical UUID dot positive revision")),
    request_body = UpdateOperatorRequest,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = OperatorGrantResponse, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn update() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/operators/{grant}/revoke", tag = "organizations",
    description = "Deactivate the exact grant revision through the reserved revoke-only admission path. Preserve identity and capabilities.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("grant" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("If-Match" = String, Header, description = "One strong exact tag: quoted canonical UUID dot positive revision")),
    request_body = ConfigurationReason,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = OperatorGrantResponse, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn revoke() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/operators",
    tag = "organizations",
    description = "Bounded current operator configuration pages; requires configure, includes revoked grant identities, and grants no business membership. Cursor scope is checked on every page.",
    security(("managementSessionCookie" = [])),
    params(
        ("team" = String, Path, format = "uuid"),
        ("environment" = String, Path, format = "uuid"),
        ("domain" = String, Path, format = "uuid"),
        ("pageSize" = Option<u32>, Query, minimum = 1, maximum = 100, description = "Canonical decimal; default 50"),
        ("pageToken" = Option<String>, Query, max_length = 512, description = "Opaque scoped cursor, not a credential")
    ),
    responses(
        (status = 200, description = "Current page; no-store", body = crate::organizations::http_input::OperatorListResponse),
        (status = 400, description = "Invalid path, query, cursor or nonempty read body", body = ErrorResponse),
        (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse),
        (status = 403, description = "Current configure authority refused", body = ErrorResponse),
        (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn list_operators() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/targets", tag = "organizations",
    description = "Register one exact audience for this domain with an immutable purpose. Requires current configure authority and domain If-Match; does not enable business access.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("If-Match" = String, Header, description = "Strong current domain ETag")),
    request_body = crate::organizations::http_input::RegisterOrganizationTargetRequest,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = crate::organizations::operators::mutations::targets::DomainConfiguration, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn register_target() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}",
    tag = "organizations",
    description = "Read current domain configuration and at most 32 exact target bindings. Requires configure; no business membership is disclosed.",
    security(("managementSessionCookie" = [])),
    params(
        ("team" = String, Path, format = "uuid"),
        ("environment" = String, Path, format = "uuid"),
        ("domain" = String, Path, format = "uuid")
    ),
    responses(
        (status = 200, description = "Current configuration; no-store; strong domain ETag", body = crate::organizations::operators::mutations::targets::DomainConfiguration, headers(("ETag" = String, description = "Strong domain revision validator"))),
        (status = 400, description = "Invalid path, query, cursor or nonempty read body", body = ErrorResponse),
        (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse),
        (status = 403, description = "Current configure authority refused", body = ErrorResponse),
        (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn configuration() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/clients", tag = "organizations",
    description = "Bind an exact current client registration with explicit target permissions; current configure authority and domain If-Match required. Does not enable the domain or issue tokens.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("If-Match" = String, Header, description = "Strong current domain ETag")),
    request_body = crate::organizations::http_input::CreateOrganizationClientRequest,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = crate::organizations::operators::mutations::clients::ClientBinding, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn create_client() {}

#[utoipa::path(
    patch, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/clients/{binding}", tag = "organizations",
    description = "Replace settings for the retained binding using its exact ETag; activation requires a current confidential DPoP-required Token Exchange client.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("binding" = String, Path, format = "uuid", description = "Retained binding UUID"), ("If-Match" = String, Header, description = "Strong current binding ETag")),
    request_body = crate::organizations::http_input::UpdateOrganizationClientRequest,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = crate::organizations::operators::mutations::clients::ClientBinding, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn update_client() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/clients/{binding}/revoke", tag = "organizations",
    description = "Deactivate a retained binding through reserved admission and receipt capacity. Remains available after client deletion; current configure authority and binding ETag required.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("binding" = String, Path, format = "uuid", description = "Retained binding UUID"), ("If-Match" = String, Header, description = "Strong current binding ETag")),
    request_body = ConfigurationReason,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = crate::organizations::operators::mutations::clients::ClientBinding, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn revoke_client() {}

#[utoipa::path(
    get,
    path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/clients",
    tag = "organizations",
    description = "Bounded client setting pages; current configure required. Retained registrations include inactive bindings. Pages stop at requested count or 60 KiB; collection and scope checked in every cursor.",
    security(("managementSessionCookie" = [])),
    params(
        ("team" = String, Path, format = "uuid"),
        ("environment" = String, Path, format = "uuid"),
        ("domain" = String, Path, format = "uuid"),
        ("pageSize" = Option<u32>, Query, minimum = 1, maximum = 100, description = "Canonical decimal; default 50"),
        ("pageToken" = Option<String>, Query, max_length = 512, description = "Opaque scoped cursor, not a credential")
    ),
    responses(
        (status = 200, description = "Current page; no-store", body = crate::organizations::http_input::OrganizationClientListResponse),
        (status = 400, description = "Invalid path, query, cursor or nonempty read body", body = ErrorResponse),
        (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse),
        (status = 403, description = "Current configure authority refused", body = ErrorResponse),
        (status = 503, description = "Admission or store unavailable; no fallback", body = ErrorResponse)
    )
)]
pub(in crate::openapi::management) fn list_clients() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/enable", tag = "organizations",
    description = "Explicitly enable a configured domain after checking every active client binding against current confidential DPoP-required Token Exchange policy. Requires current configure and domain ETag.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("If-Match" = String, Header, description = "Strong current domain ETag")),
    request_body = ConfigurationReason,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = crate::organizations::operators::mutations::targets::DomainConfiguration, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn enable_domain() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/disable", tag = "organizations",
    description = "Disable a domain through reserved admission and receipt capacity, including after client deletion or ordinary capacity exhaustion. Requires current configure and domain ETag.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("If-Match" = String, Header, description = "Strong current domain ETag")),
    request_body = ConfigurationReason,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = crate::organizations::operators::mutations::targets::DomainConfiguration, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn disable_domain() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/targets/introspection-recipients/replace", tag = "organizations",
    description = "Explicitly replace 1–8 current confidential resource server registrations for the exact target. Domain revision invalidates old ceilings.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("If-Match" = String, Header, description = "Strong current domain ETag")),
    request_body = crate::organizations::http_input::ReplaceIntrospectionRecipientsRequest,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = crate::organizations::operators::mutations::targets::DomainConfiguration, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn replace_recipients() {}

#[utoipa::path(
    post, path = "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/targets/introspection-recipients/revoke", tag = "organizations",
    description = "Remove all resource server recipients for the exact target using reserved admission and receipt capacity. Current configure authority is mandatory.",
    security(("managementSessionCookie" = [], "managementCsrfHeader" = [])),
    params(("Origin" = String, Header, description = "Configured management console origin"), ("Idempotency-Key" = String, Header, description = "1-128 printable ASCII bytes without whitespace; retained exact command identity"), ("team" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("environment" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("domain" = String, Path, format = "uuid", description = "Plain immutable UUID"), ("If-Match" = String, Header, description = "Strong current domain ETag")),
    request_body = crate::organizations::http_input::RevokeIntrospectionRecipientsRequest,
    responses((status = 200, description = "Applied or authorized replay; Cache-Control no-store; strong ETag", body = crate::organizations::operators::mutations::targets::DomainConfiguration, headers(("ETag" = String, description = "Strong representation validator"))), (status = 400, description = "Malformed or ambiguous input", body = ErrorResponse), (status = 401, description = "Invalid or expired interactive session", body = ErrorResponse), (status = 403, description = "Current authority, CSRF or scope refused", body = ErrorResponse), (status = 408, description = "Body read deadline exceeded", body = ErrorResponse), (status = 409, description = "Idempotency conflict or retained authority capacity exhausted", body = ErrorResponse), (status = 412, description = "Representation precondition failed", body = ErrorResponse), (status = 413, description = "Body exceeds 65536 bytes", body = ErrorResponse), (status = 428, description = "Exact If-Match required for update or revoke", body = ErrorResponse), (status = 503, description = "Admission, session store, database or response deadline unavailable; no fallback", body = ErrorResponse))
)]
pub(in crate::openapi::management) fn revoke_recipients() {}
