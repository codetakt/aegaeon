#![allow(dead_code)] // OpenAPI metadata markers.
use crate::openapi::types::ErrorResponse;
use crate::organizations::audit::{
    delivery::{Acknowledgment, Batch, Receipt},
    Page,
};

#[utoipa::path(get, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/audit-events", tag="organizations",
    description="Bounded live audit history, not a consistent export. Requires current human management session and explicit domain Export capability on every page. At most 100 events and 64 KiB; cursor binds Environment/domain and audit kind. No-store; unauthorized domains are not disclosed.",
    security(("managementSessionCookie"=[])),
    params(("team"=String,Path,format="uuid"),("environment"=String,Path,format="uuid"),("domain"=String,Path,format="uuid"),("pageSize"=Option<u16>,Query,minimum=1,maximum=100),("pageToken"=Option<String>,Query)),
    responses((status=200,description="Authorized bounded page", body=Page),
        (status=400,description="Invalid query or cursor",body=ErrorResponse),
        (status=401,description="Current human session required",body=ErrorResponse),
        (status=403,description="Scope or Export capability refused",body=ErrorResponse),
        (status=503,description="Store, admission, deadline or record capacity unavailable",body=ErrorResponse))
)]
pub(super) fn get() {}

#[utoipa::path(head, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/audit-events", tag="organizations",
    description="Bounded live audit history, not a consistent export. Requires current human management session and explicit domain Export capability on every page. At most 100 events and 64 KiB; cursor binds Environment/domain and audit kind. No-store; unauthorized domains are not disclosed.",
    security(("managementSessionCookie"=[])),
    params(("team"=String,Path,format="uuid"),("environment"=String,Path,format="uuid"),("domain"=String,Path,format="uuid"),("pageSize"=Option<u16>,Query,minimum=1,maximum=100),("pageToken"=Option<String>,Query)),
    responses((status=200,description="Authorized bounded page"),
        (status=400,description="Invalid query or cursor",body=ErrorResponse),
        (status=401,description="Current human session required",body=ErrorResponse),
        (status=403,description="Scope or Export capability refused",body=ErrorResponse),
        (status=503,description="Store, admission, deadline or record capacity unavailable",body=ErrorResponse))
)]
pub(super) fn head() {}

#[utoipa::path(get, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/audit-events/pending", tag="organizations",
    description="Fetch a bounded immutable outbox batch under current explicit Export authority. At most 100 events and 64 KiB. Digests cover the exact event JSON bytes. Fetch does not acknowledge; repeated fetch may repeat events. No-store.",
    security(("managementSessionCookie"=[])),
    params(("team"=String,Path,format="uuid"),("environment"=String,Path,format="uuid"),("domain"=String,Path,format="uuid")),
    responses((status=200,description="Pending batch",body=Batch,headers(("ETag"=String,description="Strong batch precondition"))),
        (status=400,description="Invalid query",body=ErrorResponse),(status=401,description="Current human session required",body=ErrorResponse),
        (status=403,description="Current Export required",body=ErrorResponse),(status=503,description="Store or finite budget unavailable",body=ErrorResponse))
)]
pub(super) fn pending_get() {}

#[utoipa::path(head, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/audit-events/pending", tag="organizations",
    description="Fetch a bounded immutable outbox batch under current explicit Export authority. At most 100 events and 64 KiB. Digests cover the exact event JSON bytes. Fetch does not acknowledge; repeated fetch may repeat events. No-store.",
    security(("managementSessionCookie"=[])),
    params(("team"=String,Path,format="uuid"),("environment"=String,Path,format="uuid"),("domain"=String,Path,format="uuid")),
    responses((status=200,description="Pending batch",headers(("ETag"=String,description="Strong batch precondition"))),
        (status=400,description="Invalid query",body=ErrorResponse),(status=401,description="Current human session required",body=ErrorResponse),
        (status=403,description="Current Export required",body=ErrorResponse),(status=503,description="Store or finite budget unavailable",body=ErrorResponse))
)]
pub(super) fn pending_head() {}

#[utoipa::path(post, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/audit-events/acknowledgments", tag="organizations",
    description="Acknowledge exact pending event IDs and digests after durable recipient storage. Current Export, Origin/CSRF, Idempotency-Key and strong batch If-Match required, including on replay. Atomic delivery state and permanent receipt; no history deletion. Maximum 100 events, 64 KiB, and 602212 acknowledgment receipts per domain. An external acknowledgment alone does not establish receiver custody.",
    security(("managementSessionCookie"=[],"managementCsrfHeader"=[])),
    params(("team"=String,Path,format="uuid"),("environment"=String,Path,format="uuid"),("domain"=String,Path,format="uuid"),("Idempotency-Key"=String,Header,description="Stable key for the same semantic request"),("If-Match"=String,Header,description="Exact strong audit batch ETag")),
    request_body=Acknowledgment,
    responses((status=200,description="Permanent acknowledgment receipt",body=Receipt,headers(("ETag"=String,description="Acknowledged batch precondition"))),
        (status=400,description="Invalid or ambiguous input",body=ErrorResponse),(status=401,description="Current human session required",body=ErrorResponse),
        (status=403,description="Current Export or CSRF refused",body=ErrorResponse),(status=409,description="Key conflict or finite receipt capacity",body=ErrorResponse),
        (status=412,description="Batch content or delivery state differs",body=ErrorResponse),(status=428,description="Exact precondition required",body=ErrorResponse),
        (status=503,description="Store or finite budget unavailable",body=ErrorResponse))
)]
pub(super) fn acknowledge() {}
