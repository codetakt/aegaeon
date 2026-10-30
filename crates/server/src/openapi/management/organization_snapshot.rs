#![allow(dead_code)] // OpenAPI metadata markers.
use crate::openapi::types::ErrorResponse;

#[utoipa::path(get, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/snapshot", tag="organizations",
    description="Consistent version-one JSON Lines snapshot of one domain, including tombstones, command/audit history and referenced permanent subject ownership. Current human management session and explicit Export required before header, each page and final manifest, on the live primary. No credentials or usable capabilities. One concurrent export per process, one-hour absolute and 30-second progress deadlines, ten rows/page, 256 KiB/row, one million rows/section, 64 GiB/transfer. All 20 section digests/counts and terminal manifest must verify before acceptance; an interrupted HTTP 200 is not a complete snapshot. No-store. Import activation is separate.",
    security(("managementSessionCookie"=[])),
    params(("team"=String,Path,format="uuid"),("environment"=String,Path,format="uuid"),("domain"=String,Path,format="uuid")),
    responses((status=200,description="Streaming snapshot; requires valid terminal manifest",body=String,content_type="application/x-ndjson"),
        (status=400,description="Invalid path, query or nonempty body",body=ErrorResponse),
        (status=401,description="Current human session required",body=ErrorResponse),
        (status=403,description="Current Export or scope refused",body=ErrorResponse),
        (status=503,description="Before header: store, finite budget or admission unavailable",body=ErrorResponse))
)]
pub(super) fn get() {}

#[utoipa::path(head, path="/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/snapshot", tag="organizations",
    description="Check current human session, scope and Export capability and return snapshot response headers. No transfer is started and no manifest is produced. No-store.",
    security(("managementSessionCookie"=[])),
    params(("team"=String,Path,format="uuid"),("environment"=String,Path,format="uuid"),("domain"=String,Path,format="uuid")),
    responses((status=200,description="Authorized response headers"),
        (status=400,description="Invalid path, query or nonempty body",body=ErrorResponse),
        (status=401,description="Current human session required",body=ErrorResponse),
        (status=403,description="Current Export or scope refused",body=ErrorResponse),
        (status=503,description="Store or admission unavailable",body=ErrorResponse))
)]
pub(super) fn head() {}
