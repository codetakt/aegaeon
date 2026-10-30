//! Dedicated semantic consumer for a selected Organizations token.
use super::{oauth_errors, AppState};
use crate::authcode::types::{BearerTokenMeta, SenderBinding};
use crate::middleware::dpop::DpopEndpointRole;
use crate::resource_authentication::ResourceScheme;
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{Method, Request, StatusCode},
    response::Response,
    Extension,
};
use std::net::SocketAddr;

mod admission;
mod authentication;
pub(super) mod delegated_invitations;
pub(super) mod identity;
pub(super) mod invitations;
pub(super) mod members;
pub(super) mod support;
pub(super) use admission::{admitted_route, capacity, ResourceAdmission};

pub(super) const PATH: &str = "/organizations/context";
const PRIVILEGE: &str = "organization.context.read";

fn error(state: &AppState, status: StatusCode, code: &str) -> Response {
    let mut response =
        oauth_errors::no_cache_json_error_with_iss(status, code, None, state.issuer.as_str());
    if status.is_client_error() {
        oauth_errors::apply_oauth_authenticate_header(&mut response, "DPoP", code);
    }
    response
}

pub(super) fn unavailable(state: &AppState) -> Response {
    error(
        state,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
}

pub(super) async fn context(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    match read(&state, &admission, remote, request).await {
        Ok(value) => super::token_json_response(StatusCode::OK, value),
        Err(response) => response,
    }
}

async fn read(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    request: Request<Body>,
) -> Result<serde_json::Value, Response> {
    state.require_subject_namespace()?;
    if state.runtime_restart.is_requested() {
        return Err(unavailable(state));
    }
    let (parts, body) = request.into_parts();
    state
        .transport
        .enforce(Some(remote), &parts.headers)
        .map_err(|kind| {
            super::transport_boundary::transport_rejection_for_route(state, kind, PATH)
        })?;
    if !matches!(parts.method, Method::GET | Method::HEAD)
        || parts.uri.query().is_some()
        || to_bytes(body, 0).await.is_err()
    {
        return Err(error(state, StatusCode::BAD_REQUEST, "invalid_request"));
    }
    let meta = authentication::authenticate(state, admission, parts).await?;
    let organization = super::organization_authority::current_organization_for_resource(
        state,
        &meta,
        &admission.0,
    )
    .await?
    .ok_or_else(|| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    representation(state, &meta, &organization)
}

fn representation(
    state: &AppState,
    meta: &BearerTokenMeta,
    organization: &crate::organizations::Organization,
) -> Result<serde_json::Value, Response> {
    let selected = meta
        .selected_organization
        .as_ref()
        .ok_or_else(|| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    if !selected.decision.privileges.contains(PRIVILEGE) {
        return Err(error(state, StatusCode::FORBIDDEN, "insufficient_scope"));
    }
    let version =
        crate::organizations::http_input::VersionTag::new(organization.id, organization.revision)
            .map_err(|_| unavailable(state))?;
    Ok(serde_json::json!({
        "organization": {"id": organization.id, "externalId": organization.external_id,
            "revision": organization.revision, "versionTag": version.header_value()},
        "iss":state.issuer.as_str(), "sub":meta.user_id,
        "authorization_details":selected.decision.authorization_details(),
        "exp":selected.decision.expires_at,
    }))
}

async fn verify_proof(
    state: &AppState,
    admission: &ResourceAdmission,
    parts: axum::http::request::Parts,
) -> Result<crate::middleware::DpopBinding, Response> {
    let dpop = state.dpop.clone();
    let owner = admission.clone();
    tokio::task::spawn_blocking(move || {
        let _owner = owner;
        super::dpop_binding_from_request(
            dpop.as_ref(),
            DpopEndpointRole::ResourceServer,
            &parts.method,
            &parts.uri,
            &parts.headers,
        )
    })
    .await
    .map_err(|_| unavailable(state))?
    .map_err(|failure| {
        super::token_sender_binding::dpop_error_response(
            state.issuer.as_str(),
            DpopEndpointRole::ResourceServer,
            failure,
        )
    })?
    .ok_or_else(|| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))
}
