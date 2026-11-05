//! Parent-token activation of separately approved temporary support authority.
use super::*;
use crate::organizations::{
    http_input::{self, VersionTag},
    support as service, Scope,
};
use axum::{
    extract::Path,
    http::{header, request::Parts, HeaderMap},
};
use sqlx::Connection;
use uuid::Uuid;
mod token;
mod transaction;

pub(in crate::web) const CREATE: &str = "/organization-support/:domain/grants";
pub(in crate::web) const READ: &str = "/organization-support/:domain/grants/:grant";
pub(in crate::web) const REVOKE: &str = "/organization-support/:domain/grants/:grant/revoke";
pub(in crate::web) fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route(CREATE, axum::routing::post(create))
        .route(READ, axum::routing::get(read))
        .route(REVOKE, axum::routing::post(revoke))
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CreateRequest {
    organization_id: Uuid,
    audience: String,
    roles: Vec<String>,
    reason: String,
}
enum Action {
    Create(service::Activation, String),
    Read(Uuid),
    Revoke(service::Revoke, String),
}
fn invalid(state: &AppState) -> Response {
    error(state, StatusCode::BAD_REQUEST, "invalid_request")
}

pub(in crate::web) async fn create(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(domain): Path<String>,
    request: Request<Body>,
) -> Response {
    handle(&state, &admission, remote, &domain, None, false, request).await
}
pub(in crate::web) async fn read(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((domain, id)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    handle(
        &state,
        &admission,
        remote,
        &domain,
        Some(&id),
        false,
        request,
    )
    .await
}
pub(in crate::web) async fn revoke(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((domain, id)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    handle(
        &state,
        &admission,
        remote,
        &domain,
        Some(&id),
        true,
        request,
    )
    .await
}
async fn handle(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    domain: &str,
    id: Option<&str>,
    revoking: bool,
    request: Request<Body>,
) -> Response {
    match execute(state, admission, remote, domain, id, revoking, request).await {
        Ok(grant) => {
            let tag = match VersionTag::new(grant.id, grant.revision) {
                Ok(v) => v,
                Err(_) => return unavailable(state),
            };
            let now = match token::now(state) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let value = serde_json::json!({"id":grant.id,"organizationId":grant.authority.organization_id,"audience":grant.authority.audience,
                "roles":grant.authority.ceiling.role_versions.keys().collect::<Vec<_>>(),"privileges":grant.authority.ceiling.privileges,
                "revision":grant.revision,"state":if !grant.active{"revoked"}else if now>=grant.expires_at{"expired"}else{"active"},"issuedAt":grant.issued_at,"expiresAt":grant.expires_at});
            let mut response = super::super::token_json_response(StatusCode::OK, value);
            if let Ok(value) = tag.header_value().parse() {
                response.headers_mut().insert(header::ETAG, value);
            } else {
                return unavailable(state);
            }
            response
        }
        Err(response) => response,
    }
}
async fn execute(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    domain: &str,
    id: Option<&str>,
    revoking: bool,
    request: Request<Body>,
) -> Result<service::Grant, Response> {
    state.require_subject_namespace()?;
    if state.runtime_restart.is_requested() {
        return Err(unavailable(state));
    }
    if !state
        .cfg
        .authorization_details_types_supported
        .iter()
        .any(|t| t == crate::organizations::ORGANIZATION_ACCESS_TYPE)
    {
        return Err(error(state, StatusCode::FORBIDDEN, "insufficient_scope"));
    }
    let scope = Scope {
        environment_id: state.environment_id,
        domain_id: members::object(domain).map_err(|_| invalid(state))?,
    };
    let id = id
        .map(members::object)
        .transpose()
        .map_err(|_| invalid(state))?;
    let (parts, body) = request.into_parts();
    state
        .transport
        .enforce(Some(remote), &parts.headers)
        .map_err(|kind| {
            super::super::transport_boundary::transport_rejection_for_route(state, kind, CREATE)
        })?;
    let action = action(state, &parts, body, id, revoking).await?;
    let request_id = super::super::request_id::request_id_from_headers(&parts.headers);
    let meta = authentication::for_audience(
        state,
        admission,
        parts,
        &format!("{}/organization-support", state.issuer),
    )
    .await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        transaction::execute(state, admission, scope, &meta, action, &request_id),
    )
    .await
    .map_err(|_| unavailable(state))?
}
fn version(state: &AppState, headers: &HeaderMap, id: Uuid) -> Result<i64, Response> {
    let tag = http_input::required_version(headers).map_err(|e| members::input_error(state, e))?;
    tag.require_current(id, tag.revision())
        .map_err(|e| members::input_error(state, e))?;
    Ok(tag.revision())
}
async fn action(
    state: &AppState,
    parts: &Parts,
    body: Body,
    id: Option<Uuid>,
    revoking: bool,
) -> Result<Action, Response> {
    if parts.uri.query().is_some() {
        return Err(invalid(state));
    }
    let mutation = parts.method == Method::POST;
    if !mutation
        && (!matches!(parts.method, Method::GET | Method::HEAD) || id.is_none() || revoking)
    {
        return Err(invalid(state));
    }
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(http_input::BODY_TIMEOUT_SECONDS),
        to_bytes(
            body,
            if mutation {
                http_input::MAX_BODY_BYTES
            } else {
                0
            },
        ),
    )
    .await
    .map_err(|_| invalid(state))?
    .map_err(|_| invalid(state))?;
    if !mutation {
        return Ok(Action::Read(id.ok_or_else(|| invalid(state))?));
    }
    if http_input::one_header(&parts.headers, "content-type").map_err(|_| invalid(state))?
        != Some("application/json")
    {
        return Err(invalid(state));
    }
    let key = http_input::idempotency_key(&parts.headers)
        .map_err(|e| members::input_error(state, e))?
        .to_owned();
    if revoking {
        let id = id.ok_or_else(|| invalid(state))?;
        let value: http_input::ConfigurationReason =
            http_input::decode_json(&bytes).map_err(|e| members::input_error(state, e))?;
        Ok(Action::Revoke(
            service::Revoke {
                id,
                expected_revision: version(state, &parts.headers, id)?,
                reason: value.reason,
            },
            key,
        ))
    } else {
        let value: CreateRequest =
            http_input::decode_json(&bytes).map_err(|e| members::input_error(state, e))?;
        Ok(Action::Create(
            service::Activation {
                expected_revision: version(state, &parts.headers, value.organization_id)?,
                organization_id: value.organization_id,
                audience: value.audience,
                roles: value.roles,
                reason: value.reason,
            },
            key,
        ))
    }
}
