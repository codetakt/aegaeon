use super::*;
use crate::organizations::{
    http_input::{self, VersionTag},
    invitations::{self as service, delegated},
    repository::{ActorKind, AuditActor},
    selected,
};
use axum::{
    extract::{MatchedPath, Path},
    http::header,
};
use sqlx::Connection;
use std::collections::HashMap;
use uuid::Uuid;

pub(in crate::web) const ISSUE: &str = "/organizations/:organization/invitations";
pub(in crate::web) const READ: &str = "/organizations/:organization/invitations/:invitation";
pub(in crate::web) const REVOKE: &str =
    "/organizations/:organization/invitations/:invitation/revoke";

pub(in crate::web) fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route(ISSUE, axum::routing::post(handle))
        .route(READ, axum::routing::get(handle))
        .route(REVOKE, axum::routing::post(handle))
}

enum Operation {
    Issue(service::FirstAdminRequest),
    Read(Uuid),
    Revoke(Uuid, i64),
}
struct Input {
    organization: Uuid,
    operation: Operation,
    key: String,
    reason: String,
    request_id: String,
}

fn bad(state: &AppState) -> Response {
    error(state, StatusCode::BAD_REQUEST, "invalid_request")
}
fn input_error(state: &AppState, failure: http_input::InputError) -> Response {
    let status = match failure {
        http_input::InputError::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
        http_input::InputError::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
        _ => StatusCode::BAD_REQUEST,
    };
    error(state, status, "invalid_request")
}

async fn parse(
    state: &AppState,
    path: &HashMap<String, String>,
    parts: &axum::http::request::Parts,
    body: Body,
) -> Result<Input, Response> {
    if parts.uri.query().is_some() {
        return Err(bad(state));
    }
    let organization = members::object(path.get("organization").ok_or_else(|| bad(state))?)
        .map_err(|e| input_error(state, e))?;
    let route = parts
        .extensions
        .get::<MatchedPath>()
        .ok_or_else(|| bad(state))?
        .as_str();
    let request_id = super::super::request_id::request_id_from_headers(&parts.headers);
    if route == READ && matches!(parts.method, Method::GET | Method::HEAD) {
        tokio::time::timeout(std::time::Duration::from_secs(10), to_bytes(body, 0))
            .await
            .map_err(|_| bad(state))?
            .map_err(|_| bad(state))?;
        let id = members::object(path.get("invitation").ok_or_else(|| bad(state))?)
            .map_err(|e| input_error(state, e))?;
        return Ok(Input {
            organization,
            operation: Operation::Read(id),
            key: "read".into(),
            reason: "Inspect organization invitation".into(),
            request_id,
        });
    }
    if parts.method != Method::POST
        || !matches!(route, ISSUE | REVOKE)
        || http_input::one_header(&parts.headers, "content-type")
            .map_err(|e| input_error(state, e))?
            != Some("application/json")
    {
        return Err(bad(state));
    }
    let tag = http_input::required_version(&parts.headers).map_err(|e| input_error(state, e))?;
    let key = http_input::idempotency_key(&parts.headers)
        .map_err(|e| input_error(state, e))?
        .to_owned();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        to_bytes(body, http_input::MAX_BODY_BYTES),
    )
    .await
    .map_err(|_| bad(state))?
    .map_err(|_| bad(state))?;
    let (operation, reason) = if route == ISSUE {
        if tag.object() != organization {
            return Err(input_error(
                state,
                http_input::InputError::PreconditionFailed,
            ));
        }
        let value: http_input::invitations::IssueInvitationRequest =
            http_input::decode_json(&bytes).map_err(|e| input_error(state, e))?;
        let roles = value.roles().map_err(|e| input_error(state, e))?;
        (
            Operation::Issue(service::FirstAdminRequest {
                organization_id: organization,
                expected_revision: tag.revision(),
                recipient: value.recipient,
                roles,
                lifetime_seconds: value.lifetime_seconds,
            }),
            value.reason,
        )
    } else {
        let id = members::object(path.get("invitation").ok_or_else(|| bad(state))?)
            .map_err(|e| input_error(state, e))?;
        if tag.object() != id {
            return Err(input_error(
                state,
                http_input::InputError::PreconditionFailed,
            ));
        }
        let value: http_input::ConfigurationReason =
            http_input::decode_json(&bytes).map_err(|e| input_error(state, e))?;
        (Operation::Revoke(id, tag.revision()), value.reason)
    };
    Ok(Input {
        organization,
        operation,
        key,
        reason,
        request_id,
    })
}

async fn handle(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(path): Path<HashMap<String, String>>,
    request: Request<Body>,
) -> Response {
    match execute(&state, &admission, remote, &path, request).await {
        Ok(value) => {
            let Ok(tag) = VersionTag::new(value.id, value.revision).and_then(|tag| {
                tag.header_value()
                    .parse()
                    .map_err(|_| http_input::InputError::Invalid)
            }) else {
                return unavailable(&state);
            };
            let mut response =
                super::super::token_json_response(StatusCode::OK, serde_json::json!(value));
            response.headers_mut().insert(header::ETAG, tag);
            response
        }
        Err(response) => response,
    }
}

async fn execute(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    path: &HashMap<String, String>,
    request: Request<Body>,
) -> Result<service::Invitation, Response> {
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
    let (parts, body) = request.into_parts();
    state
        .transport
        .enforce(Some(remote), &parts.headers)
        .map_err(|kind| {
            super::super::transport_boundary::transport_rejection_for_route(state, kind, ISSUE)
        })?;
    let input = parse(state, path, &parts, body).await?;
    let meta = authentication::authenticate(state, admission, parts).await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        transaction(state, admission, &meta, input),
    )
    .await
    .map_err(|_| unavailable(state))?
}

async fn transaction(
    state: &AppState,
    admission: &ResourceAdmission,
    meta: &BearerTokenMeta,
    input: Input,
) -> Result<service::Invitation, Response> {
    let selected = meta
        .selected_organization
        .as_ref()
        .ok_or_else(|| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    if selected.decision.organization_id != input.organization {
        return Err(error(state, StatusCode::FORBIDDEN, "insufficient_scope"));
    }
    let now = crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| unavailable(state))?;
    let binding = selected
        .token_binding(meta, state.environment_id, &state.issuer, now)
        .map_err(|_| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let original = meta
        .exchange_grant
        .as_ref()
        .and_then(|g| g.organization.as_ref())
        .ok_or_else(|| unavailable(state))?;
    let expected = super::super::organization_authority::projection(state)?;
    let runtime = delegated::Runtime {
        store: &state.tokens.store,
        admission: &admission.0,
        issuer: &state.issuer,
    };
    let mut connection = admission
        .0
        .connection(&state.db_pool)
        .await
        .map_err(|_| unavailable(state))?;
    let mut tx = connection
        .as_mut()
        .map_err(|_| unavailable(state))?
        .begin()
        .await
        .map_err(|_| unavailable(state))?;
    if !selected::is_current(&mut tx, selected, original, &binding, now)
        .await
        .map_err(|_| unavailable(state))?
    {
        return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    let actor = AuditActor {
        basis: Some(
            serde_json::json!({"kind":"delegated_invitation","rootId":binding.root_id,"organizationGeneration":selected.decision.organization_generation,"membership":selected.decision.authority,"roleVersions":selected.decision.role_versions}),
        ),
        id: binding.user_id,
        kind: ActorKind::Member,
        client_id: binding.client_id.clone(),
        client_registration_id: Some(binding.client_registration_id),
        request_id: input.request_id,
        reason: input.reason,
    };
    let call = delegated::Request {
        scope: binding.scope,
        meta,
        actor: &actor,
        key: &input.key,
        runtime: &runtime,
        now,
    };
    let value = match input.operation {
        Operation::Issue(value) => delegated::issue(&mut tx, &call, &value).await,
        Operation::Read(id) => delegated::inspect(&mut tx, &call, input.organization, id).await,
        Operation::Revoke(id, revision) => {
            delegated::revoke(&mut tx, &call, input.organization, id, revision).await
        }
    }
    .map_err(|e| members::storage_error(state, &e))?;
    super::super::organization_authority::recheck_projection(state, &mut tx, &expected).await?;
    let commit = crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| unavailable(state))?;
    if commit < now || commit >= selected.decision.expires_at {
        return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    let commit_call = delegated::Request {
        now: commit,
        ..call
    };
    delegated::inspect(&mut tx, &commit_call, input.organization, value.id)
        .await
        .map_err(|e| members::storage_error(state, &e))?;
    admission.0.admit_commit().map_err(|_| unavailable(state))?;
    tx.commit().await.map_err(|_| unavailable(state))?;
    connection.release().await;
    Ok(value)
}
