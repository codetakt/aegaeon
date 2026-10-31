//! Recipient-only POST boundary. An invitation link is never a credential.
use super::*;
use crate::organizations::http_input::invitations::{
    AcceptInvitationRequest as Accept, RecipientChallengeRequest as Challenge,
};
use crate::organizations::{http_input, invitations as service, Scope};
use axum::{extract::Path, http::request::Parts};
use sqlx::Connection;
use uuid::Uuid;

pub(in crate::web) const CHALLENGE_PATH: &str =
    "/organization-invitations/:domain/:invitation/challenges";
pub(in crate::web) const ACCEPT_PATH: &str = "/organization-invitations/:domain/:invitation/accept";

pub(in crate::web) fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route(CHALLENGE_PATH, axum::routing::post(challenge))
        .route(ACCEPT_PATH, axum::routing::post(accept))
}

enum Action {
    Challenge(Challenge, String),
    Accept(Accept),
}

pub(in crate::web) async fn challenge(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((domain, invitation)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    handle(
        &state,
        &admission,
        remote,
        &domain,
        &invitation,
        request,
        false,
    )
    .await
}

pub(in crate::web) async fn accept(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((domain, invitation)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    handle(
        &state,
        &admission,
        remote,
        &domain,
        &invitation,
        request,
        true,
    )
    .await
}

fn invalid(state: &AppState) -> Response {
    error(state, StatusCode::BAD_REQUEST, "invalid_request")
}

async fn action(
    state: &AppState,
    parts: &Parts,
    body: Body,
    accept: bool,
) -> Result<Action, Response> {
    if parts.method != Method::POST
        || parts.uri.query().is_some()
        || http_input::one_header(&parts.headers, "content-type").map_err(|_| invalid(state))?
            != Some("application/json")
    {
        return Err(invalid(state));
    }
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(http_input::BODY_TIMEOUT_SECONDS),
        to_bytes(body, http_input::MAX_BODY_BYTES),
    )
    .await
    .map_err(|_| invalid(state))?
    .map_err(|_| invalid(state))?;
    if accept {
        let value: Accept = http_input::decode_json(&bytes).map_err(|_| invalid(state))?;
        if value.challenge_id.is_nil() {
            return Err(invalid(state));
        }
        Ok(Action::Accept(value))
    } else {
        let value = http_input::decode_json(&bytes).map_err(|_| invalid(state))?;
        let key = http_input::idempotency_key(&parts.headers)
            .map_err(|_| invalid(state))?
            .to_owned();
        Ok(Action::Challenge(value, key))
    }
}

async fn handle(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    domain: &str,
    invitation: &str,
    request: Request<Body>,
    accepting: bool,
) -> Response {
    match execute(
        state, admission, remote, domain, invitation, request, accepting,
    )
    .await
    {
        Ok(value) => super::super::token_json_response(StatusCode::OK, value),
        Err(response) => response,
    }
}

async fn execute(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    domain: &str,
    invitation: &str,
    request: Request<Body>,
    accepting: bool,
) -> Result<serde_json::Value, Response> {
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
    let invitation = members::object(invitation).map_err(|_| invalid(state))?;
    let (parts, body) = request.into_parts();
    state
        .transport
        .enforce(Some(remote), &parts.headers)
        .map_err(|kind| {
            super::super::transport_boundary::transport_rejection_for_route(
                state,
                kind,
                CHALLENGE_PATH,
            )
        })?;
    let request_id = super::super::request_id::request_id_from_headers(&parts.headers);
    let action = action(state, &parts, body, accepting).await?;
    let audience = format!("{}/organization-invitations", state.issuer);
    let meta = authentication::for_audience(state, admission, parts, &audience).await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        transaction(
            state,
            admission,
            scope,
            invitation,
            &meta,
            action,
            &request_id,
        ),
    )
    .await
    .map_err(|_| unavailable(state))?
}

fn now(state: &AppState) -> Result<i64, Response> {
    crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| unavailable(state))
}

async fn transaction(
    state: &AppState,
    admission: &ResourceAdmission,
    scope: Scope,
    invitation_id: Uuid,
    meta: &BearerTokenMeta,
    action: Action,
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    let expected = super::super::organization_authority::projection(state)?;
    let started = now(state)?;
    service::recipient::token_deadline(meta, &state.issuer, started)
        .map_err(|_| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
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
    let runtime = service::delegated::Runtime {
        store: &state.tokens.store,
        admission: &admission.0,
        issuer: &state.issuer,
    };
    let recipient = service::recipient::current(
        &mut tx,
        scope,
        invitation_id,
        meta,
        &state.issuer,
        started,
        &runtime,
    )
    .await
    .map_err(|e| members::storage_error(state, &e))?;
    let mut input = service::Acceptance {
        request_id,
        scope,
        invitation_id,
        invitation_capability: "",
        challenge_id: Uuid::nil(),
        challenge_capability: "",
        recipient: &recipient,
        now: started,
    };
    let value = match action {
        Action::Challenge(value, key) => {
            input.invitation_capability = &value.invitation_capability;
            let id = service::request_challenge_current(&mut tx, &input, &key, Some(&runtime))
                .await
                .map_err(|e| members::storage_error(state, &e))?;
            serde_json::json!({"challengeId":id})
        }
        Action::Accept(value) => {
            input.invitation_capability = &value.invitation_capability;
            input.challenge_id = value.challenge_id;
            input.challenge_capability = &value.challenge_capability;
            let member = service::accept_current(&mut tx, &input, Some(&runtime))
                .await
                .map_err(|e| members::storage_error(state, &e))?;
            serde_json::json!({"organizationId":member.organization_id,"userId":member.user_id,"incarnation":member.incarnation,"revision":member.revision})
        }
    };
    super::super::organization_authority::recheck_projection(state, &mut tx, &expected).await?;
    let commit_time = now(state)?;
    if commit_time < started || commit_time >= recipient.expires_at {
        return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    service::recheck(&mut tx, scope, invitation_id, commit_time, &runtime)
        .await
        .map_err(|e| members::storage_error(state, &e))?;
    admission.0.admit_commit().map_err(|_| unavailable(state))?;
    tx.commit().await.map_err(|_| unavailable(state))?;
    connection.release().await;
    Ok(value)
}
