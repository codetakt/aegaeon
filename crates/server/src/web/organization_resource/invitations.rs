//! Recipient-only POST boundary. An invitation link is never a credential.
use super::*;
use crate::organizations::http_input::invitations::{
    AcceptInvitationRequest as Accept, RecipientChallengeRequest as Challenge,
};
use crate::organizations::{http_input, invitations as service, Scope};
use crate::web::accept::{self as negotiation, NegotiationError, Representation};
use axum::{
    extract::{MatchedPath, Path},
    http::{header, request::Parts, HeaderValue},
};

use service::preview::{self, Condition};
use uuid::Uuid;
mod confirmation;

pub(in crate::web) const CHALLENGE_PATH: &str =
    "/organization-invitations/:domain/:invitation/challenges";
pub(in crate::web) const STATUS_PATH: &str =
    "/organization-invitations/:domain/:invitation/challenge-status";
const EXTENDED_CONTENT_TYPE: HeaderValue =
    HeaderValue::from_static("application/vnd.aegaeon.invitation-challenge.v2+json");
pub(in crate::web) const PREVIEW_PATH: &str =
    "/organization-invitations/:domain/:invitation/preview";
pub(in crate::web) const ACCEPT_PATH: &str = "/organization-invitations/:domain/:invitation/accept";

pub(in crate::web) fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route(CHALLENGE_PATH, axum::routing::post(handle))
        .route(STATUS_PATH, axum::routing::post(handle))
        .route(PREVIEW_PATH, axum::routing::post(handle))
        .route(ACCEPT_PATH, axum::routing::post(handle))
}

enum Action {
    Challenge(Challenge, String, Representation),
    Status(Challenge),
    Confirm(Accept, confirmation::Operation),
}

fn invalid(state: &AppState) -> Response {
    error(state, StatusCode::BAD_REQUEST, "invalid_request")
}

async fn action(
    state: &AppState,
    parts: &Parts,
    body: Body,
    path: &str,
    representation: Representation,
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
    if path == ACCEPT_PATH || path == PREVIEW_PATH {
        let value: Accept = http_input::decode_json(&bytes).map_err(|_| invalid(state))?;
        if value.challenge_id.is_nil() {
            return Err(invalid(state));
        }
        Ok(Action::Confirm(
            value,
            if path == PREVIEW_PATH {
                confirmation::Operation::Preview
            } else {
                confirmation::Operation::Accept(confirmation::condition(&parts.headers))
            },
        ))
    } else if path == STATUS_PATH {
        Ok(Action::Status(
            http_input::decode_json(&bytes).map_err(|_| invalid(state))?,
        ))
    } else if path == CHALLENGE_PATH {
        let value = http_input::decode_json(&bytes).map_err(|_| invalid(state))?;
        let key = http_input::idempotency_key(&parts.headers)
            .map_err(|_| invalid(state))?
            .to_owned();
        Ok(Action::Challenge(value, key, representation))
    } else {
        Err(invalid(state))
    }
}

async fn handle(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(ids): Path<(String, String)>,
    matched: MatchedPath,
    request: Request<Body>,
) -> Response {
    let path = matched.as_str();
    let mut response = execute(&state, &admission, remote, ids, request, path)
        .await
        .unwrap_or_else(|refusal| refusal);
    if path == CHALLENGE_PATH {
        response
            .headers_mut()
            .append(header::VARY, HeaderValue::from_static("Accept"));
    }
    response
}

async fn execute(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    (domain, invitation): (String, String),
    request: Request<Body>,
    path: &str,
) -> Result<Response, Response> {
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
        domain_id: members::object(&domain).map_err(|_| invalid(state))?,
    };
    let invitation = members::object(&invitation).map_err(|_| invalid(state))?;
    let (parts, body) = request.into_parts();
    state
        .transport
        .enforce(Some(remote), &parts.headers)
        .map_err(|kind| {
            super::super::transport_boundary::transport_rejection_for_route(state, kind, path)
        })?;
    let request_id = super::super::request_id::request_id_from_headers(&parts.headers);
    let representation = if path == CHALLENGE_PATH {
        negotiation::select(
            &parts.headers,
            Some(b"vnd.aegaeon.invitation-challenge.v2+json"),
        )
        .map_err(|reason| {
            let status = match reason {
                NegotiationError::Malformed => StatusCode::BAD_REQUEST,
                NegotiationError::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            };
            error(state, status, "invalid_request")
        })?
    } else {
        Representation::Json
    };
    let action = action(state, &parts, body, path, representation).await?;
    let audience = format!("{}/organization-invitations", state.issuer);
    let meta = authentication::for_audience(state, admission, parts, &audience).await?;
    let (value, etag) = tokio::time::timeout(
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
    .map_err(|_| unavailable(state))??;
    let mut response = super::super::token_json_response(StatusCode::OK, value);
    if let Some(tag) = etag {
        response.headers_mut().insert(header::ETAG, tag);
    }
    if representation == Representation::Alternate {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, EXTENDED_CONTENT_TYPE);
    }
    Ok(response)
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
) -> Result<(serde_json::Value, Option<HeaderValue>), Response> {
    let expected = super::super::organization_authority::projection(state)?;
    let started = now(state)?;
    service::recipient::token_deadline(meta, &state.issuer, started)
        .map_err(|_| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let mut connection = admission
        .0
        .connection(&state.db_pool)
        .await
        .map_err(|_| unavailable(state))?;
    let mut tx = connection.begin().await.map_err(|_| unavailable(state))?;
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
    .map_err(|e| match e {
        // At this boundary all object syntax is already validated. An invalid
        // retained authority must look like any other inaccessible invitation.
        crate::organizations::repository::RepositoryError::Authority(
            crate::organizations::AuthorityError::Invalid,
        ) => error(state, StatusCode::FORBIDDEN, "insufficient_scope"),
        other => members::storage_error(state, &other),
    })?;
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
    let mut etag = None;
    let mut proof_deadline = None;
    let value = match action {
        Action::Status(value) => {
            input.invitation_capability = &value.invitation_capability;
            let status = service::challenge_status(&mut tx, &input, &runtime)
                .await
                .map_err(|e| members::storage_error(state, &e))?;
            serde_json::json!(status)
        }
        Action::Challenge(value, key, representation) => {
            input.invitation_capability = &value.invitation_capability;
            let allocated =
                service::request_challenge_current(&mut tx, &input, &key, Some(&runtime))
                    .await
                    .map_err(|e| members::storage_error(state, &e))?;
            match representation {
                Representation::Json => serde_json::json!({"challengeId":allocated.challenge_id}),
                Representation::Alternate => serde_json::json!(allocated),
            }
        }
        Action::Confirm(value, operation) => {
            input.invitation_capability = &value.invitation_capability;
            input.challenge_id = value.challenge_id;
            input.challenge_capability = &value.challenge_capability;
            let result = confirmation::run(state, &mut tx, &input, &runtime, operation).await?;
            etag = result.tag;
            proof_deadline = Some(result.expires_at);
            result.body
        }
    };
    super::super::organization_authority::recheck_projection(state, &mut tx, &expected).await?;
    let commit_time = now(state)?;
    if commit_time < started || commit_time >= recipient.expires_at {
        return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    if proof_deadline.is_some_and(|deadline| commit_time >= deadline) {
        return Err(error(state, StatusCode::FORBIDDEN, "insufficient_scope"));
    }
    service::recheck(&mut tx, scope, invitation_id, commit_time, &runtime)
        .await
        .map_err(|e| members::storage_error(state, &e))?;
    admission.0.admit_commit().map_err(|_| unavailable(state))?;
    tx.commit().await.map_err(|_| unavailable(state))?;
    connection.release().await;
    Ok((value, etag))
}
