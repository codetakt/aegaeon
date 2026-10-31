//! Invitation-linked browser credential enrollment; never an OAuth token grant.
use super::*;
use crate::organizations::{http_input, invitations::enrollment as service, Scope};
use axum::{extract::Path, http::request::Parts};
use sqlx::Connection;
use uuid::Uuid;

mod completion;
mod presentation;
pub(in crate::web) const PATH: &str = "/organization-invitations/:domain/:invitation/identity";
const COOKIE: &str = "__Host-aegaeon-organization-identity-csrf";

#[derive(serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Request {
        purpose: service::Purpose,
        invitation_capability: String,
        login_identifier: Option<String>,
        request_key: String,
    },
    Complete {
        request_id: Uuid,
        proof: String,
        password: String,
        password_confirmation: String,
    },
}

pub(in crate::web) async fn handle(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((domain, invitation)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let mut response =
        match execute(&state, &admission, remote, &domain, &invitation, request).await {
            Ok(response) | Err(response) => response,
        };
    // This browser proof flow never challenges for a selected OAuth credential.
    response
        .headers_mut()
        .remove(axum::http::header::WWW_AUTHENTICATE);
    response
}

fn invalid(state: &AppState) -> Response {
    error(state, StatusCode::BAD_REQUEST, "invalid_request")
}
fn now(state: &AppState) -> Result<i64, Response> {
    crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| unavailable(state))
}

async fn execute(
    state: &AppState,
    admission: &ResourceAdmission,
    remote: SocketAddr,
    domain: &str,
    invitation: &str,
    request: Request<Body>,
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
        return Err(error(state, StatusCode::NOT_FOUND, "not_found"));
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
            super::super::transport_boundary::transport_rejection_for_route(state, kind, PATH)
        })?;
    if parts.uri.query().is_some() {
        return Err(invalid(state));
    }
    if matches!(parts.method, Method::GET | Method::HEAD) {
        to_bytes(body, 0).await.map_err(|_| invalid(state))?;
        return presentation::form(state, scope.domain_id, invitation).await;
    }
    let request_id = super::super::request_id::request_id_from_headers(&parts.headers);
    let action = action(state, &parts, body).await?;
    let value = transaction(state, admission, scope, invitation, action, &request_id).await?;
    Ok(super::super::token_json_response(StatusCode::OK, value))
}

async fn action(state: &AppState, parts: &Parts, body: Body) -> Result<Action, Response> {
    if parts.method != Method::POST
        || http_input::one_header(&parts.headers, "content-type").map_err(|_| invalid(state))?
            != Some("application/x-www-form-urlencoded")
    {
        return Err(invalid(state));
    }
    let origin = url::Url::parse(&state.issuer)
        .map_err(|_| unavailable(state))?
        .origin()
        .ascii_serialization();
    if http_input::one_header(&parts.headers, "origin").map_err(|_| invalid(state))?
        != Some(origin.as_str())
    {
        return Err(error(state, StatusCode::FORBIDDEN, "invalid_request"));
    }
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(http_input::BODY_TIMEOUT_SECONDS),
        to_bytes(body, 8192),
    )
    .await
    .map_err(|_| invalid(state))?
    .map_err(|_| invalid(state))?;
    let params: Vec<(String, String)> =
        serde_urlencoded::from_bytes(&bytes).map_err(|_| invalid(state))?;
    let mut fields = serde_json::Map::new();
    for (name, value) in &params {
        if fields
            .insert(name.clone(), serde_json::Value::String(value.clone()))
            .is_some()
        {
            return Err(invalid(state));
        }
    }
    let valid = super::super::try_validate_form_csrf_async(
        &parts.headers,
        &params,
        COOKIE,
        state.device.local_auth_csrf_store.clone(),
    )
    .await
    .map_err(|_| unavailable(state))?;
    if !valid {
        return Err(error(state, StatusCode::FORBIDDEN, "invalid_request"));
    }
    fields.remove("csrf_token");
    if fields
        .get("login_identifier")
        .and_then(serde_json::Value::as_str)
        == Some("")
    {
        fields.remove("login_identifier");
    }
    serde_json::from_value(serde_json::Value::Object(fields)).map_err(|_| invalid(state))
}

async fn transaction(
    state: &AppState,
    admission: &ResourceAdmission,
    scope: Scope,
    invitation: Uuid,
    action: Action,
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    let action = match action {
        Action::Complete {
            request_id: object_id,
            proof,
            password,
            password_confirmation,
        } => {
            return completion::execute(completion::Command {
                state,
                admission,
                scope,
                invitation,
                object_id,
                proof,
                password,
                password_confirmation,
                request_id,
            })
            .await;
        }
        request => request,
    };
    let expected = super::super::organization_authority::projection(state)?;
    let started = now(state)?;
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
    let runtime = crate::organizations::invitations::delegated::Runtime {
        store: &state.tokens.store,
        admission: &admission.0,
        issuer: &state.issuer,
    };
    let (value, completed) = match action {
        Action::Request {
            purpose,
            invitation_capability,
            login_identifier,
            request_key,
        } => {
            let input = service::Request {
                request_id,
                scope,
                invitation,
                capability: &invitation_capability,
                purpose,
                login_identifier: login_identifier.as_deref(),
                key: &request_key,
                now: started,
            };
            let id = service::request(&mut tx, &input, Some(&runtime))
                .await
                .map_err(|e| members::storage_error(state, &e))?;
            (
                serde_json::json!({"requestId":id,"message":"If eligible, a proof will be sent to the invitation address. Open the form again to complete the request."}),
                None,
            )
        }
        Action::Complete { .. } => return Err(invalid(state)),
    };
    super::super::organization_authority::recheck_projection(state, &mut tx, &expected).await?;
    recheck(
        state,
        &mut tx,
        scope,
        invitation,
        started,
        completed,
        (&runtime, request_id),
    )
    .await?;
    admission.0.admit_commit().map_err(|_| unavailable(state))?;
    tx.commit().await.map_err(|_| unavailable(state))?;
    connection.release().await;
    Ok(value)
}

pub(in crate::web) fn routes() -> axum::Router<AppState> {
    axum::Router::new().route(PATH, axum::routing::get(handle).post(handle))
}

async fn recheck(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: Scope,
    invitation: Uuid,
    started: i64,
    completed: Option<(Uuid, String)>,
    context: (
        &crate::organizations::invitations::delegated::Runtime<'_>,
        &str,
    ),
) -> Result<(), Response> {
    let (runtime, request_id) = context;
    let commit_time = now(state)?;
    if commit_time < started {
        return Err(unavailable(state));
    }
    if let Some((request, proof)) = completed {
        service::recheck_completion(
            tx,
            &service::Completion {
                request_id,
                scope,
                invitation,
                request,
                proof: &proof,
                now: commit_time,
            },
            Some(runtime),
        )
        .await
        .map_err(|e| members::storage_error(state, &e))?;
    } else {
        crate::organizations::invitations::recheck(tx, scope, invitation, commit_time, runtime)
            .await
            .map_err(|e| members::storage_error(state, &e))?;
    }
    Ok(())
}
