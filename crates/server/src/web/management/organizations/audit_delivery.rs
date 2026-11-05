use super::super::http_boundary::RequestContext;
use super::{
    boundary::{failure, input_error, storage_error},
    mutations::NoQuery,
    AppState,
};
use crate::organizations::{
    audit::delivery::{self, Acknowledgment},
    http_input::{self, InputError},
    repository::{ActorKind, AuditActor},
    request_work::Admission,
    Scope,
};
use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use sqlx::Connection;
use uuid::Uuid;

pub(super) async fn pending(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
) -> Response {
    execute(
        &state,
        &headers,
        &admission,
        &context,
        team,
        Scope {
            environment_id,
            domain_id,
        },
        None,
    )
    .await
}

pub(super) async fn acknowledge(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input = match http_input::decode_json(&body) {
        Ok(value) => value,
        Err(error) => return input_error(error, &context.request_id),
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        team,
        Scope {
            environment_id,
            domain_id,
        },
        Some(input),
    )
    .await
}

fn required_batch(headers: &HeaderMap) -> Result<&str, InputError> {
    let value =
        http_input::one_header(headers, "if-match")?.ok_or(InputError::PreconditionRequired)?;
    if value.len() > http_input::MAX_PRECONDITION_BYTES {
        return Err(InputError::TooLarge);
    }
    let value = value.trim_matches([' ', '\t']);
    if value == "*" {
        return Err(InputError::PreconditionRequired);
    }
    let value = value
        .strip_prefix("\"audit-batch.")
        .and_then(|s| s.strip_suffix('"'))
        .ok_or(InputError::Invalid)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(InputError::Invalid);
    }
    Ok(value)
}

async fn execute(
    state: &AppState,
    headers: &HeaderMap,
    admission: &Admission,
    context: &RequestContext,
    team: Uuid,
    scope: Scope,
    input: Option<Acknowledgment>,
) -> Response {
    match transaction(state, headers, admission, context, team, scope, input).await {
        Ok(response) | Err(response) => response,
    }
}

async fn transaction(
    state: &AppState,
    headers: &HeaderMap,
    admission: &Admission,
    context: &RequestContext,
    team: Uuid,
    scope: Scope,
    input: Option<Acknowledgment>,
) -> Result<Response, Response> {
    let request_id = &context.request_id;
    let (key, expected) = if input.is_some() {
        (
            http_input::idempotency_key(headers).map_err(|e| input_error(e, request_id))?,
            required_batch(headers).map_err(|e| input_error(e, request_id))?,
        )
    } else {
        ("", "")
    };
    let session =
        super::audit_identity::authenticate(state, headers, admission, team, request_id).await?;
    let unavailable = || {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            request_id,
        )
    };
    let mut connection = admission
        .connection(&state.db_pool)
        .await
        .map_err(|_| unavailable())?;
    let mut tx = connection
        .as_mut()
        .map_err(|_| unavailable())?
        .begin()
        .await
        .map_err(|_| unavailable())?;
    if !session.is_human_session() {
        // Match credential revocation's lock order before domain/grant locks;
        // final validation below also observes expiry after intervening work.
        super::audit_identity::lock_current(&mut tx, &session, headers, team, request_id).await?;
    }
    let (encoded, hash) = if let Some(input) = input {
        let actor = AuditActor {
            basis: None,
            id: session.administrator_id,
            kind: ActorKind::Operator,
            client_id: session.api_key_id().map_or_else(
                || "management-console".into(),
                |key| format!("management-api-key:{key}"),
            ),
            client_registration_id: None,
            request_id: request_id.clone(),
            reason: input.reason.clone(),
        };
        let receipt = delivery::acknowledge(
            &mut tx,
            delivery::Command {
                scope,
                team,
                actor: &actor,
                key,
                expected_batch: expected,
                input: &input,
            },
        )
        .await
        .map_err(|e| storage_error(&e, request_id))?;
        (
            serde_json::to_vec(&receipt).map_err(|_| unavailable())?,
            expected.to_owned(),
        )
    } else {
        let (batch, hash) = delivery::pending(&mut tx, scope, team, session.administrator_id)
            .await
            .map_err(|e| storage_error(&e, request_id))?;
        (serde_json::to_vec(&batch).map_err(|_| unavailable())?, hash)
    };
    if encoded.len() > http_input::MAX_BODY_BYTES {
        return Err(unavailable());
    }
    super::audit_identity::recheck_current(
        state, headers, admission, &mut tx, &session, team, request_id,
    )
    .await?;
    admission.admit_commit().map_err(|_| unavailable())?;
    tx.commit().await.map_err(|_| unavailable())?;
    connection.release().await;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::ETAG, format!("\"audit-batch.{hash}\"")),
        ],
        Body::from(encoded),
    )
        .into_response())
}
