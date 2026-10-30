use super::super::{
    error_response,
    session_support::{get_management_session_id, management_bearer_api_key},
    state::ManagementSession,
    AppState,
};
use crate::organizations::{
    http_input::{self, InputError},
    repository::RepositoryError,
    request_work::Admission,
    AuthorityError,
};
use axum::{
    body::{self, Body},
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::time::Duration;

pub(super) fn failure(status: StatusCode, code: &str, request_id: &str) -> Response {
    let mut response = error_response(
        status,
        code,
        "Organizations request refused",
        None,
        Some(request_id),
    );
    crate::util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn input_error(error: InputError, request_id: &str) -> Response {
    let status = match error {
        InputError::Invalid => StatusCode::BAD_REQUEST,
        InputError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        InputError::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
        InputError::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
    };
    failure(status, "invalid_request", request_id)
}

pub(super) fn storage_error(error: &RepositoryError, request_id: &str) -> Response {
    let (status, code) = match error {
        RepositoryError::Authority(AuthorityError::Invalid) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        RepositoryError::Authority(AuthorityError::Conflict) => {
            (StatusCode::CONFLICT, "idempotency_conflict")
        }
        RepositoryError::Authority(AuthorityError::PreconditionFailed) => {
            (StatusCode::PRECONDITION_FAILED, "precondition_failed")
        }
        RepositoryError::Authority(AuthorityError::Exhausted) => {
            (StatusCode::CONFLICT, "authority_capacity_exhausted")
        }
        RepositoryError::Authority(_) => (StatusCode::FORBIDDEN, "forbidden"),
        RepositoryError::Unavailable | RepositoryError::Storage(_) | RepositoryError::Decode(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
    };
    failure(status, code, request_id)
}

pub(super) async fn ordinary(req: Request<Body>, next: Next) -> Response {
    admitted(req, next, Admission::try_acquire()).await
}

pub(super) async fn revocation(req: Request<Body>, next: Next) -> Response {
    admitted(req, next, Admission::try_acquire_revocation()).await
}

pub(super) async fn snapshot(req: Request<Body>, next: Next) -> Response {
    admitted(req, next, Admission::try_acquire_snapshot()).await
}

async fn admitted(
    req: Request<Body>,
    next: Next,
    admission: Result<Admission, sqlx::Error>,
) -> Response {
    let request_id = crate::web::request_id::request_id_from_headers(req.headers());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let admission = match admission {
        Ok(value) => value,
        Err(_) => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                &request_id,
            )
        }
    };
    let (mut parts, body) = req.into_parts();
    let bytes = match tokio::time::timeout(
        Duration::from_secs(http_input::BODY_TIMEOUT_SECONDS),
        body::to_bytes(body, http_input::MAX_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return failure(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                &request_id,
            )
        }
        Err(_) => return failure(StatusCode::REQUEST_TIMEOUT, "request_timeout", &request_id),
    };
    parts.extensions.insert(admission.clone());
    if matches!(
        parts.method,
        axum::http::Method::GET | axum::http::Method::HEAD
    ) && !bytes.is_empty()
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_request", &request_id);
    }
    let mut response = match tokio::time::timeout_at(
        deadline,
        next.run(Request::from_parts(parts, Body::from(bytes))),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            &request_id,
        ),
    };
    // Axum path/query extractors otherwise use plain text for malformed input.
    // Keep this route family's declared management error envelope consistent.
    if response.status() == StatusCode::BAD_REQUEST
        && !response
            .headers()
            .get("content-type")
            .is_some_and(|v| v.as_bytes().starts_with(b"application/json"))
    {
        response = failure(StatusCode::BAD_REQUEST, "invalid_request", &request_id);
    }
    crate::util::apply_no_cache_headers(&mut response);
    response
}

/// No implicit SQL checkout. Current human identity/topology is checked through
/// the admitted connection in the caller's transaction, before any receipt.
pub(in crate::web::management) async fn require_organization_management_session(
    state: &AppState,
    headers: &HeaderMap,
    admission: &Admission,
    request_id: &str,
) -> Result<ManagementSession, Response> {
    admission.ensure_open().map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            request_id,
        )
    })?;
    if management_bearer_api_key(headers, request_id)?.is_some() {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "human_session_required",
            request_id,
        ));
    }
    let sid = get_management_session_id(headers, request_id)?
        .ok_or_else(|| failure(StatusCode::UNAUTHORIZED, "unauthenticated", request_id))?;
    let now = crate::web::now_epoch_secs().map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            request_id,
        )
    })?;
    let store = state.management.sessions.clone();
    let session = admission
        .blocking(move || store.try_get(&sid, now))
        .await
        .map_err(|_| {
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                request_id,
            )
        })?
        .map_err(|_| {
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                request_id,
            )
        })?
        .ok_or_else(|| failure(StatusCode::UNAUTHORIZED, "unauthenticated", request_id))?;
    if !session.is_human_session() {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "human_session_required",
            request_id,
        ));
    }
    Ok(session)
}
