use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, FromRequest, MatchedPath, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tower::{Layer, ServiceExt};

use super::super::{dcr_runtime::dcr_database_error_response, AppState};

pub(in crate::web) async fn registration_update_capacity(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let issuer = state.issuer.clone();
    let is_update = request.method() == Method::PUT
        && request
            .extensions()
            .get::<MatchedPath>()
            .is_some_and(|path| path.as_str() == "/register/:client_id");
    if !is_update {
        return next.run(request).await;
    }
    match crate::dcr_persistence::admit_http_update(async move {
        let (parts, body) = request.into_parts();
        let body = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            DefaultBodyLimit::max(super::super::router::SERVER_REQUEST_BODY_LIMIT_BYTES)
                .layer(tower::service_fn(|request| async move {
                    Bytes::from_request(request, &()).await
                }))
                .oneshot(Request::new(body)),
        )
        .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(error)) => return error.into_response(),
            Err(_) => {
                return super::super::no_cache_json_error_with_iss(
                    StatusCode::REQUEST_TIMEOUT,
                    "invalid_request",
                    Some("registration update body deadline exceeded"),
                    state.issuer.as_str(),
                )
            }
        };
        next.run(Request::from_parts(parts, Body::from(body))).await
    })
    .await
    {
        Ok(response) => response,
        Err(error) => dcr_database_error_response(&error, issuer.as_str()),
    }
}
