use axum::{
    extract::{MatchedPath, Request, State},
    http::Method,
    middleware::Next,
    response::Response,
};

use super::super::{dcr_runtime::dcr_database_error_response, AppState};

pub(in crate::web) async fn registration_update_capacity(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let is_update = request.method() == Method::PUT
        && request
            .extensions()
            .get::<MatchedPath>()
            .is_some_and(|path| path.as_str() == "/register/:client_id");
    if !is_update {
        return next.run(request).await;
    }
    match crate::dcr_persistence::admit_http_update(next.run(request)).await {
        Ok(response) => response,
        Err(error) => dcr_database_error_response(&error, state.issuer.as_str()),
    }
}
