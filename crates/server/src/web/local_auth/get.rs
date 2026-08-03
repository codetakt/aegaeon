use axum::extract::{OriginalUri, Query, State};
use axum::response::Response;
use http::StatusCode;
use serde::Deserialize;

use super::super::{
    enforce_no_credentials_in_uri, local_password_session_acr, normalized_acr,
    render_local_login_form, render_local_result_page, validate_return_to, AppState,
};
use crate::web::local_auth_support::{
    local_auth_response, local_auth_response_with_csrf_cookie, local_password_acr_error_response,
    try_local_csrf_token_async,
};

#[derive(Deserialize, Default)]
pub(in crate::web) struct LocalLoginQuery {
    return_to: Option<String>,
    acr: Option<String>,
}

pub(in crate::web) async fn local_login_get(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<LocalLoginQuery>,
) -> Response {
    if let Err(resp) = enforce_no_credentials_in_uri(&uri, state.issuer.as_str()) {
        return resp;
    }
    let return_to = match validate_return_to(query.return_to) {
        Ok(value) => value,
        Err(message) => {
            return local_auth_response(
                StatusCode::BAD_REQUEST,
                render_local_result_page("Invalid request", &message, None),
            );
        }
    };
    let requested_acr = normalized_acr(query.acr.as_deref());
    if local_password_session_acr(
        state.cfg.local_password_acr.as_deref(),
        requested_acr.as_deref(),
    )
    .is_err()
    {
        return local_password_acr_error_response();
    }
    let csrf_token =
        match try_local_csrf_token_async(state.device.local_auth_csrf_store.clone()).await {
            Ok(token) => token,
            Err(response) => return response,
        };
    local_auth_response_with_csrf_cookie(
        StatusCode::OK,
        render_local_login_form(
            return_to.as_deref(),
            requested_acr.as_deref(),
            &csrf_token,
            None,
        ),
        &csrf_token,
    )
}
