use axum::{
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use crate::util;

use super::super::dcr_response::build_client_read_response_with_response_types;
use super::super::AppState;
use super::admission::enforce_registration_management_admission;
use super::auth::authenticate_database_registration_token;

pub(in crate::web) async fn register_read(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if let Err(resp) = enforce_registration_management_admission(&state, &uri, issuer_base) {
        return resp;
    }

    let stored = match authenticate_database_registration_token(&state, &headers, &client_id).await
    {
        Ok(client) => client,
        Err(resp) => return resp,
    };
    let mut response = (
        StatusCode::OK,
        Json(build_client_read_response_with_response_types(
            &stored.client,
            &stored.response_types,
        )),
    )
        .into_response();
    util::apply_no_cache_headers(&mut response);
    response
}
