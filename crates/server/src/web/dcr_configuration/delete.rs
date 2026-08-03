use axum::{
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::util;

use super::super::dcr_runtime::{
    dcr_database_context, dcr_database_error_response, synchronize_dcr_database_runtime_clients,
};
use super::super::{request_id_from_headers, AppState};
use super::admission::enforce_registration_management_admission;
use super::auth::authenticate_database_registration_token;

async fn register_delete_database(
    state: &AppState,
    headers: &HeaderMap,
    client_id: &str,
    issuer_base: &str,
) -> Response {
    let request_id = request_id_from_headers(headers);
    let stored = match authenticate_database_registration_token(state, headers, client_id).await {
        Ok(client) => client,
        Err(resp) => return resp,
    };
    let (pool, _) = match dcr_database_context(state, issuer_base) {
        Ok(context) => context,
        Err(resp) => return resp,
    };
    if let Err(error) =
        crate::dcr_persistence::delete_dynamic_registration(pool, &stored, &request_id).await
    {
        return dcr_database_error_response(&error, issuer_base);
    }
    if let Err(resp) =
        synchronize_dcr_database_runtime_clients(state, issuer_base, &request_id).await
    {
        return resp;
    }
    no_content_response()
}

fn no_content_response() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

pub(in crate::web) async fn register_delete(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if let Err(resp) = enforce_registration_management_admission(&state, &uri, issuer_base) {
        return resp;
    }

    register_delete_database(&state, &headers, &client_id, issuer_base).await
}
