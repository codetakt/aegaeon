use super::super::dcr_bearer::registration_bearer_token;
use super::super::dcr_runtime::{dcr_database_context, dcr_database_error_response};
use super::super::oauth_errors::bearer_json_error_with_iss;
use super::super::AppState;
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::dcr_persistence::DcrStoredClient;

pub(in crate::web::dcr_configuration) async fn authenticate_database_registration_token(
    state: &AppState,
    headers: &HeaderMap,
    path_client_id: &str,
) -> Result<DcrStoredClient, Response> {
    let issuer_base = state.issuer.as_str();
    let token = registration_bearer_token(headers, issuer_base)?;
    let (pool, issuer_host) = dcr_database_context(state, issuer_base)?;
    match crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        issuer_host,
        path_client_id,
        token,
    )
    .await
    {
        Ok(Some(client)) => Ok(client),
        Ok(None) => Err(bearer_json_error_with_iss(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            Some("invalid registration access token"),
            issuer_base,
        )),
        Err(error) => Err(dcr_database_error_response(&error, issuer_base)),
    }
}
