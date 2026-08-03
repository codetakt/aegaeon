use super::super::dcr_runtime::{dcr_database_context, dcr_database_error_response};
use super::super::oauth_errors::{authorization_header, bearer_json_error_with_iss};
use super::super::AppState;
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::dcr_persistence::DcrStoredClient;
use crate::util;

fn extract_registration_bearer_token<'a>(
    headers: &'a HeaderMap,
    issuer_base: &str,
) -> Result<&'a str, Response> {
    let token = match authorization_header(headers) {
        Ok(header) => header.and_then(|value| util::parse_bearer_authorization_header(value).ok()),
        Err(err) => {
            let description = err.description("Authorization");
            return Err(bearer_json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(&description),
                issuer_base,
            ));
        }
    };

    let token = match token {
        Some(token) if !token.is_empty() => token,
        _ => {
            return Err(bearer_json_error_with_iss(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                Some("missing or malformed authorization header"),
                issuer_base,
            ));
        }
    };

    Ok(token)
}

pub(in crate::web::dcr_configuration) async fn authenticate_database_registration_token(
    state: &AppState,
    headers: &HeaderMap,
    path_client_id: &str,
) -> Result<DcrStoredClient, Response> {
    let issuer_base = state.issuer.as_str();
    let token = extract_registration_bearer_token(headers, issuer_base)?;
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
