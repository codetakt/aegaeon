use super::dcr_client_build::build_registered_client_from_metadata;
use super::dcr_profile_validation::validate_registration_policy_or_response;
use super::dcr_response::{
    build_registration_created_response, dcr_response_types, invalid_client_metadata_response,
    required_dcr_registration_access_token,
};
use super::dcr_runtime::{
    dcr_database_context, dcr_database_error_response, dcr_disabled_response,
    synchronize_dcr_database_runtime_clients,
};
use super::oauth_errors::{authorization_header, no_cache_json_error_with_iss};
use super::request_admission::{enforce_content_type, enforce_no_credentials_in_uri};
use super::{clock_error_response, request_id_from_headers, AppState};
use axum::{
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::client_registry::RegisteredClient;
use crate::dcr::{parse_client_registration, ClientRegistration, ClientRegistrationParseError};
use crate::util;

fn bearer_hash_matches(header: Option<&str>, expected_hash: &str) -> bool {
    match header {
        Some(value) => util::parse_bearer_authorization_header(value).is_ok_and(|token| {
            let token_hash = crate::dcr_persistence::dcr_bearer_token_hash(token);
            util::constant_time_eq(token_hash.as_bytes(), expected_hash.as_bytes())
        }),
        None => false,
    }
}

fn parse_registration_body_for_create(
    body: &[u8],
    issuer_base: &str,
) -> Result<ClientRegistration, Response> {
    match parse_client_registration(body) {
        Ok(body) => Ok(body),
        Err(ClientRegistrationParseError::InvalidJson) => Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("invalid json body"),
            issuer_base,
        )),
        Err(
            ClientRegistrationParseError::InvalidMetadata(msg)
            | ClientRegistrationParseError::PolicyViolation(msg),
        ) => Err(invalid_client_metadata_response(msg)),
        Err(ClientRegistrationParseError::Internal(_)) => Err(no_cache_json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            Some("registration parser backend misconfigured"),
            issuer_base,
        )),
    }
}

pub(super) fn parse_registration_body_for_update(
    body: &[u8],
    issuer_base: &str,
) -> Result<ClientRegistration, Response> {
    match parse_client_registration(body) {
        Ok(body) => Ok(body),
        Err(ClientRegistrationParseError::InvalidJson) => Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("invalid json body"),
            issuer_base,
        )),
        Err(
            ClientRegistrationParseError::InvalidMetadata(msg)
            | ClientRegistrationParseError::PolicyViolation(msg),
        ) => Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            Some(&msg),
            issuer_base,
        )),
        Err(ClientRegistrationParseError::Internal(_)) => Err(no_cache_json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            Some("registration parser backend misconfigured"),
            issuer_base,
        )),
    }
}

fn require_registration_bearer(
    expected_hash: Option<&str>,
    headers: &HeaderMap,
) -> Result<(), Response> {
    let Some(expected_hash) = expected_hash else {
        return Ok(());
    };
    let header = match authorization_header(headers) {
        Ok(header) => header,
        Err(err) => {
            let description = err.description("Authorization");
            let mut response = (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "unauthorized_client",
                    "error_description": description,
                })),
            )
                .into_response();
            util::apply_no_cache_headers(&mut response);
            return Err(response);
        }
    };
    if bearer_hash_matches(header, expected_hash) {
        Ok(())
    } else {
        let mut response = (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized_client",
                "error_description": "missing or invalid authorization header",
            })),
        )
            .into_response();
        util::apply_no_cache_headers(&mut response);
        Err(response)
    }
}

fn enforce_registration_create_admission(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    issuer_base: &str,
) -> Result<(), Response> {
    if !state.dcr_enabled {
        return Err(dcr_disabled_response(issuer_base));
    }
    enforce_no_credentials_in_uri(uri, issuer_base)?;
    enforce_content_type(headers, "application/json", issuer_base)?;
    require_registration_bearer(state.dcr_required_bearer_hash.as_deref(), headers)
}

fn dcr_client_issued_at(issuer_base: &str) -> Result<Option<u64>, Response> {
    util::now_unix_epoch_secs().map(Some).map_err(|err| {
        util::log_clock_error("dcr client registration clock", &err);
        clock_error_response(issuer_base)
    })
}

fn build_new_registered_client(
    state: &AppState,
    meta: &ClientRegistration,
    issuer_base: &str,
) -> Result<RegisteredClient, Response> {
    build_registered_client_from_metadata(
        meta,
        uuid::Uuid::new_v4().to_string(),
        aegaeon_crypto::rand::random_base64url(32),
        dcr_client_issued_at(issuer_base)?,
        None,
        state.dcr_require_client_jwt_kid,
        &state.dcr_scope_allowlist,
    )
}

async fn persist_created_registration_in_database(
    state: &AppState,
    issuer_base: &str,
    registered: &RegisteredClient,
    meta: &ClientRegistration,
    request_id: &str,
) -> Result<(), Response> {
    let response_types = dcr_response_types(meta);
    let registration_access_token =
        required_dcr_registration_access_token(issuer_base, registered)?;
    let (pool, issuer_host) = dcr_database_context(state, issuer_base)?;
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        issuer_host,
        registered,
        &response_types,
        registration_access_token,
        request_id,
    )
    .await
    .map_err(|error| dcr_database_error_response(&error, issuer_base))?;
    synchronize_dcr_database_runtime_clients(state, issuer_base, request_id).await
}

async fn persist_created_registration(
    state: &AppState,
    issuer_base: &str,
    registered: &RegisteredClient,
    meta: &ClientRegistration,
    request_id: &str,
) -> Result<(), Response> {
    persist_created_registration_in_database(state, issuer_base, registered, meta, request_id).await
}

pub(super) async fn register(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let issuer_base = state.issuer.as_str();
    let request_id = request_id_from_headers(&headers);
    if let Err(response) =
        enforce_registration_create_admission(&state, &uri, &headers, issuer_base)
    {
        return response;
    }

    let meta = match parse_registration_body_for_create(body.as_ref(), issuer_base) {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    if let Err(resp) =
        validate_registration_policy_or_response(&state, issuer_base, &meta, None).await
    {
        return resp;
    }

    let registered = match build_new_registered_client(&state, &meta, issuer_base) {
        Ok(client) => client,
        Err(resp) => return resp,
    };
    if let Err(response) =
        persist_created_registration(&state, issuer_base, &registered, &meta, &request_id).await
    {
        return response;
    }

    build_registration_created_response(issuer_base, &registered, &meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dcr_registration_bearer_compares_against_hash() {
        let expected_hash = crate::dcr_persistence::dcr_bearer_token_hash("registration-gate");

        assert!(bearer_hash_matches(
            Some("Bearer registration-gate"),
            &expected_hash
        ));
        assert!(!bearer_hash_matches(
            Some("Bearer different-token"),
            &expected_hash
        ));
        assert!(!bearer_hash_matches(None, &expected_hash));
    }
}
