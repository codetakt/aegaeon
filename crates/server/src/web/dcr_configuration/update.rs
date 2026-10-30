use axum::{
    extract::{OriginalUri, Path, State},
    http::HeaderMap,
    response::Response,
};

use crate::dcr::ClientRegistration;
use crate::dcr_persistence::DcrStoredClient;

use super::super::dcr_client_build::{
    build_registered_client_from_metadata_with_secret_state, BuiltDcrClient, DcrClientBuildInput,
    ExistingDcrClientSecret,
};
use super::super::dcr_profile_validation::validate_registration_policy_with_existing_response_types_or_response;
use super::super::dcr_registration::parse_registration_body_for_update;
use super::super::dcr_response::{
    build_registration_update_response, dcr_update_response_types,
    required_dcr_registration_access_token,
};
use super::super::dcr_runtime::{
    dcr_database_context, dcr_database_error_response, dcr_database_secret_change,
    synchronize_dcr_database_runtime_clients,
};
use super::super::{request_id_from_headers, AppState};
use super::admission::enforce_registration_update_admission;
use super::auth::authenticate_database_registration_token;

fn database_existing_secret_state(stored: &DcrStoredClient) -> ExistingDcrClientSecret {
    if stored.has_active_client_secret {
        ExistingDcrClientSecret::PresentWithoutPlaintext
    } else {
        ExistingDcrClientSecret::None
    }
}

fn build_database_updated_client(
    state: &AppState,
    client_id: &str,
    meta: &ClientRegistration,
    stored: &DcrStoredClient,
) -> Result<BuiltDcrClient, Response> {
    build_registered_client_from_metadata_with_secret_state(DcrClientBuildInput {
        meta,
        client_id: client_id.to_string(),
        registration_access_token: aegaeon_crypto::rand::random_base64url(32),
        client_id_issued_at: stored.client.client_id_issued_at,
        existing: Some(&stored.client),
        existing_secret: database_existing_secret_state(stored),
        require_client_jwt_kid: state.dcr_require_client_jwt_kid,
        scope_allowlist: &state.dcr_scope_allowlist,
    })
}

async fn persist_database_registration_update(
    state: &AppState,
    issuer_base: &str,
    stored: &DcrStoredClient,
    built: &BuiltDcrClient,
    response_types: &[String],
    request_id: &str,
    client_secret_assertion: Option<&str>,
) -> Result<(), Response> {
    let registration_access_token =
        required_dcr_registration_access_token(issuer_base, &built.client)?;
    let secret_change = dcr_database_secret_change(
        &built.client.token_endpoint_auth_method,
        built.generated_client_secret.clone(),
    );
    let (pool, _) = dcr_database_context(state, issuer_base)?;
    crate::dcr_persistence::update_dynamic_registration(
        pool,
        stored,
        &built.client,
        response_types,
        registration_access_token,
        secret_change,
        client_secret_assertion,
        request_id,
    )
    .await
    .map_err(|error| dcr_database_error_response(&error, issuer_base))?;
    synchronize_dcr_database_runtime_clients(state, issuer_base, request_id).await
}

async fn register_update_database(
    state: &AppState,
    headers: &HeaderMap,
    client_id: &str,
    body: &[u8],
    issuer_base: &str,
) -> Response {
    let request_id = request_id_from_headers(headers);
    let stored = match authenticate_database_registration_token(state, headers, client_id).await {
        Ok(client) => client,
        Err(resp) => return resp,
    };
    let update =
        match parse_registration_body_for_update(body, issuer_base, &stored.client.client_id) {
            Ok(meta) => meta,
            Err(resp) => return resp,
        };
    let meta = match validate_registration_policy_with_existing_response_types_or_response(
        state,
        issuer_base,
        &update.metadata,
        Some(&stored.client),
        Some(&stored.response_types),
    )
    .await
    {
        Ok(effective) => effective,
        Err(response) => return response,
    };
    let built = match build_database_updated_client(state, client_id, &meta, &stored) {
        Ok(client) => client,
        Err(resp) => return resp,
    };
    let response_types = dcr_update_response_types(&meta, &stored.response_types);
    if let Err(resp) = persist_database_registration_update(
        state,
        issuer_base,
        &stored,
        &built,
        &response_types,
        &request_id,
        update.client_secret_assertion.as_deref(),
    )
    .await
    {
        return resp;
    }
    build_registration_update_response(
        issuer_base,
        &built.client,
        &response_types,
        built.generated_client_secret.is_some(),
    )
}

pub(in crate::web) async fn register_update(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let issuer_base = state.issuer.as_str();

    if let Err(response) =
        enforce_registration_update_admission(&state, &uri, &headers, issuer_base)
    {
        return response;
    }

    register_update_database(&state, &headers, &client_id, body.as_ref(), issuer_base).await
}
