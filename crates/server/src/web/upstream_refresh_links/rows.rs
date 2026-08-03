use super::super::upstream_refresh_token_envelope::{
    open_upstream_refresh_token, upstream_refresh_token_envelope_error_response,
};
use super::errors::{
    corrupted_account_link_row_error, corrupted_upstream_client_row_error, internal_server_error,
};
use super::{AccountLinkIdentity, UpstreamClient};
use crate::upstream::{open_upstream_client_secret, upstream_client_auth_method_uses_secret};
use axum::response::Response;
use sqlx::{postgres::PgRow, Row};

pub(super) fn read_link_identity_from_row(
    row: &PgRow,
    issuer_base: &str,
) -> Result<AccountLinkIdentity, Response> {
    Ok(AccountLinkIdentity {
        account_link_id: row
            .try_get("account_link_id")
            .map_err(|_| corrupted_account_link_row_error(issuer_base))?,
        environment_id: row
            .try_get("environment_id")
            .map_err(|_| corrupted_account_link_row_error(issuer_base))?,
        upstream_issuer: row
            .try_get("upstream_issuer")
            .map_err(|_| corrupted_account_link_row_error(issuer_base))?,
        upstream_sub_hash: row
            .try_get("upstream_sub_hash")
            .map_err(|_| corrupted_account_link_row_error(issuer_base))?,
        refresh_token_generation: row
            .try_get("upstream_refresh_token_generation")
            .map_err(|_| corrupted_account_link_row_error(issuer_base))?,
    })
}

pub(super) fn open_refresh_token_from_row(
    row: &PgRow,
    identity: &AccountLinkIdentity,
    issuer_base: &str,
) -> Result<String, Response> {
    let encrypted_refresh_token = row
        .try_get::<Vec<u8>, _>("upstream_refresh_token_encrypted")
        .map_err(|_| internal_server_error(issuer_base, "upstream refresh token is corrupted"))?;

    let client = read_upstream_client_from_row(row, issuer_base)?;
    open_upstream_refresh_token(
        encrypted_refresh_token.as_slice(),
        identity.environment_id,
        identity.upstream_issuer.as_str(),
        identity.upstream_sub_hash.as_str(),
        client.connection_id,
        identity.refresh_token_generation,
    )
    .map_err(|error| {
        upstream_refresh_token_envelope_error_response(
            error,
            "failed to decrypt upstream refresh token",
            issuer_base,
        )
    })
}

pub(super) fn read_upstream_client_from_row(
    row: &PgRow,
    issuer_base: &str,
) -> Result<UpstreamClient, Response> {
    Ok(UpstreamClient {
        connection_id: row
            .try_get("connection_id")
            .map_err(|_| corrupted_upstream_client_row_error(issuer_base))?,
        connection_identifier: row
            .try_get("connection_identifier")
            .map_err(|_| corrupted_upstream_client_row_error(issuer_base))?,
        client_id: row
            .try_get("client_id")
            .map_err(|_| corrupted_upstream_client_row_error(issuer_base))?,
        auth_method: row
            .try_get("client_auth_method")
            .map_err(|_| corrupted_upstream_client_row_error(issuer_base))?,
    })
}

pub(super) fn open_optional_upstream_client_secret(
    row: &PgRow,
    identity: &AccountLinkIdentity,
    client: &UpstreamClient,
    issuer_base: &str,
) -> Result<Option<String>, Response> {
    if !upstream_client_auth_method_uses_secret(client.auth_method.as_str()) {
        return Ok(None);
    }

    let encrypted_client_secret: Option<Vec<u8>> = row
        .try_get("client_secret_encrypted")
        .map_err(|_| corrupted_upstream_client_row_error(issuer_base))?;
    let Some(encrypted_client_secret) = encrypted_client_secret else {
        return Err(internal_server_error(
            issuer_base,
            "upstream connection client_secret is not configured",
        ));
    };

    open_upstream_client_secret(
        encrypted_client_secret.as_slice(),
        identity.environment_id,
        client.connection_id,
    )
    .map(Some)
    .map_err(|_| {
        internal_server_error(
            issuer_base,
            "upstream connection client_secret is unavailable",
        )
    })
}
