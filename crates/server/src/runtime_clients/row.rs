use sqlx::Row;

use crate::client_registry::{ClientSecretCredential, RegisteredClient, RegisteredClientJwks};

use super::error::RuntimeClientSnapshotError;
use super::snapshot::RuntimeClientSnapshotEntry;

pub(super) fn runtime_client_entry_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<RuntimeClientSnapshotEntry, RuntimeClientSnapshotError> {
    let client_id: String = row.try_get("client_identifier")?;
    let inline_jwks = row
        .try_get::<Option<serde_json::Value>, _>("jwks")?
        .map(|value| RegisteredClientJwks::from_value(value, false))
        .transpose()
        .map_err(|message| {
            RuntimeClientSnapshotError::InvalidDynamicRegistrationProjection(
                client_id.clone(),
                message,
            )
        })?;
    let client_id_issued_at = row
        .try_get::<Option<i64>, _>("client_id_issued_at_epoch_secs")?
        .map(|value| {
            u64::try_from(value).map_err(|_| {
                RuntimeClientSnapshotError::InvalidDynamicRegistrationProjection(
                    client_id.clone(),
                    "client_id_issued_at is invalid".to_string(),
                )
            })
        })
        .transpose()?;
    let client = RegisteredClient {
        client_id: client_id.clone(),
        client_secret: None,
        redirect_uris: row.try_get("redirect_uris")?,
        post_logout_redirect_uris: row.try_get("post_logout_redirect_uris")?,
        backchannel_logout_uri: row.try_get("backchannel_logout_uri")?,
        backchannel_logout_session_required: row.try_get("backchannel_logout_session_required")?,
        token_endpoint_auth_method: row.try_get("token_endpoint_authentication_method")?,
        jwks_pem: None,
        inline_jwks,
        jwks_uri: row.try_get("jwks_uri")?,
        token_endpoint_auth_signing_alg: row.try_get("token_endpoint_auth_signing_alg")?,
        allowed_scopes: row.try_get("allowed_scopes")?,
        allowed_grant_types: row.try_get("allowed_grant_types")?,
        registration_access_token: None,
        client_id_issued_at,
    };
    let secret_hashes: Vec<String> = row.try_get("client_secret_hashes")?;
    let expires_at_epoch_secs: Vec<i64> = row.try_get("client_secret_expires_at_epoch_secs")?;
    let client_secret_credentials =
        secret_credentials_from_projection(&client_id, secret_hashes, expires_at_epoch_secs)?;

    Ok(RuntimeClientSnapshotEntry {
        client,
        client_secret_credentials,
    })
}

fn secret_credentials_from_projection(
    client_id: &str,
    secret_hashes: Vec<String>,
    expires_at_epoch_secs: Vec<i64>,
) -> Result<Vec<ClientSecretCredential>, RuntimeClientSnapshotError> {
    if secret_hashes.len() != expires_at_epoch_secs.len() {
        return Err(
            RuntimeClientSnapshotError::InconsistentClientSecretProjection(client_id.to_string()),
        );
    }
    Ok(secret_hashes
        .into_iter()
        .zip(expires_at_epoch_secs)
        .map(|(secret_hash, expires_at_epoch_secs)| {
            ClientSecretCredential::new(secret_hash, expires_at_epoch_secs)
        })
        .collect())
}
