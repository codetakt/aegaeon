use sqlx::Row;
use uuid::Uuid;

use super::DcrDatabaseError;
use crate::client_registry::{RegisteredClient, RegisteredClientJwks};

#[derive(Clone, Debug)]
pub struct DcrStoredClient {
    pub team_id: Uuid,
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub configuration_version_id: Uuid,
    pub database_client_id: Uuid,
    pub registration_access_token_hash: String,
    pub client: RegisteredClient,
    pub response_types: Vec<String>,
    pub has_active_client_secret: bool,
}

pub(super) fn stored_client_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<DcrStoredClient, DcrDatabaseError> {
    let client_id_issued_at = row
        .try_get::<i64, _>("client_id_issued_at_epoch_secs")
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| {
            DcrDatabaseError::CorruptRegistration("client_id_issued_at is invalid".to_string())
        })?;
    let jwks = row
        .try_get::<Option<serde_json::Value>, _>("jwks")?
        .map(|value| RegisteredClientJwks::from_value(value, false))
        .transpose()
        .map_err(DcrDatabaseError::CorruptRegistration)?;

    Ok(DcrStoredClient {
        team_id: row.try_get("team_id")?,
        tenant_id: row.try_get("tenant_id")?,
        environment_id: row.try_get("environment_id")?,
        configuration_version_id: row.try_get("configuration_version_id")?,
        database_client_id: row.try_get("database_client_id")?,
        registration_access_token_hash: row.try_get("registration_access_token_hash")?,
        response_types: row.try_get("response_types")?,
        has_active_client_secret: row.try_get("has_active_client_secret")?,
        client: RegisteredClient {
            client_id: row.try_get("client_identifier")?,
            client_secret: None,
            redirect_uris: row.try_get("redirect_uris")?,
            post_logout_redirect_uris: row.try_get("post_logout_redirect_uris")?,
            backchannel_logout_uri: row.try_get("backchannel_logout_uri")?,
            backchannel_logout_session_required: row
                .try_get("backchannel_logout_session_required")?,
            token_endpoint_auth_method: row.try_get("token_endpoint_authentication_method")?,
            jwks_pem: None,
            inline_jwks: jwks,
            jwks_uri: row.try_get("jwks_uri")?,
            token_endpoint_auth_signing_alg: row.try_get("token_endpoint_auth_signing_alg")?,
            allowed_scopes: row.try_get("allowed_scopes")?,
            allowed_grant_types: row.try_get("allowed_grant_types")?,
            registration_access_token: None,
            client_id_issued_at: Some(client_id_issued_at),
        },
    })
}
