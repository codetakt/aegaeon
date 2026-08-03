use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::client_registry::RegisteredClient;

use super::environment::ActiveDcrEnvironment;
use super::{
    registration_access_token_hash, require_dynamic_registration_access_token,
    require_dynamic_registration_client_id_issued_at, DcrDatabaseError, DcrStoredClient,
};

pub(super) async fn insert_client_row(
    tx: &mut Transaction<'_, Postgres>,
    environment: ActiveDcrEnvironment,
    database_client_id: Uuid,
    client: &RegisteredClient,
    _response_types: &[String],
) -> Result<(), DcrDatabaseError> {
    sqlx::query(
        r"
INSERT INTO aegaeon.clients (
  id,
  environment_id,
  configuration_version_id,
  client_identifier,
  name,
  client_type,
  redirect_uris,
  allowed_grant_types,
  allowed_scopes,
  token_endpoint_authentication_method
)
VALUES ($1, $2, $3, $4, $5, $6::aegaeon.client_type, $7, $8, $9, $10)
        ",
    )
    .bind(database_client_id)
    .bind(environment.environment_id)
    .bind(environment.configuration_version_id)
    .bind(&client.client_id)
    .bind(client_name(client))
    .bind(client_type_for_auth_method(
        &client.token_endpoint_auth_method,
    ))
    .bind(&client.redirect_uris)
    .bind(&client.allowed_grant_types)
    .bind(&client.allowed_scopes)
    .bind(&client.token_endpoint_auth_method)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn update_client_row(
    tx: &mut Transaction<'_, Postgres>,
    stored: &DcrStoredClient,
    client: &RegisteredClient,
    _response_types: &[String],
) -> Result<(), DcrDatabaseError> {
    sqlx::query(
        r"
UPDATE aegaeon.clients
SET
  client_identifier = $1,
  name = $2,
  client_type = $3::aegaeon.client_type,
  redirect_uris = $4,
  allowed_grant_types = $5,
  allowed_scopes = $6,
  token_endpoint_authentication_method = $7,
  updated_at = now()
WHERE id = $8
  AND environment_id = $9
  AND configuration_version_id = $10
  AND status = 'ACTIVE'
        ",
    )
    .bind(&client.client_id)
    .bind(client_name(client))
    .bind(client_type_for_auth_method(
        &client.token_endpoint_auth_method,
    ))
    .bind(&client.redirect_uris)
    .bind(&client.allowed_grant_types)
    .bind(&client.allowed_scopes)
    .bind(&client.token_endpoint_auth_method)
    .bind(stored.database_client_id)
    .bind(stored.environment_id)
    .bind(stored.configuration_version_id)
    .execute(&mut **tx)
    .await
    .map(|result| result.rows_affected())
    .map_err(DcrDatabaseError::Database)
    .and_then(expect_single_affected_row)?;
    Ok(())
}

pub(super) async fn insert_dynamic_registration_row(
    tx: &mut Transaction<'_, Postgres>,
    environment: ActiveDcrEnvironment,
    database_client_id: Uuid,
    client: &RegisteredClient,
    response_types: &[String],
    registration_access_token: &str,
) -> Result<(), DcrDatabaseError> {
    let registration_access_token =
        require_dynamic_registration_access_token(registration_access_token)?;
    let client_id_issued_at = require_dynamic_registration_client_id_issued_at(client)?;
    let inline_jwks = client
        .inline_jwks
        .as_ref()
        .map(|jwks| jwks.as_value().clone());
    sqlx::query(
        r"
INSERT INTO aegaeon.dynamic_client_registrations (
  environment_id,
  client_id,
  client_identifier,
  registration_access_token_hash,
  registration_access_token_hash_algorithm,
  client_id_issued_at,
  response_types,
  post_logout_redirect_uris,
  backchannel_logout_uri,
  backchannel_logout_session_required,
  jwks_uri,
  jwks,
  token_endpoint_auth_signing_alg
)
VALUES (
  $1,
  $2,
  $3,
  $4,
  'sha256',
  to_timestamp($5)::timestamptz,
  $6,
  $7,
  $8,
  $9,
  $10,
  $11,
  $12
)
        ",
    )
    .bind(environment.environment_id)
    .bind(database_client_id)
    .bind(&client.client_id)
    .bind(registration_access_token_hash(registration_access_token))
    .bind(client_id_issued_at as f64)
    .bind(response_types)
    .bind(&client.post_logout_redirect_uris)
    .bind(&client.backchannel_logout_uri)
    .bind(client.backchannel_logout_session_required)
    .bind(&client.jwks_uri)
    .bind(inline_jwks)
    .bind(&client.token_endpoint_auth_signing_alg)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn update_dynamic_registration_row(
    tx: &mut Transaction<'_, Postgres>,
    stored: &DcrStoredClient,
    client: &RegisteredClient,
    response_types: &[String],
    registration_access_token: &str,
) -> Result<(), DcrDatabaseError> {
    let registration_access_token =
        require_dynamic_registration_access_token(registration_access_token)?;
    let client_id_issued_at = require_dynamic_registration_client_id_issued_at(client)?;
    let inline_jwks = client
        .inline_jwks
        .as_ref()
        .map(|jwks| jwks.as_value().clone());
    sqlx::query(
        r"
UPDATE aegaeon.dynamic_client_registrations
SET
  client_identifier = $1,
  registration_access_token_hash = $2,
  client_id_issued_at = to_timestamp($3)::timestamptz,
  response_types = $4,
  post_logout_redirect_uris = $5,
  backchannel_logout_uri = $6,
  backchannel_logout_session_required = $7,
  jwks_uri = $8,
  jwks = $9,
  token_endpoint_auth_signing_alg = $10,
  updated_at = now()
WHERE environment_id = $11
  AND client_id = $12
  AND registration_access_token_hash = $13
  AND registration_access_token_hash_algorithm = 'sha256'
        ",
    )
    .bind(&client.client_id)
    .bind(registration_access_token_hash(registration_access_token))
    .bind(client_id_issued_at as f64)
    .bind(response_types)
    .bind(&client.post_logout_redirect_uris)
    .bind(&client.backchannel_logout_uri)
    .bind(client.backchannel_logout_session_required)
    .bind(&client.jwks_uri)
    .bind(inline_jwks)
    .bind(&client.token_endpoint_auth_signing_alg)
    .bind(stored.environment_id)
    .bind(stored.database_client_id)
    .bind(&stored.registration_access_token_hash)
    .execute(&mut **tx)
    .await
    .map(|result| result.rows_affected())
    .map_err(DcrDatabaseError::Database)
    .and_then(expect_single_affected_row)?;
    Ok(())
}

pub(super) async fn replace_client_secret(
    tx: &mut Transaction<'_, Postgres>,
    environment: ActiveDcrEnvironment,
    database_client_id: Uuid,
    plaintext_secret: &str,
) -> Result<(), DcrDatabaseError> {
    let secret_hash = crate::local_credentials::hash_password(plaintext_secret)
        .map_err(DcrDatabaseError::ClientSecretHash)?;
    sqlx::query(
        r"
INSERT INTO aegaeon.client_secrets (
  environment_id,
  client_id,
  configuration_version_id,
  secret_hash,
  secret_hash_algorithm,
  expires_at,
  comment
)
VALUES (
  $1,
  $2,
  $3,
  $4,
  'argon2id',
  TIMESTAMPTZ '9999-12-31 23:59:59+00',
  'dynamic client registration secret'
)
        ",
    )
    .bind(environment.environment_id)
    .bind(database_client_id)
    .bind(environment.configuration_version_id)
    .bind(secret_hash)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn revoke_active_client_secrets(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    database_client_id: Uuid,
) -> Result<(), DcrDatabaseError> {
    sqlx::query(
        r"
UPDATE aegaeon.client_secrets
SET status = 'REVOKED',
    revoked_at = now()
WHERE environment_id = $1
  AND client_id = $2
  AND status = 'ACTIVE'
        ",
    )
    .bind(environment_id)
    .bind(database_client_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn delete_dynamic_registration_row(
    tx: &mut Transaction<'_, Postgres>,
    stored: &DcrStoredClient,
) -> Result<(), DcrDatabaseError> {
    sqlx::query(
        r"
DELETE FROM aegaeon.dynamic_client_registrations
WHERE environment_id = $1
  AND client_id = $2
  AND registration_access_token_hash = $3
  AND registration_access_token_hash_algorithm = 'sha256'
        ",
    )
    .bind(stored.environment_id)
    .bind(stored.database_client_id)
    .bind(&stored.registration_access_token_hash)
    .execute(&mut **tx)
    .await
    .map(|result| result.rows_affected())
    .map_err(DcrDatabaseError::Database)
    .and_then(expect_single_affected_row)
}

pub(super) async fn mark_client_deleted(
    tx: &mut Transaction<'_, Postgres>,
    stored: &DcrStoredClient,
) -> Result<(), DcrDatabaseError> {
    sqlx::query(
        r"
UPDATE aegaeon.clients
SET status = 'DELETED',
    deleted_at = now(),
    updated_at = now()
WHERE id = $1
  AND environment_id = $2
  AND configuration_version_id = $3
  AND status <> 'DELETED'
        ",
    )
    .bind(stored.database_client_id)
    .bind(stored.environment_id)
    .bind(stored.configuration_version_id)
    .execute(&mut **tx)
    .await
    .map(|result| result.rows_affected())
    .map_err(DcrDatabaseError::Database)
    .and_then(expect_single_affected_row)
}

fn expect_single_affected_row(rows: u64) -> Result<(), DcrDatabaseError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(DcrDatabaseError::ConcurrentModification)
    }
}

fn client_type_for_auth_method(method: &str) -> &'static str {
    if method.trim().eq_ignore_ascii_case("none") {
        "PUBLIC"
    } else {
        "CONFIDENTIAL"
    }
}

fn client_name(client: &RegisteredClient) -> String {
    format!("Dynamic client {}", client.client_id)
}
