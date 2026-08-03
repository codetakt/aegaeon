use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use crate::client_registry::RegisteredClient;

mod audit;
mod environment;
mod locking;
mod mutation;
mod schema;
mod stored_client;
pub use schema::preflight_dynamic_registration_schema;
#[cfg(test)]
pub(crate) use schema::{
    DynamicRegistrationSchemaDeficit, DynamicRegistrationSchemaInventory, REQUIRED_DCR_COLUMNS,
    REQUIRED_DCR_CONSTRAINTS, REQUIRED_DCR_INDEXES,
};
pub use stored_client::DcrStoredClient;

use self::audit::write_dcr_audit_event;
use self::environment::{
    load_active_environment, load_active_environment_for_update, normalize_issuer_host,
    ActiveDcrEnvironment,
};
use self::locking::lock_current_dynamic_registration;
use self::mutation::{
    delete_dynamic_registration_row, insert_client_row, insert_dynamic_registration_row,
    mark_client_deleted, replace_client_secret, revoke_active_client_secrets, update_client_row,
    update_dynamic_registration_row,
};
use self::stored_client::stored_client_from_row;

pub const MIN_DCR_BEARER_TOKEN_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DcrClientSecretChange {
    Preserve,
    ReplaceWithPlaintext(String),
    RevokeAll,
}

#[derive(Debug, Error)]
pub enum DcrDatabaseError {
    #[error("issuer host for dynamic client registration persistence must not be empty")]
    EmptyIssuerHost,

    #[error("no active management environment matched issuer host `{0}`")]
    EnvironmentNotFound(String),

    #[error("multiple active management environments matched issuer host `{0}`")]
    MultipleEnvironments(String),

    #[error("stored dynamic client registration is corrupted: {0}")]
    CorruptRegistration(String),

    #[error("failed to hash generated client secret: {0}")]
    ClientSecretHash(String),

    #[error("dynamic client registration database schema preflight failed: {0}")]
    SchemaPreflight(String),

    #[error("dynamic client registration changed concurrently")]
    ConcurrentModification,

    #[error("dynamic client registration database query failed: {0}")]
    Database(#[from] sqlx::Error),
}

impl DcrDatabaseError {
    #[must_use]
    pub fn is_unique_violation(&self) -> bool {
        matches!(
            self,
            Self::Database(sqlx::Error::Database(db_err))
                if db_err.code().as_deref() == Some("23505")
        )
    }
}

#[must_use]
pub fn registration_access_token_hash(token: &str) -> String {
    aegaeon_crypto::hash::sha256_hex(token.as_bytes())
}

#[must_use]
pub fn dcr_bearer_token_hash(token: &str) -> String {
    aegaeon_crypto::hash::sha256_hex(token.as_bytes())
}

#[must_use]
pub fn client_auth_method_uses_secret(method: &str) -> bool {
    let method = method.trim();
    method.eq_ignore_ascii_case("client_secret_basic")
        || method.eq_ignore_ascii_case("client_secret_post")
}

pub(super) fn require_dynamic_registration_access_token(
    token: &str,
) -> Result<&str, DcrDatabaseError> {
    if token.trim().is_empty() {
        Err(DcrDatabaseError::CorruptRegistration(
            "registration_access_token is missing".to_string(),
        ))
    } else {
        Ok(token)
    }
}

pub(super) fn require_dynamic_registration_client_id_issued_at(
    client: &RegisteredClient,
) -> Result<u64, DcrDatabaseError> {
    client.client_id_issued_at.ok_or_else(|| {
        DcrDatabaseError::CorruptRegistration("client_id_issued_at is missing".to_string())
    })
}

pub async fn load_dcr_bearer_token_hash_for_issuer_host(
    pool: &PgPool,
    issuer_host: &str,
) -> Result<Option<String>, DcrDatabaseError> {
    let environment = load_active_environment(pool, issuer_host).await?;
    sqlx::query(
        r"
SELECT token_hash
FROM aegaeon.environment_dcr_bearer_tokens
WHERE environment_id = $1
  AND token_hash_algorithm = 'sha256'
        ",
    )
    .bind(environment.environment_id)
    .fetch_optional(pool)
    .await?
    .map(|row| row.try_get("token_hash"))
    .transpose()
    .map_err(DcrDatabaseError::Database)
}

pub async fn create_dynamic_registration(
    pool: &PgPool,
    issuer_host: &str,
    client: &RegisteredClient,
    response_types: &[String],
    registration_access_token: &str,
    request_id: &str,
) -> Result<(), DcrDatabaseError> {
    let database_client_id = Uuid::new_v4();
    let mut tx = pool.begin().await?;
    let environment = load_active_environment_for_update(&mut tx, issuer_host).await?;

    insert_client_row(
        &mut tx,
        environment,
        database_client_id,
        client,
        response_types,
    )
    .await?;

    if let Some(secret) = client.client_secret.as_deref() {
        replace_client_secret(&mut tx, environment, database_client_id, secret).await?;
    }

    insert_dynamic_registration_row(
        &mut tx,
        environment,
        database_client_id,
        client,
        response_types,
        registration_access_token,
    )
    .await?;

    write_dcr_audit_event(
        &mut tx,
        environment,
        database_client_id,
        "dcr.client.created.v1",
        client,
        response_types,
        request_id,
    )
    .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn load_dynamic_registration_by_token(
    pool: &PgPool,
    issuer_host: &str,
    client_identifier: &str,
    registration_access_token: &str,
) -> Result<Option<DcrStoredClient>, DcrDatabaseError> {
    let issuer_host = normalize_issuer_host(issuer_host)?;
    let token_hash = registration_access_token_hash(registration_access_token);
    let row = sqlx::query(
        r"
SELECT
  rt.team_id,
  rt.tenant_id,
  rt.environment_id,
  rt.configuration_version_id,
  c.id AS database_client_id,
  c.client_identifier,
  c.redirect_uris,
  c.allowed_grant_types,
  c.allowed_scopes,
  c.token_endpoint_authentication_method,
  EXTRACT(EPOCH FROM dcr.client_id_issued_at)::BIGINT AS client_id_issued_at_epoch_secs,
  dcr.response_types,
  dcr.post_logout_redirect_uris,
  dcr.backchannel_logout_uri,
  dcr.backchannel_logout_session_required,
  dcr.jwks_uri,
  dcr.jwks,
  dcr.token_endpoint_auth_signing_alg,
  dcr.registration_access_token_hash,
  EXISTS (
    SELECT 1
    FROM aegaeon.client_secrets cs
    WHERE cs.environment_id = c.environment_id
      AND cs.client_id = c.id
      AND cs.status = 'ACTIVE'
      AND cs.expires_at > now()
      AND cs.secret_hash_algorithm = 'argon2id'
  ) AS has_active_client_secret
FROM aegaeon.dynamic_client_registrations dcr
JOIN aegaeon.clients c
  ON c.environment_id = dcr.environment_id
 AND c.id = dcr.client_id
JOIN aegaeon.environments e
  ON e.id = c.environment_id
JOIN aegaeon.active_runtime_environments rt
  ON rt.environment_id = e.id
WHERE rt.issuer_host = $1
  AND c.status = 'ACTIVE'
  AND c.configuration_version_id = rt.configuration_version_id
  AND c.client_identifier = $2
  AND dcr.registration_access_token_hash = $3
  AND dcr.registration_access_token_hash_algorithm = 'sha256'
LIMIT 1
        ",
    )
    .bind(issuer_host)
    .bind(client_identifier)
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;

    row.as_ref().map(stored_client_from_row).transpose()
}

pub async fn update_dynamic_registration(
    pool: &PgPool,
    stored: &DcrStoredClient,
    client: &RegisteredClient,
    response_types: &[String],
    registration_access_token: &str,
    secret_change: DcrClientSecretChange,
    request_id: &str,
) -> Result<(), DcrDatabaseError> {
    let mut tx = pool.begin().await?;
    lock_current_dynamic_registration(&mut tx, stored).await?;

    update_client_row(&mut tx, stored, client, response_types).await?;

    update_dynamic_registration_row(
        &mut tx,
        stored,
        client,
        response_types,
        registration_access_token,
    )
    .await?;

    match secret_change {
        DcrClientSecretChange::Preserve => {}
        DcrClientSecretChange::ReplaceWithPlaintext(secret) => {
            revoke_active_client_secrets(&mut tx, stored.environment_id, stored.database_client_id)
                .await?;
            replace_client_secret(
                &mut tx,
                ActiveDcrEnvironment {
                    team_id: stored.team_id,
                    tenant_id: stored.tenant_id,
                    environment_id: stored.environment_id,
                    configuration_version_id: stored.configuration_version_id,
                },
                stored.database_client_id,
                &secret,
            )
            .await?;
        }
        DcrClientSecretChange::RevokeAll => {
            revoke_active_client_secrets(&mut tx, stored.environment_id, stored.database_client_id)
                .await?;
        }
    }

    write_dcr_audit_event(
        &mut tx,
        ActiveDcrEnvironment {
            team_id: stored.team_id,
            tenant_id: stored.tenant_id,
            environment_id: stored.environment_id,
            configuration_version_id: stored.configuration_version_id,
        },
        stored.database_client_id,
        "dcr.client.updated.v1",
        client,
        response_types,
        request_id,
    )
    .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn delete_dynamic_registration(
    pool: &PgPool,
    stored: &DcrStoredClient,
    request_id: &str,
) -> Result<(), DcrDatabaseError> {
    let mut tx = pool.begin().await?;
    lock_current_dynamic_registration(&mut tx, stored).await?;

    revoke_active_client_secrets(&mut tx, stored.environment_id, stored.database_client_id).await?;
    delete_dynamic_registration_row(&mut tx, stored).await?;
    mark_client_deleted(&mut tx, stored).await?;

    write_dcr_audit_event(
        &mut tx,
        ActiveDcrEnvironment {
            team_id: stored.team_id,
            tenant_id: stored.tenant_id,
            environment_id: stored.environment_id,
            configuration_version_id: stored.configuration_version_id,
        },
        stored.database_client_id,
        "dcr.client.deleted.v1",
        &stored.client,
        &stored.response_types,
        request_id,
    )
    .await?;

    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
