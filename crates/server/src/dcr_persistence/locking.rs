use sqlx::{Postgres, Transaction};

use super::{DcrDatabaseError, DcrStoredClient};

pub(super) async fn lock_current_dynamic_registration(
    tx: &mut Transaction<'_, Postgres>,
    stored: &DcrStoredClient,
) -> Result<(), DcrDatabaseError> {
    crate::organizations::request_work::async_store::ensure_environment_if_scoped(
        stored.environment_id,
    )?;
    // Match management mutations: environment, client, then registration.
    // NO KEY UPDATE still serializes environment activation, while permitting
    // the KEY SHARE foreign-key check of an application projection that already
    // holds the client. FOR UPDATE here would introduce a different lock cycle.
    let environment = sqlx::query_scalar::<_, i64>(
        "SELECT 1::BIGINT FROM aegaeon.environments WHERE id = $1 FOR NO KEY UPDATE",
    )
    .bind(stored.environment_id)
    .fetch_optional(&mut **tx)
    .await?;
    if environment.is_none() {
        return Err(DcrDatabaseError::ConcurrentModification);
    }
    let client = sqlx::query_scalar::<_, i64>(
        "SELECT 1::BIGINT FROM aegaeon.clients WHERE environment_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(stored.environment_id)
    .bind(stored.database_client_id)
    .fetch_optional(&mut **tx)
    .await?;
    if client.is_none() {
        return Err(DcrDatabaseError::ConcurrentModification);
    }
    // Recheck the complete authorization predicate after both potential waits.
    let locked = sqlx::query_scalar::<_, i64>(
        r"
SELECT 1::BIGINT
FROM aegaeon.dynamic_client_registrations dcr
JOIN aegaeon.clients c
  ON c.environment_id = dcr.environment_id
 AND c.id = dcr.client_id
JOIN aegaeon.environments e
  ON e.id = c.environment_id
JOIN aegaeon.active_runtime_environments rt
  ON rt.environment_id = e.id
WHERE dcr.environment_id = $1
  AND dcr.client_id = $2
  AND dcr.registration_access_token_hash = $3
  AND dcr.registration_access_token_hash_algorithm = 'sha256'
  AND c.status = 'ACTIVE'
  AND c.configuration_version_id = $4
  AND c.configuration_version_id = rt.configuration_version_id
  AND c.configuration_version_id = e.active_configuration_version_id
  AND rt.issuer_host = $5
  AND rt.team_id = $6
  AND rt.tenant_id = $7
FOR UPDATE OF dcr
        ",
    )
    .bind(stored.environment_id)
    .bind(stored.database_client_id)
    .bind(&stored.registration_access_token_hash)
    .bind(stored.configuration_version_id)
    .bind(&stored.issuer_host)
    .bind(stored.team_id)
    .bind(stored.tenant_id)
    .fetch_optional(&mut **tx)
    .await?;

    match locked {
        Some(_) => Ok(()),
        None => Err(DcrDatabaseError::ConcurrentModification),
    }
}
