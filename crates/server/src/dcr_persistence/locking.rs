use sqlx::{Postgres, Transaction};

use super::{DcrDatabaseError, DcrStoredClient};

pub(super) async fn lock_current_dynamic_registration(
    tx: &mut Transaction<'_, Postgres>,
    stored: &DcrStoredClient,
) -> Result<(), DcrDatabaseError> {
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
FOR UPDATE OF dcr, c, e
        ",
    )
    .bind(stored.environment_id)
    .bind(stored.database_client_id)
    .bind(&stored.registration_access_token_hash)
    .bind(stored.configuration_version_id)
    .fetch_optional(&mut **tx)
    .await?;

    match locked {
        Some(_) => Ok(()),
        None => Err(DcrDatabaseError::ConcurrentModification),
    }
}
