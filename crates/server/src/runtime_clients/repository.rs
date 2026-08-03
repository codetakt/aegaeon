use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::runtime_configuration::RuntimeAuthorityRevision;

use super::error::RuntimeClientSnapshotError;
use super::projection::RuntimeClientProjectionUpdate;
use super::queries;
use super::row::runtime_client_entry_from_row;
use super::snapshot::RuntimeClientSnapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationSubordinateEntityIdsPage {
    pub entity_ids: Vec<String>,
    pub next_cursor: Option<String>,
}

async fn load_active_runtime_client_snapshot_for_issuer_host_guarded(
    pool: &PgPool,
    issuer_host: &str,
    expected_revision: &RuntimeAuthorityRevision,
) -> Result<RuntimeClientProjectionUpdate, RuntimeClientSnapshotError> {
    let issuer_host = normalize_issuer_host(issuer_host)?;
    let mut tx = begin_runtime_client_snapshot(pool).await?;
    let authority_revision =
        validate_runtime_authority_revision_in_tx(&mut tx, issuer_host, expected_revision).await?;
    let fingerprint_before = authority_revision
        .active_runtime_client_fingerprint()
        .to_string();

    let query = queries::active_runtime_clients_for_issuer_host();
    let rows = sqlx::query(&query)
        .bind(issuer_host)
        .fetch_all(&mut *tx)
        .await?;

    let entries = rows
        .iter()
        .map(runtime_client_entry_from_row)
        .collect::<Result<Vec<_>, _>>()
        .and_then(|entries| {
            RuntimeClientSnapshot::try_new_with_fingerprint(entries, fingerprint_before.clone())
        })?;
    tx.commit().await?;

    Ok(RuntimeClientProjectionUpdate::new(
        entries,
        authority_revision,
    ))
}

async fn begin_runtime_client_snapshot(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>, RuntimeClientSnapshotError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

pub(crate) async fn load_active_runtime_client_fingerprint_for_issuer_host_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    issuer_host: &str,
) -> Result<String, RuntimeClientSnapshotError> {
    let issuer_host = normalize_issuer_host(issuer_host)?;
    let query = queries::active_runtime_client_fingerprint_for_issuer_host();
    let row = sqlx::query(&query)
        .bind(issuer_host)
        .fetch_one(&mut **tx)
        .await?;

    row.try_get("active_runtime_client_fingerprint")
        .map_err(RuntimeClientSnapshotError::DatabaseQuery)
}

pub async fn load_federation_subordinate_entity_ids_page(
    pool: &PgPool,
    issuer_host: &str,
    cursor: Option<&str>,
    limit: usize,
) -> Result<FederationSubordinateEntityIdsPage, RuntimeClientSnapshotError> {
    let issuer_host = normalize_issuer_host(issuer_host)?;
    let fetch_limit = limit
        .checked_add(1)
        .ok_or(RuntimeClientSnapshotError::InvalidPagination("limit"))?;
    let query = queries::federation_subordinate_entity_ids_for_issuer_host_keyset_page();
    let rows = sqlx::query(&query)
        .bind(issuer_host)
        .bind(cursor)
        .bind(usize_to_i64(fetch_limit, "limit")?)
        .fetch_all(pool)
        .await?;

    let mut entity_ids = rows
        .iter()
        .map(|row| row.try_get::<String, _>("client_identifier"))
        .filter_map(|client_identifier| match client_identifier {
            Ok(client_identifier)
                if crate::federation::validate_entity_url(&client_identifier).is_ok() =>
            {
                Some(Ok(client_identifier))
            }
            Ok(_) => None,
            Err(error) => Some(Err(RuntimeClientSnapshotError::DatabaseQuery(error))),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let next_cursor = if entity_ids.len() > limit {
        entity_ids.truncate(limit);
        entity_ids.last().cloned()
    } else {
        None
    };

    Ok(FederationSubordinateEntityIdsPage {
        entity_ids,
        next_cursor,
    })
}

pub async fn load_runtime_client_projection_from_database_guarded(
    pool: &PgPool,
    issuer_host: &str,
    expected_revision: &RuntimeAuthorityRevision,
) -> Result<RuntimeClientProjectionUpdate, RuntimeClientSnapshotError> {
    load_active_runtime_client_snapshot_for_issuer_host_guarded(
        pool,
        issuer_host,
        expected_revision,
    )
    .await
}

fn normalize_issuer_host(issuer_host: &str) -> Result<&str, RuntimeClientSnapshotError> {
    let issuer_host = issuer_host.trim();
    if issuer_host.is_empty() {
        return Err(RuntimeClientSnapshotError::EmptyIssuerHost);
    }
    Ok(issuer_host)
}

fn usize_to_i64(value: usize, parameter: &'static str) -> Result<i64, RuntimeClientSnapshotError> {
    i64::try_from(value).map_err(|_| RuntimeClientSnapshotError::InvalidPagination(parameter))
}

async fn validate_runtime_authority_revision_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    issuer_host: &str,
    expected_revision: &RuntimeAuthorityRevision,
) -> Result<RuntimeAuthorityRevision, RuntimeClientSnapshotError> {
    let current_revision =
        load_runtime_authority_revision_for_issuer_host_in_tx(tx, issuer_host).await?;
    if expected_revision.stable_authority_matches(&current_revision) {
        Ok(current_revision)
    } else {
        Err(RuntimeClientSnapshotError::RuntimeRevisionMismatch(
            issuer_host.to_string(),
        ))
    }
}

async fn load_runtime_authority_revision_for_issuer_host_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    issuer_host: &str,
) -> Result<RuntimeAuthorityRevision, RuntimeClientSnapshotError> {
    let rows = sqlx::query(
        crate::runtime_authority_queries::ACTIVE_RUNTIME_AUTHORITY_REVISION_FOR_ISSUER_HOST,
    )
    .bind(issuer_host)
    .fetch_all(&mut **tx)
    .await?;

    let [row] = rows.as_slice() else {
        return if rows.is_empty() {
            Err(RuntimeClientSnapshotError::NotFound(
                issuer_host.to_string(),
            ))
        } else {
            Err(RuntimeClientSnapshotError::AmbiguousIssuerHost(
                issuer_host.to_string(),
            ))
        };
    };

    Ok(RuntimeAuthorityRevision::try_new(
        row.try_get("active_configuration_version_id")?,
        row.try_get("active_configuration_document_fingerprint")?,
        row.try_get("active_runtime_key_set_fingerprint")?,
        load_active_runtime_client_fingerprint_for_issuer_host_in_tx(tx, issuer_host).await?,
        row.try_get("active_dcr_bearer_token_fingerprint")?,
    )?)
}
