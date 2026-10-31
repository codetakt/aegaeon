//! Inactive destination preparation. A receipt is never an activation capability.
//! Dependencies are observed before the write transaction and must be reconciled
//! again under the independent cutover fence before any serving admission.
use super::{Input, PreparationError, Result, SourceInspection};
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection, Postgres, Row, Transaction};
use std::io::BufRead;
use uuid::Uuid;

const SECTIONS: &[&str] = &[
    "targets",
    "roles",
    "client_bindings",
    "operators",
    "organizations",
    "memberships",
    "invitations",
    "challenges",
    "identity_requests",
    "administrative_grants",
    "audit",
    "receipts",
    "outbox",
];

/// The caller owns a bounded maintenance process, explicit private input and
/// finite connection settings, as for inspection. Only a new destination scope
/// is supported. Existing identity/dependency rows are compared, never replaced.
/// A lost commit acknowledgement is reconciled by the same operation and digest.
pub async fn inactive<R: BufRead>(
    mut connection: PgConnection,
    input: Input<R>,
    runtime: &str,
    operation: Uuid,
) -> Result<Value> {
    let result = owned(&mut connection, input, runtime, operation).await;
    connection
        .close()
        .await
        .map_err(PreparationError::Storage)?;
    result
}

async fn owned<R: BufRead>(
    connection: &mut PgConnection,
    input: Input<R>,
    runtime: &str,
    operation: Uuid,
) -> Result<Value> {
    if operation.is_nil() {
        return Err(PreparationError::Invalid("nil import operation"));
    }
    super::boundary(connection).await?;
    super::create_staging(connection).await?;
    let mut tx = connection
        .begin()
        .await
        .map_err(PreparationError::Storage)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(PreparationError::Storage)?;
    let mut inspection = super::inspect_rows(&mut tx, input).await?;
    validate_catalog(&mut tx, &inspection, runtime).await?;
    let scope = inspection.integrity.scope;
    let previous: Option<Value> =
        sqlx::query_scalar("SELECT aegaeon.organization_import_operation_v1($1,$2,$3,$4)")
            .bind(operation)
            .bind(scope.environment_id)
            .bind(scope.domain_id)
            .bind(&inspection.integrity.sha256)
            .fetch_one(&mut *tx)
            .await
            .map_err(PreparationError::Storage)?;
    if let Some(previous) = previous {
        tx.rollback().await.map_err(PreparationError::Storage)?;
        return Ok(previous);
    }
    inspection.target =
        Some(super::target::inspect(&mut tx, &inspection.integrity, runtime).await?);
    // Only private temporary rows survive this read-only transaction. This is
    // not a source-writer fence or a claim that references remain current.
    tx.commit().await.map_err(PreparationError::Storage)?;
    let mut tx = connection
        .begin()
        .await
        .map_err(PreparationError::Storage)?;
    let result = write(&mut tx, &inspection, operation).await;
    match result {
        Ok(receipt) => {
            tx.commit().await.map_err(PreparationError::Storage)?;
            Ok(receipt)
        }
        Err(error) => {
            tx.rollback().await.map_err(PreparationError::Storage)?;
            Err(error)
        }
    }
}

async fn validate_catalog(
    tx: &mut Transaction<'_, Postgres>,
    inspection: &SourceInspection,
    runtime: &str,
) -> Result<()> {
    use crate::subject_ownership::history::preflight;
    let environment = inspection.integrity.scope.environment_id;
    let namespace = super::target::lookup(tx, environment, runtime, "namespace", &[]).await?;
    let schema = namespace
        .get(&environment.to_string())
        .and_then(|n| n["schema_sha256"].as_str())
        .ok_or(PreparationError::Invalid("target namespace missing"))?;
    let catalog = super::target::lookup(tx, environment, runtime, "catalog", &[]).await?;
    let rows: Vec<_> = catalog.into_iter().collect();
    preflight::verify_compiled_catalog(&rows, schema, runtime)
        .map_err(|_| PreparationError::Invalid("target compiled catalog mismatch"))
}

async fn write(
    tx: &mut Transaction<'_, Postgres>,
    inspection: &SourceInspection,
    operation: Uuid,
) -> Result<Value> {
    let scope = inspection.integrity.scope;
    let domain: Value = sqlx::query_scalar(
        "SELECT data FROM pg_temp.organization_import_rows WHERE section='domain'",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(PreparationError::Storage)?;
    let receipt = json!({"version":1,"operationId":operation,"state":"prepared",
        "activationAuthorized":false,"cutoverDependenciesChecked":false,
        "inspection":inspection});
    sqlx::query("SELECT aegaeon.organization_import_begin_v1($1,$2,$3,$4,$5,$6)")
        .bind(operation)
        .bind(scope.environment_id)
        .bind(scope.domain_id)
        .bind(&inspection.integrity.sha256)
        .bind(domain)
        .bind(&receipt)
        .execute(&mut **tx)
        .await
        .map_err(PreparationError::Storage)?;
    for section in SECTIONS {
        copy_section(tx, operation, section).await?;
    }
    sqlx::query_scalar("SELECT aegaeon.organization_import_finish_v1($1)")
        .bind(operation)
        .fetch_one(&mut **tx)
        .await
        .map_err(PreparationError::Storage)
}

async fn copy_section(
    tx: &mut Transaction<'_, Postgres>,
    operation: Uuid,
    section: &str,
) -> Result<()> {
    let mut after: Option<String> = None;
    loop {
        let rows = sqlx::query("SELECT row_key,data FROM pg_temp.organization_import_rows WHERE section=$1 AND ($2::text IS NULL OR row_key>$2 COLLATE \"C\") ORDER BY row_key LIMIT 10")
            .bind(section).bind(&after).fetch_all(&mut **tx).await.map_err(PreparationError::Storage)?;
        if rows.is_empty() {
            return Ok(());
        }
        for row in rows {
            let key: String = row.try_get("row_key").map_err(PreparationError::Storage)?;
            let data: Value = row.try_get("data").map_err(PreparationError::Storage)?;
            sqlx::query("SELECT aegaeon.organization_import_row_v1($1,$2,$3)")
                .bind(operation)
                .bind(section)
                .bind(data)
                .execute(&mut **tx)
                .await
                .map_err(PreparationError::Storage)?;
            after = Some(key);
        }
    }
}
