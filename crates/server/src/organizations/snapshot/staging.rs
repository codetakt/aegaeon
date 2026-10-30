//! Source-only import inspection in private transaction-local tables. Never
//! writes application tables or adopts the source's authority/dependencies.
use super::input::{Input, InputError, IntegrityReceipt, PendingRow};
use serde::Serialize;
use sqlx::{Connection, PgConnection, Postgres, Transaction};
use std::io::BufRead;

mod contracts;
mod graph;
mod owners;
mod registrations;
pub mod target;

#[derive(Debug, thiserror::Error)]
pub enum PreparationError {
    #[error(transparent)]
    Input(#[from] InputError),
    #[error("Organizations import preparation refused: {0}")]
    Invalid(&'static str),
    #[error("Organizations import row {record} ({section}) refused: {reason}")]
    Row {
        record: u64,
        section: &'static str,
        reason: &'static str,
    },
    #[error("Organizations import preparation store failed")]
    Storage(#[source] sqlx::Error),
}
type Result<T> = std::result::Result<T, PreparationError>;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceInspection {
    pub integrity: IntegrityReceipt,
    pub rows: u64,
    source_graph_checked: bool,
    target_dependencies_checked: bool,
    activation_authorized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<target::TargetInspection>,
}

/// Consumes an exclusively owned direct connection and private regular-file
/// source. The caller must bound file I/O with a separate process deadline and
/// configure finite PostgreSQL statement/idle/transaction deadlines at connect.
/// The connection is closed on success/error; cancellation drops it. Preparation
/// never uses a pool connection or leaves its temporary rows available for reuse.
pub async fn inspect_source<R: BufRead>(
    mut connection: PgConnection,
    input: Input<R>,
) -> Result<SourceInspection> {
    let result = inspect_owned(&mut connection, input, None).await;
    connection
        .close()
        .await
        .map_err(PreparationError::Storage)?;
    result
}

/// Compare retained source references through an explicitly authorized
/// maintenance connection. This never adopts source or target authority.
pub async fn inspect_target<R: BufRead>(
    mut connection: PgConnection,
    input: Input<R>,
    runtime_role: &str,
) -> Result<SourceInspection> {
    let result = inspect_owned(&mut connection, input, Some(runtime_role)).await;
    connection
        .close()
        .await
        .map_err(PreparationError::Storage)?;
    result
}

async fn inspect_owned<R: BufRead>(
    connection: &mut PgConnection,
    input: Input<R>,
    runtime_role: Option<&str>,
) -> Result<SourceInspection> {
    boundary(connection).await?;
    // PostgreSQL refuses CREATE TEMP inside READ ONLY. Create an empty private
    // table first, then put all input processing in a read-only transaction.
    sqlx::query("CREATE TEMPORARY TABLE organization_import_rows (section text COLLATE \"C\" NOT NULL, row_key text COLLATE \"C\" NOT NULL, data jsonb NOT NULL, exact_data text NOT NULL, PRIMARY KEY(section,row_key))")
        .execute(&mut *connection).await.map_err(PreparationError::Storage)?;
    sqlx::query("CREATE INDEX organization_import_source_owners ON pg_temp.organization_import_rows((data->>'owner_id')) WHERE section='subject_history'")
        .execute(&mut *connection).await.map_err(PreparationError::Storage)?;
    let mut tx = connection
        .begin()
        .await
        .map_err(PreparationError::Storage)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(PreparationError::Storage)?;
    let result = async {
        let mut inspection = inspect_rows(&mut tx, input).await?;
        if let Some(runtime_role) = runtime_role {
            inspection.target =
                Some(target::inspect(&mut tx, &inspection.integrity, runtime_role).await?);
        }
        Ok(inspection)
    }
    .await;
    tx.rollback().await.map_err(PreparationError::Storage)?;
    result
}

async fn inspect_rows<R: BufRead>(
    tx: &mut Transaction<'_, Postgres>,
    mut input: Input<R>,
) -> Result<SourceInspection> {
    let mut rows = 0u64;
    let mut page = Vec::with_capacity(10);
    while let Some(row) = input.next_row()? {
        let record = rows
            .checked_add(2)
            .ok_or(PreparationError::Invalid("source position overflow"))?;
        contracts::validate(&row).map_err(|reason| PreparationError::Row {
            record,
            section: row.section,
            reason,
        })?;
        page.push(row);
        if page.len() == 10 {
            insert_page(tx, &page).await?;
            page.clear();
        }
        rows = rows
            .checked_add(1)
            .ok_or(PreparationError::Invalid("staging count overflow"))?;
    }
    let integrity = input.finish()?;
    if !page.is_empty() {
        insert_page(tx, &page).await?;
    }
    graph::check(tx, &integrity).await?;
    Ok(SourceInspection {
        integrity,
        rows,
        source_graph_checked: true,
        target_dependencies_checked: false,
        activation_authorized: false,
        target: None,
    })
}

async fn insert_page(tx: &mut Transaction<'_, Postgres>, page: &[PendingRow]) -> Result<()> {
    let mut query = sqlx::QueryBuilder::<Postgres>::new(
        "INSERT INTO pg_temp.organization_import_rows(section,row_key,data,exact_data) ",
    );
    query.push_values(page, |mut row, value| {
        row.push_bind(value.section)
            .push_bind(&value.key)
            .push_bind(&value.data)
            .push_bind(&value.exact_data);
    });
    query
        .build()
        .execute(&mut **tx)
        .await
        .map_err(PreparationError::Storage)?;
    Ok(())
}

async fn boundary(connection: &mut PgConnection) -> Result<()> {
    let valid: bool = sqlx::query_scalar("SELECT NOT pg_is_in_recovery() AND current_setting('statement_timeout')::interval>interval '0' AND current_setting('statement_timeout')::interval<=interval '5 seconds' AND current_setting('lock_timeout')::interval>interval '0' AND current_setting('lock_timeout')::interval<=interval '1 second' AND current_setting('idle_in_transaction_session_timeout')::interval>interval '0' AND current_setting('idle_in_transaction_session_timeout')::interval<=interval '30 seconds' AND current_setting('transaction_timeout')::interval>interval '0' AND current_setting('transaction_timeout')::interval<=interval '1 hour'")
        .fetch_one(connection).await.map_err(PreparationError::Storage)?;
    if !valid {
        return Err(PreparationError::Invalid(
            "read-only primary or finite transaction boundary",
        ));
    }
    Ok(())
}
