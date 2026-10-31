//! Point-in-time current history comparison under an exact drained witness fence.
//! This inspection cannot clear admissions, repair records or activate a store.
use super::{Input, PreparationError, Result, SourceInspection};
use crate::organizations::witness::{history::Progress, Control, Scope};
use serde::Serialize;
use sqlx::{Connection, PgConnection, Postgres, Transaction};
use std::io::BufRead;
use uuid::Uuid;

/// Independently selected recovery operation; source files cannot select it.
#[derive(Clone, Copy)]
pub struct Fence {
    pub scope: Scope,
    pub operation_id: Uuid,
    pub revision: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inspection {
    deployment_id: Uuid,
    operation_id: Uuid,
    revision: i64,
    history: Progress,
    source_owners: i64,
    source_subjects: i64,
    relevant_owner_history_checked: bool,
    activation_authorized: bool,
}

/// Both links are exclusively owned and closed on either outcome. The caller
/// supplies private retained input and a bounded process, as for target inspection.
/// This is an observation at a fence, not a transferable authorization receipt.
pub async fn inspect<R: BufRead>(
    mut connection: PgConnection,
    mut control: Control,
    input: Input<R>,
    runtime_role: &str,
    fence: Fence,
) -> Result<SourceInspection> {
    let result = owned(&mut connection, &mut control, input, runtime_role, fence).await;
    let primary_close = connection.close().await;
    let control_close = control.close().await;
    primary_close.map_err(PreparationError::Storage)?;
    control_close.map_err(|_| invalid("recovery history connection cleanup"))?;
    result
}

async fn owned<R: BufRead>(
    connection: &mut PgConnection,
    control: &mut Control,
    input: Input<R>,
    runtime_role: &str,
    fence: Fence,
) -> Result<SourceInspection> {
    require(
        !fence.scope.environment_id.is_nil()
            && !fence.scope.deployment_id.is_nil()
            && !fence.operation_id.is_nil()
            && fence.revision > 0,
        "recovery fence identity",
    )?;
    super::boundary(connection).await?;
    super::create_staging(connection).await?;
    sqlx::raw_sql("CREATE TEMPORARY TABLE organization_recovery_owners (owner_id uuid PRIMARY KEY); CREATE TEMPORARY TABLE organization_recovery_subjects (subject text COLLATE \"C\" PRIMARY KEY, owner_id uuid NOT NULL REFERENCES organization_recovery_owners(owner_id)); CREATE INDEX ON organization_recovery_subjects(owner_id)")
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
        let mut inspection = super::inspect_rows(&mut tx, input).await?;
        require(
            inspection.integrity.scope.environment_id == fence.scope.environment_id,
            "recovery history Environment differs",
        )?;
        inspection.target =
            Some(super::target::inspect(&mut tx, &inspection.integrity, runtime_role).await?);
        inspection.recovery = Some(compare(&mut tx, control, fence).await?);
        Ok(inspection)
    }
    .await;
    tx.rollback().await.map_err(PreparationError::Storage)?;
    result
}

async fn read(
    control: &mut Control,
    fence: Fence,
    after: u64,
) -> Result<crate::organizations::witness::history::Page> {
    control
        .history_read(
            fence.scope,
            fence.operation_id,
            fence.revision,
            after,
            crate::organizations::witness::history::BATCH_ENTRIES as u32,
        )
        .await
        .map_err(|_| invalid("current independent history unavailable"))
}

async fn compare(
    tx: &mut Transaction<'_, Postgres>,
    control: &mut Control,
    fence: Fence,
) -> Result<Inspection> {
    let mut page = read(control, fence, 0).await?;
    let fixed = page.progress.clone();
    let issuer: String = sqlx::query_scalar("SELECT data->>'issuer_host' FROM pg_temp.organization_import_rows WHERE section='namespace'")
        .fetch_one(&mut **tx).await.map_err(PreparationError::Storage)?;
    require(
        page.progress.sealed && page.progress.issuer_host == issuer,
        "recovery history namespace differs or is incomplete",
    )?;
    let mut sequence = 0;
    let mut previous: Option<String> = None;
    let mut owners = 0;
    let mut subjects = 0;
    loop {
        require(
            page.progress == fixed,
            "recovery history changed during inspection",
        )?;
        for entry in &page.entries {
            require(
                previous
                    .as_ref()
                    .is_none_or(|hash| *hash == entry.previous_digest),
                "recovery history page link differs",
            )?;
            match entry.kind.as_str() {
                "owner" => {
                    sqlx::query(
                        "INSERT INTO pg_temp.organization_recovery_owners(owner_id) VALUES($1)",
                    )
                    .bind(entry.owner_id)
                    .execute(&mut **tx)
                    .await
                    .map_err(PreparationError::Storage)?;
                    owners += 1;
                }
                "reservation" => {
                    sqlx::query("INSERT INTO pg_temp.organization_recovery_subjects(subject,owner_id) VALUES($1,$2)")
                        .bind(&entry.subject).bind(entry.owner_id).execute(&mut **tx).await.map_err(PreparationError::Storage)?;
                    subjects += 1;
                }
                _ => return Err(invalid("recovery history kind")),
            }
            sequence = entry.sequence;
            previous = Some(entry.digest.clone());
        }
        if sequence == fixed.sequence {
            break;
        }
        page = read(control, fence, sequence).await?;
    }
    require(
        owners == fixed.owner_count && subjects == fixed.subject_count,
        "recovery history counts differ",
    )?;
    let invalid_owner: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows s WHERE s.section='owners' AND NOT EXISTS(SELECT FROM pg_temp.organization_recovery_owners h WHERE h.owner_id=(s.data->>'owner_id')::uuid))")
        .fetch_one(&mut **tx).await.map_err(PreparationError::Storage)?;
    require(
        !invalid_owner,
        "source owner absent from current independent history",
    )?;
    let invalid_subject: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_temp.organization_import_rows s WHERE s.section='subject_history' AND NOT EXISTS(SELECT FROM pg_temp.organization_recovery_subjects h WHERE h.subject=s.data->>'subject' COLLATE \"C\" AND h.owner_id=(s.data->>'owner_id')::uuid))")
        .fetch_one(&mut **tx).await.map_err(PreparationError::Storage)?;
    require(
        !invalid_subject,
        "source subject differs from current independent history",
    )?;
    let missing: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_temp.organization_recovery_subjects h JOIN pg_temp.organization_import_rows o ON o.section='owners' AND (o.data->>'owner_id')::uuid=h.owner_id WHERE NOT EXISTS(SELECT FROM pg_temp.organization_import_rows s WHERE s.section='subject_history' AND s.data->>'subject'=h.subject COLLATE \"C\" AND (s.data->>'owner_id')::uuid=h.owner_id))")
        .fetch_one(&mut **tx).await.map_err(PreparationError::Storage)?;
    require(!missing, "source omits current retained subject history")?;
    let (source_owners, source_subjects): (i64, i64) = sqlx::query_as("SELECT count(*) FILTER(WHERE section='owners'),count(*) FILTER(WHERE section='subject_history') FROM pg_temp.organization_import_rows")
        .fetch_one(&mut **tx).await.map_err(PreparationError::Storage)?;
    let final_page = read(control, fence, sequence).await?;
    require(
        final_page.entries.is_empty() && final_page.progress == fixed,
        "recovery fence or history changed after comparison",
    )?;
    Ok(Inspection {
        deployment_id: fence.scope.deployment_id,
        operation_id: fence.operation_id,
        revision: fence.revision,
        history: fixed,
        source_owners,
        source_subjects,
        relevant_owner_history_checked: true,
        activation_authorized: false,
    })
}
fn invalid(reason: &'static str) -> PreparationError {
    PreparationError::Invalid(reason)
}
fn require(valid: bool, reason: &'static str) -> Result<()> {
    if valid {
        Ok(())
    } else {
        Err(invalid(reason))
    }
}
