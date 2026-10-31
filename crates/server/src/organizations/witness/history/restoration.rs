//! Append-only preparation from the live independent journal. No identity,
//! credential, serving selection or pending admission is created or released.
use super::{hex, initial_digest, Progress, BATCH_ENTRIES};
use crate::organizations::{snapshot::staging, witness::Control};
use crate::subject_ownership::history::preflight;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection};
use std::time::Duration;
use uuid::Uuid;

pub struct Request<'a> {
    pub fence: staging::recovery::Fence,
    pub operation_id: Uuid,
    pub runtime_role: &'a str,
    pub expected: &'a Progress,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preparation {
    operation_id: Uuid,
    history_sequence: u64,
    history_sha256: String,
    pages: u64,
    independent_facts_present: bool,
    activation_authorized: bool,
}

/// Consumes the direct primary connection, closing it on success and error.
/// The caller retains the live control link and private journal through cleanup.
/// A process deadline must bound the complete maintenance invocation as well.
pub async fn prepare(
    mut primary: PgConnection,
    control: &mut Control,
    request: Request<'_>,
) -> anyhow::Result<Preparation> {
    let result = owned(&mut primary, control, request).await;
    let close = tokio::time::timeout(Duration::from_secs(5), primary.close()).await;
    close??;
    result
}
async fn owned(
    primary: &mut PgConnection,
    control: &mut Control,
    request: Request<'_>,
) -> anyhow::Result<Preparation> {
    anyhow::ensure!(
        !request.operation_id.is_nil() && request.expected.sealed,
        "sealed history and restoration operation required"
    );
    check_target(primary, &request).await?;
    let scope = request.fence.scope;
    let mut after = 0;
    let mut previous = hex(&initial_digest(
        scope.environment_id,
        &request.expected.issuer_host,
    )?);
    let mut pages = 0;
    loop {
        let page = control
            .history_read(
                scope,
                request.fence.operation_id,
                request.fence.revision,
                after,
                BATCH_ENTRIES as u32,
            )
            .await?;
        anyhow::ensure!(
            page.progress == *request.expected,
            "current restoration history changed"
        );
        if page.entries.is_empty() {
            anyhow::ensure!(
                after == request.expected.sequence && previous == request.expected.digest,
                "restoration history head mismatch"
            );
            break;
        }
        let end = aegaeon_pure::organization_history::batch_end(after, page.entries.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("restoration page bound"))?;
        let mut digest = previous.clone();
        for entry in &page.entries {
            anyhow::ensure!(
                entry.previous_digest == digest,
                "restoration page chain mismatch"
            );
            digest.clone_from(&entry.digest);
        }
        let input = json!({"operation_id":request.operation_id,"environment_id":scope.environment_id,
            "deployment_id":scope.deployment_id,"witness_operation_id":request.fence.operation_id,
            "witness_revision":request.fence.revision,"issuer_host":request.expected.issuer_host,
            "source_sequence":request.expected.sequence,"source_digest":request.expected.digest,
            "after_sequence":after,"previous_digest":previous,"entries":page.entries});
        anyhow::ensure!(
            serde_json::to_vec(&input)?.len() <= 1024 * 1024,
            "restoration page byte bound"
        );
        // The fixed function is one atomic autocommit transaction. Uncertain
        // acknowledgement never advances this client to another page or retries.
        let receipt: Value = tokio::time::timeout(
            Duration::from_secs(5),
            sqlx::query_scalar("SELECT aegaeon.restore_subject_history_page_v1($1)")
                .bind(input)
                .fetch_one(&mut *primary),
        )
        .await??;
        anyhow::ensure!(
            receipt
                == json!({"operation_id":request.operation_id,"sequence":end,"digest":digest,
            "complete":end==request.expected.sequence,"activation_authorized":false}),
            "restoration acknowledgement differs"
        );
        let current = control
            .history_read(
                scope,
                request.fence.operation_id,
                request.fence.revision,
                end,
                1,
            )
            .await?;
        anyhow::ensure!(
            current.progress == *request.expected,
            "restoration fence changed after primary commit"
        );
        after = end;
        previous = digest;
        pages += 1;
    }
    Ok(Preparation {
        operation_id: request.operation_id,
        history_sequence: after,
        history_sha256: previous,
        pages,
        independent_facts_present: true,
        activation_authorized: false,
    })
}

async fn check_target(primary: &mut PgConnection, request: &Request<'_>) -> anyhow::Result<()> {
    staging::boundary(primary).await?;
    let mut tx = primary.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let scope = request.fence.scope;
    let namespace = staging::target::lookup(
        &mut tx,
        scope.environment_id,
        request.runtime_role,
        "namespace",
        &[],
    )
    .await?;
    let namespace = namespace
        .get(&scope.environment_id.to_string())
        .ok_or_else(|| anyhow::anyhow!("adopted namespace missing"))?;
    anyhow::ensure!(
        namespace["issuer_host"].as_str() == Some(request.expected.issuer_host.as_str()),
        "restoration issuer mismatch"
    );
    let schema = namespace["schema_sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("namespace catalog identity"))?;
    let catalog = staging::target::lookup(
        &mut tx,
        scope.environment_id,
        request.runtime_role,
        "catalog",
        &[],
    )
    .await?;
    let rows: Vec<_> = catalog.into_iter().collect();
    preflight::verify_compiled_catalog(&rows, schema, request.runtime_role)?;
    tx.rollback().await?;
    Ok(())
}
