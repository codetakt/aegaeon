//! Fixed native history inspection. No import, maintenance release or activation.
use super::{hex, initial_digest, Progress, BATCH_ENTRIES};
use crate::organizations::{
    store_observation::{self, transport},
    witness::{
        deployment::{DeploymentControl, DeploymentId},
        Role, Scope,
    },
};
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection};
use std::path::Path;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) struct Fence {
    pub scope: Scope,
    pub operation: Uuid,
    pub revision: i64,
    pub parent_operation: Uuid,
    pub parent_revision: i64,
}

pub(crate) async fn inspect(ca: &Path, issuer: &str, fence: Fence) -> Result<Value> {
    ensure!(
        !fence.scope.environment_id.is_nil()
            && !fence.operation.is_nil()
            && !fence.parent_operation.is_nil()
            && fence.revision > 0
            && fence.parent_revision > 0,
        "exact history fences required"
    );
    let deployment = DeploymentId::new(fence.scope.deployment_id)?;
    let control_url = std::env::var("AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL")?;
    let primary_url = std::env::var("AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL")?;
    let mut control = DeploymentControl::connect(&control_url, ca, Role::Maintenance).await?;
    let before = control.current(deployment).await?;
    ensure!(
        before.phase == "fenced"
            && before.pending == 0
            && before.operation_id == fence.parent_operation
            && before.revision == fence.parent_revision,
        "parent history fence differs"
    );
    let options = transport::postgres_options(&primary_url, ca, transport::certificate(ca)?)?
        .application_name("aegaeon-organization-history-inspect");
    let mut primary = PgConnection::connect_with(&options).await?;
    let namespace = crate::web::namespace_runtime::validate_connection_inputs(
        &mut primary,
        fence.scope.environment_id,
        issuer,
    )
    .await?;
    let primary_observed = store_observation::primary(&mut primary).await?;
    let witness = control.environment_maintenance()?;
    let control_observed = store_observation::primary(
        witness
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("control connection unavailable"))?,
    )
    .await?;
    ensure!(
        primary_observed.different_cluster(&control_observed),
        "independent stores required"
    );
    let maintenance_before = maintenance(witness, deployment).await?;
    let history = scan(witness, fence).await?;
    ensure!(
        maintenance(witness, deployment).await? == maintenance_before,
        "maintenance ownership changed during inspection"
    );
    let host: String =
        sqlx::query_scalar("SELECT issuer_host FROM aegaeon.environments WHERE id=$1")
            .bind(fence.scope.environment_id)
            .fetch_one(&mut primary)
            .await?;
    ensure!(
        history.issuer_host == host,
        "independent history issuer differs"
    );
    let after = control.current(deployment).await?;
    ensure!(
        serde_json::to_value(&before)? == serde_json::to_value(&after)?,
        "parent fence changed"
    );
    primary.close().await?;
    control.close().await?;
    Ok(
        json!({"environmentId":fence.scope.environment_id,"namespaceReceiptId":namespace,
        "primary":primary_observed,"control":control_observed,"history":history,
        "parentFence":after,"primaryClosed":true,"controlClosed":true,
        "activationAuthorized":false}),
    )
}

async fn maintenance(
    control: &mut super::super::Control,
    deployment: DeploymentId,
) -> Result<Value> {
    let state = control
        .value(
            sqlx::query_scalar("SELECT organization_witness.maintenance_state($1)")
                .bind(deployment.uuid()),
        )
        .await?;
    ensure!(state["pending"] == false, "pending maintenance remains");
    Ok(state)
}

async fn scan(control: &mut super::super::Control, fence: Fence) -> Result<Progress> {
    let first = control
        .history_read(
            fence.scope,
            fence.operation,
            fence.revision,
            0,
            BATCH_ENTRIES as u32,
        )
        .await?;
    let fixed = first.progress.clone();
    ensure!(fixed.sealed, "sealed current namespace required");
    let mut page = first;
    let mut sequence = 0;
    let mut previous = hex(&initial_digest(
        fence.scope.environment_id,
        &fixed.issuer_host,
    )?);
    let mut counts = (0u64, 0u64);
    loop {
        ensure!(page.progress == fixed, "history changed");
        for entry in &page.entries {
            ensure!(entry.previous_digest == previous, "history chain differs");
            previous.clone_from(&entry.digest);
            sequence += 1;
            if entry.kind == "owner" {
                counts.0 += 1;
            } else {
                counts.1 += 1;
            }
        }
        if page.entries.is_empty() {
            break;
        }
        page = control
            .history_read(
                fence.scope,
                fence.operation,
                fence.revision,
                sequence,
                BATCH_ENTRIES as u32,
            )
            .await?;
    }
    ensure!(
        sequence == fixed.sequence
            && previous == fixed.digest
            && counts == (u64::from(fixed.owner_count), u64::from(fixed.subject_count)),
        "history head differs"
    );
    Ok(fixed)
}
