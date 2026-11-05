//! One registered activation transaction across the parent and complete children.
use super::{
    complete, follows, json, transaction::command, DeploymentControl, Plan, Result, Stage, Value,
};
use crate::organizations::{
    store_observation::{self, Postgres, Redis},
    witness::{
        deployment::{configuration::Configuration, DeploymentId},
        store_progress,
    },
};
use anyhow::ensure;
use serde::Deserialize;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    version: u8,
    pub epoch_sha256: String,
    pub manifest_sha256: String,
    publication_sha256: String,
    root_cert_sha256: String,
    configurations: Vec<Startup>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Startup {
    environment_id: Uuid,
    runtime_file: PathBuf,
    runtime_sha256: String,
    issuer_host: String,
}

impl Intent {
    pub(super) fn check(
        &self,
        plan: &Plan,
        epoch_digest: &str,
        ca: &[u8],
        primary: &str,
        token: &str,
    ) -> Result<()> {
        plan.validate()?;
        ensure!(
            self.version == 1
                && self.epoch_sha256 == epoch_digest
                && self.root_cert_sha256 == crate::subject_ownership::history::sha256_hex(ca)
                && self.configurations.len() == plan.children.len()
        );
        for digest in [&self.manifest_sha256, &self.publication_sha256] {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
        }
        for (input, child) in self.configurations.iter().zip(&plan.children) {
            ensure!(input.environment_id == child.environment_id);
            let raw = super::cli::private(&input.runtime_file, 1024 * 1024)?;
            ensure!(crate::subject_ownership::history::sha256_hex(&raw) == input.runtime_sha256);
            let config = Configuration::parse(&raw)?;
            let selectors = config.check_cutover(plan)?;
            ensure!(
                selectors
                    .iter()
                    .filter(|(id, host)| *id == input.environment_id && *host == input.issuer_host)
                    .count()
                    == 1
            );
            config.check_runtime(input.environment_id, &child.issuer, primary, token)?;
        }
        Ok(())
    }
}

pub(super) async fn activate(
    mut control: DeploymentControl,
    mut primary: Postgres,
    mut token: Redis,
    plan: &Plan,
    intent: &Intent,
    digest: &str,
) -> Result<Value> {
    let result = async {
        plan.validate()?;
        command(&mut control, "BEGIN").await?;
        let result = inside(&mut control, &mut primary, &mut token, plan, intent, digest).await;
        if result.is_ok() {
            command(&mut control, "COMMIT").await?;
        } else {
            let _ = command(&mut control, "ROLLBACK").await;
        }
        result
    }
    .await;
    let primary_closed = primary.close().await;
    token.close();
    let control_closed = control.close().await;
    let receipt = result?;
    primary_closed?;
    control_closed?;
    Ok(receipt)
}

async fn inventory(
    control: &mut DeploymentControl,
    plan: &Plan,
    intent: &Intent,
    digest: &str,
) -> Result<Value> {
    Ok(control
        .environment_maintenance()?
        .value(
            sqlx::query_scalar(
                "SELECT organization_witness.cutover_activation_selection($1,$2,$3,$4,$5)",
            )
            .bind(plan.deployment_id)
            .bind(plan.cutover_operation_id)
            .bind(&intent.epoch_sha256)
            .bind(&intent.manifest_sha256)
            .bind(digest),
        )
        .await?)
}

async fn inside(
    control: &mut DeploymentControl,
    primary: &mut Postgres,
    token: &mut Redis,
    plan: &Plan,
    intent: &Intent,
    digest: &str,
) -> Result<Value> {
    let before = inventory(control, plan, intent, digest).await?;
    let active = before["parent"]["phase"] == "active";
    complete(
        &before,
        plan,
        if active {
            Stage::Active
        } else {
            Stage::Prepared
        },
    )?;
    bindings(&before, plan, active)?;
    observe(control, primary, token, plan, intent, &before).await?;
    if !active {
        let deployment = DeploymentId::new(plan.deployment_id)?;
        control
            .activate(
                deployment,
                plan.parent.operation_id,
                plan.parent.revision + 1,
                &plan.parent.selection.acceptance_sha256,
            )
            .await?;
        for child in &plan.children {
            control
                .bind_child(
                    deployment,
                    plan.parent.selection.epoch,
                    child.environment_id,
                    child.transition.selection.epoch,
                )
                .await?;
            control
                .environment_maintenance()?
                .activate(
                    plan.scope(child),
                    child.transition.operation_id,
                    child.transition.revision + 1,
                    &child.transition.selection.acceptance_sha256,
                )
                .await?;
        }
    }
    let after = inventory(control, plan, intent, digest).await?;
    complete(&after, plan, Stage::Active)?;
    bindings(&after, plan, true)?;
    observe(control, primary, token, plan, intent, &after).await?;
    ensure!(
        before["parentCheckpoint"] == after["parentCheckpoint"]
            && before["childCheckpoints"] == after["childCheckpoints"],
        "activation changed prepared checkpoints"
    );
    Ok(
        json!({"version":1,"activationIntentSha256":digest,"epochIntentSha256":intent.epoch_sha256,
        "manifestSha256":intent.manifest_sha256,"selection":after,"workersStarted":false,"supplierQualified":false}),
    )
}

fn bindings(value: &Value, plan: &Plan, active: bool) -> Result<()> {
    let actual = value["bindings"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("activation bindings missing"))?;
    if !active {
        ensure!(actual.is_empty(), "prepared selection already associated");
        return Ok(());
    }
    ensure!(
        actual.len() == plan.children.len(),
        "complete active associations required"
    );
    for child in &plan.children {
        let expected = json!({"environment_id":child.environment_id,"child_epoch":child.transition.selection.epoch,
            "deployment_id":plan.deployment_id,"deployment_epoch":plan.parent.selection.epoch});
        let rows: Vec<_> = actual
            .iter()
            .filter(|row| {
                expected
                    .as_object()
                    .is_some_and(|fields| fields.iter().all(|(key, value)| &row[key] == value))
            })
            .collect();
        ensure!(rows.len() == 1, "active association differs");
        let row = rows[0];
        ensure!(
            row.as_object().is_some_and(|fields| fields.len() == 6)
                && row["principal"] == value["parentCheckpoint"]["principal"]
                && row["bound_at"].as_str().is_some_and(|timestamp| {
                    time::OffsetDateTime::parse(
                        timestamp,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .is_ok()
                }),
            "active association provenance differs"
        );
    }
    Ok(())
}

async fn observe(
    control: &mut DeploymentControl,
    primary: &mut Postgres,
    token: &mut Redis,
    plan: &Plan,
    intent: &Intent,
    value: &Value,
) -> Result<()> {
    ensure!(
        value["publicationSha256"] == intent.publication_sha256,
        "published receipt differs"
    );
    let observed_control = store_observation::primary(
        control
            .environment_maintenance()?
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("control unavailable"))?,
    )
    .await?;
    ensure!(primary.observation().different_cluster(&observed_control));
    follows(
        &serde_json::to_value(&observed_control)?,
        &plan.stores.control,
    )?;
    let (actual, token) = store_progress::values(primary, token).await?;
    follows(&actual, &plan.stores.primary)?;
    ensure!(token == plan.stores.token);
    let children = value["childCheckpoints"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("child checkpoints missing"))?;
    ensure!(children.len() == plan.children.len());
    checkpoint(&value["parentCheckpoint"], &plan.parent, &actual, &token)?;
    ensure!(value["parentCheckpoint"]["deployment_id"] == json!(plan.deployment_id));
    for child in &plan.children {
        let entries: Vec<_> = children
            .iter()
            .filter(|entry| entry["environment_id"] == json!(child.environment_id))
            .collect();
        ensure!(entries.len() == 1);
        checkpoint(entries[0], &child.transition, &actual, &token)?;
    }
    Ok(())
}

fn checkpoint(
    value: &Value,
    transition: &super::Transition,
    actual: &Value,
    token: &Value,
) -> Result<()> {
    ensure!(
        value["epoch"] == json!(transition.selection.epoch)
            && value["operation_id"] == json!(transition.operation_id)
            && value["prepared_revision"] == json!(transition.revision + 1)
            && value["primary_id"] == json!(transition.selection.primary)
            && value["token_store_id"] == json!(transition.selection.token_store)
            && &value["token_incarnation"] == token
    );
    let mut expected = value["primary_incarnation"]
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("checkpoint incarnation missing"))?;
    let minimum = value["wal_position"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("checkpoint WAL missing"))?;
    let initial = value["initial_wal"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("initial WAL missing"))?;
    ensure!(initial <= minimum);
    expected.insert("wal_position".into(), json!(minimum));
    follows(actual, &Value::Object(expected))
}

#[cfg(test)]
mod tests;
