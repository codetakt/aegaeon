use super::super::deployment::DeploymentId;
use super::*;
use crate::organizations::store_observation::{self, Postgres, Redis};

/// All connections are consumed, including on failure or uncertain COMMIT.
/// SQL errors never commit the preceding parent/child prefix.
pub(crate) async fn prepare(
    mut control: DeploymentControl,
    mut primary: Postgres,
    mut token: Redis,
    plan: &Plan,
    digest: &str,
) -> Result<Value> {
    let result = async {
        plan.validate()?;
        command(&mut control, "BEGIN").await?;
        let result = inside(&mut control, &mut primary, &mut token, plan, digest).await;
        if result.is_ok() {
            command(&mut control, "COMMIT").await?;
        } else {
            // Failure to acknowledge rollback is not successful completion.
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

pub(super) async fn command(control: &mut DeploymentControl, sql: &str) -> Result<()> {
    let connection = control
        .environment_maintenance()?
        .connection
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("control connection unavailable"))?;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        sqlx::raw_sql(sql).execute(connection),
    )
    .await??;
    Ok(())
}

async fn inside(
    control: &mut DeploymentControl,
    primary: &mut Postgres,
    token: &mut Redis,
    plan: &Plan,
    digest: &str,
) -> Result<Value> {
    let before = inventory(control, plan, digest).await?;
    let prepared = before["parent"]["phase"] == "prepared";
    complete(
        &before,
        plan,
        if prepared {
            Stage::Prepared
        } else {
            Stage::Fenced
        },
    )?;
    let control_observed = store_observation::primary(
        control
            .environment_maintenance()?
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("control connection unavailable"))?,
    )
    .await?;
    ensure!(
        primary.observation().different_cluster(&control_observed),
        "independent SQL clusters required"
    );
    follows(
        &serde_json::to_value(&control_observed)?,
        &plan.stores.control,
    )?;
    follows(
        &serde_json::to_value(primary.observation())?,
        &plan.stores.primary,
    )?;
    ensure!(
        serde_json::to_value(token.observation())? == plan.stores.token,
        "actual token identity differs"
    );
    let deployment = DeploymentId::new(plan.deployment_id)?;
    control
        .prepare(
            deployment,
            plan.parent.operation_id,
            plan.parent.revision,
            &plan.parent.selection,
        )
        .await?;
    let parent_progress = control
        .pin_store_progress(
            deployment,
            plan.parent.operation_id,
            plan.parent.revision + 1,
            primary,
            token,
        )
        .await?;
    let mut children = Vec::with_capacity(plan.children.len());
    for child in &plan.children {
        let witness = control.environment_maintenance()?;
        let transition = &child.transition;
        let state = witness
            .prepare(
                plan.scope(child),
                transition.operation_id,
                transition.revision,
                &transition.selection,
            )
            .await?;
        let progress = witness
            .pin_store_progress(
                plan.scope(child),
                transition.operation_id,
                transition.revision + 1,
                primary,
                token,
            )
            .await?;
        children.push(json!({"state":state,"progress":progress}));
    }
    let after = inventory(control, plan, digest).await?;
    complete(&after, plan, Stage::Prepared)?;
    Ok(json!({"version":1,"intentSha256":digest,"selection":after,
        "parentProgress":parent_progress,"children":children,
        "activationAuthorized":false,"supplierQualified":false}))
}
