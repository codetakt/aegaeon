//! Read-only startup diagnosis, never serving authority or an admission.
use super::super::store_progress::{values, ObservedStores};
use super::*;
use crate::organizations::store_observation::{Postgres, Redis};
use serde_json::Value;

// Private deserialization from the catalog-verified runtime control connection.
// No constructor, serialization, Clone, admission conversion or completion API.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StartupPreflight {
    version: u32,
    deployment_id: Uuid,
    environment_id: Uuid,
    parent: Checkpoint,
    child: Checkpoint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    selection: Selection,
    primary_incarnation: Value,
    token_incarnation: Value,
    minimum_wal: u64,
}

impl DeploymentControl {
    pub(super) async fn startup_preflight(
        &mut self,
        deployment: DeploymentId,
        parent: &Selection,
        environment: Uuid,
        child: &Selection,
    ) -> Result<StartupPreflight> {
        if self.control.role != Role::Runtime
            || environment.is_nil()
            || !dispatch::valid_selection(parent)
            || !dispatch::valid_selection(child)
            || (parent.primary, parent.token_store) != (child.primary, child.token_store)
        {
            return Err(Error::Refused);
        }
        let snapshot: StartupPreflight = serde_json::from_value(
            self.control
                .value(
                    sqlx::query_scalar(
                        "SELECT organization_witness.startup_preflight($1,$2,$3,$4)",
                    )
                    .bind(deployment.0)
                    .bind(environment)
                    .bind(serde_json::to_value(parent)?)
                    .bind(serde_json::to_value(child)?),
                )
                .await?,
        )?;
        if snapshot.version != 1
            || snapshot.deployment_id != deployment.0
            || snapshot.environment_id != environment
            || snapshot.parent.selection != *parent
            || snapshot.child.selection != *child
        {
            return Err(Error::Refused);
        }
        Ok(snapshot)
    }
}

impl StartupPreflight {
    /// Dedicated diagnostic observers remain owned through cleanup. This snapshot
    /// cannot replace real acquisition, fresh observation or namespace validation.
    pub(super) async fn check(self, primary: &mut Postgres, token: &mut Redis) -> Result<()> {
        let (primary, token) = values(primary, token).await?;
        self.parent.check(primary.clone(), &token)?;
        self.child.check(primary, &token)?;
        Ok(())
    }
}

impl Checkpoint {
    fn check(&self, primary: Value, token: &Value) -> Result<()> {
        ObservedStores::check_values(
            &self.primary_incarnation,
            &self.token_incarnation,
            self.minimum_wal,
            primary,
            token,
        )?;
        Ok(())
    }
}
