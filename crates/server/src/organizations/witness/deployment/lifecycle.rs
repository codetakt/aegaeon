use super::*;

impl DeploymentControl {
    pub async fn initialize(&mut self, deployment: DeploymentId, operation: Uuid) -> Result<State> {
        self.control.maintenance()?;
        State::decode(
            self.control
                .value(
                    sqlx::query_scalar("SELECT organization_witness.deployment_initialize($1,$2)")
                        .bind(deployment.0)
                        .bind(operation),
                )
                .await?,
            deployment,
        )
    }

    pub async fn fence(
        &mut self,
        deployment: DeploymentId,
        operation: Uuid,
        revision: i64,
    ) -> Result<State> {
        self.control.maintenance()?;
        State::decode(
            self.control
                .value(
                    sqlx::query_scalar("SELECT organization_witness.deployment_fence($1,$2,$3)")
                        .bind(deployment.0)
                        .bind(operation)
                        .bind(revision),
                )
                .await?,
            deployment,
        )
    }

    pub async fn prepare(
        &mut self,
        deployment: DeploymentId,
        operation: Uuid,
        revision: i64,
        selection: &Selection,
    ) -> Result<State> {
        self.control.maintenance()?;
        State::decode(self.control.value(
            sqlx::query_scalar("SELECT organization_witness.deployment_prepare($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                .bind(deployment.0).bind(operation).bind(revision).bind(selection.epoch)
                .bind(selection.primary).bind(selection.token_store).bind(&selection.source_sha256)
                .bind(&selection.history_sha256).bind(&selection.acceptance_sha256),
        ).await?, deployment)
    }

    pub async fn activate(
        &mut self,
        deployment: DeploymentId,
        operation: Uuid,
        revision: i64,
        acceptance: &str,
    ) -> Result<State> {
        self.control.maintenance()?;
        State::decode(
            self.control
                .value(
                    sqlx::query_scalar(
                        "SELECT organization_witness.deployment_activate($1,$2,$3,$4)",
                    )
                    .bind(deployment.0)
                    .bind(operation)
                    .bind(revision)
                    .bind(acceptance),
                )
                .await?,
            deployment,
        )
    }

    pub async fn bind_child(
        &mut self,
        deployment: DeploymentId,
        epoch: Uuid,
        environment: Uuid,
        child_epoch: Uuid,
    ) -> Result<()> {
        self.control.maintenance()?;
        let result = self
            .control
            .value(
                sqlx::query_scalar(
                    "SELECT to_jsonb(organization_witness.deployment_bind_child($1,$2,$3,$4))",
                )
                .bind(deployment.0)
                .bind(epoch)
                .bind(environment)
                .bind(child_epoch),
            )
            .await?;
        if result != serde_json::Value::String(String::new()) {
            return Err(Error::Refused);
        }
        Ok(())
    }
}
