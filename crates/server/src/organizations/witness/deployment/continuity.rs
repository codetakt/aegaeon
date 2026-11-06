//! Post-work durable seals and drained restart acceptance.
//! The control transaction owns ordering; a data-store seal is not authority.
use super::super::store_progress::{values, ObservedStores};
use super::*;
use crate::organizations::store_observation::{Postgres, Redis};
use serde_json::Value;
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    deployment_id: Uuid,
    selection: Selection,
    seal: Uuid,
    restart_generation: u32,
    primary_incarnation: Value,
    token_incarnation: Value,
    minimum_wal: u64,
}

impl Snapshot {
    fn decode(value: Value, deployment: DeploymentId, selection: &Selection) -> Result<Self> {
        let snapshot: Self = serde_json::from_value(value)?;
        if snapshot.deployment_id != deployment.0
            || snapshot.selection != *selection
            || snapshot.seal.is_nil()
            || snapshot.restart_generation > 65_536
        {
            return Err(Error::Refused);
        }
        Ok(snapshot)
    }

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

impl DeploymentControl {
    /// Runtime-owned transactions only. Any lost response discards this control
    /// connection; dropping it cannot release an earlier durable admission.
    pub(super) async fn continuity_command(&mut self, command: &'static str) -> Result<()> {
        if self.control.role != Role::Runtime {
            return Err(Error::Refused);
        }
        let connection = self.control.connection.as_mut().ok_or(Error::Refused)?;
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            sqlx::query(command).execute(connection),
        )
        .await;
        match result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => {
                self.control.connection.take();
                Err(Error::Storage(error))
            }
            Err(_) => {
                self.control.connection.take();
                Err(Error::Deadline)
            }
        }
    }

    /// Called only during the separately qualified, drained preparation. It may
    /// be nested in the cutover transaction and never commits that transaction.
    pub(super) async fn pin_continuity(
        &mut self,
        deployment: DeploymentId,
        operation: Uuid,
        revision: i64,
        primary: &mut Postgres,
        token: &mut Redis,
    ) -> Result<()> {
        self.control.maintenance()?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PreparedSeal {
            epoch: Uuid,
            seal: Option<Uuid>,
        }
        let prepared: PreparedSeal = serde_json::from_value(
            self.control
                .value(
                    sqlx::query_scalar(
                        "SELECT organization_witness.deployment_store_seal_preparation($1,$2,$3)",
                    )
                    .bind(deployment.0)
                    .bind(operation)
                    .bind(revision),
                )
                .await?,
        )?;
        if prepared.epoch.is_nil() || prepared.seal.is_some_and(|seal| seal.is_nil()) {
            return Err(Error::Refused);
        }
        let seal = if let Some(seal) = prepared.seal {
            compare_seals(primary, token, deployment, seal).await?;
            seal
        } else {
            let seal = Uuid::new_v4();
            let prior_primary = primary
                .continuity_read(deployment.0)
                .await
                .map_err(|_| Error::StoreContinuityMismatch)?;
            let prior_token = token
                .continuity_read(deployment.0)
                .await
                .map_err(|_| Error::StoreContinuityMismatch)?;
            primary
                .continuity_replace(deployment.0, prior_primary, seal)
                .await
                .map_err(|_| Error::StoreContinuityMismatch)?;
            token
                .continuity_replace(deployment.0, prior_token, seal)
                .await
                .map_err(|_| Error::StoreContinuityMismatch)?;
            compare_seals(primary, token, deployment, seal).await?;
            seal
        };
        let pinned: PreparedSeal = serde_json::from_value(
            self.control
                .value(
                    sqlx::query_scalar(
                        "SELECT organization_witness.deployment_store_seal_pin($1,$2,$3,$4)",
                    )
                    .bind(deployment.0)
                    .bind(operation)
                    .bind(revision)
                    .bind(seal),
                )
                .await?,
        )?;
        if pinned.epoch != prepared.epoch || pinned.seal != Some(seal) {
            return Err(Error::Refused);
        }
        Ok(())
    }

    /// Read-only on an unchanged incarnation. A changed incarnation requires
    /// drained ownership and exact durable seals under the independent lock.
    /// It never rewrites seals, clears pending work or changes authority epochs.
    pub(super) async fn ensure_store_continuity(
        &mut self,
        deployment: DeploymentId,
        selection: &Selection,
        primary: &mut Postgres,
        token: &mut Redis,
        attempt: &mut aegaeon_pure::organization_recovery::Preflight,
    ) -> Result<()> {
        if self.control.role != Role::Runtime {
            return Err(Error::Refused);
        }
        let selected = serde_json::to_value(selection)?;
        let snapshot = Snapshot::decode(
            self.control
                .value(
                    sqlx::query_scalar(
                        "SELECT organization_witness.deployment_store_continuity($1,$2)",
                    )
                    .bind(deployment.0)
                    .bind(&selected),
                )
                .await?,
            deployment,
            selection,
        )?;
        let (observed_primary, observed_token) = values(primary, token).await?;
        match snapshot.check(observed_primary.clone(), &observed_token) {
            Ok(()) => return Ok(()),
            Err(Error::PrimaryIncarnationChanged | Error::TokenIncarnationChanged) => {}
            Err(error) => return Err(error),
        }
        // Arm before the first await on a potentially mutating path. Cancellation
        // or an uncertain restart COMMIT must retain the existing fence.
        if !attempt.begin_mutation() {
            return Err(Error::Refused);
        }
        self.continuity_command("BEGIN").await?;
        let result = self
            .restart_continuity(deployment, selection, primary, token)
            .await;
        self.finish_restart_transaction(result, attempt).await
    }

    async fn finish_restart_transaction(
        &mut self,
        result: Result<()>,
        attempt: &mut aegaeon_pure::organization_recovery::Preflight,
    ) -> Result<()> {
        if result.is_ok() {
            self.continuity_command("COMMIT").await?;
            attempt.finish();
        } else if self.continuity_command("ROLLBACK").await.is_ok() {
            // Only this SQL transaction could mutate. Its confirmed rollback
            // settles the outcome while preserving the original refusal.
            attempt.finish();
        }
        result
    }

    async fn restart_continuity(
        &mut self,
        deployment: DeploymentId,
        selection: &Selection,
        primary: &mut Postgres,
        token: &mut Redis,
    ) -> Result<()> {
        let selected = serde_json::to_value(selection)?;
        let (observed_primary, observed_token) = values(primary, token).await?;
        let locked = self
            .control
            .value(
                sqlx::query_scalar(
                    "SELECT organization_witness.deployment_store_restart_lock($1,$2,$3,$4)",
                )
                .bind(deployment.0)
                .bind(&selected)
                .bind(&observed_primary)
                .bind(&observed_token),
            )
            .await
            .map_err(restart_error)?;
        let snapshot = Snapshot::decode(locked, deployment, selection)?;
        compare_seals(primary, token, deployment, snapshot.seal).await?;
        // Both observations must still name these same owned live connections.
        let (observed_primary, observed_token) = values(primary, token).await?;
        let result = self.control.value(
            sqlx::query_scalar("SELECT organization_witness.deployment_store_restart_finish($1,$2,$3,$4,$5,$6)")
                .bind(deployment.0).bind(&selected).bind(&observed_primary).bind(&observed_token)
                .bind(snapshot.seal).bind(Uuid::new_v4()),
        ).await.map_err(restart_error)?;
        let result = Snapshot::decode(result, deployment, selection)?;
        if result.seal != snapshot.seal
            || !(snapshot.restart_generation..=snapshot.restart_generation + 1)
                .contains(&result.restart_generation)
        {
            return Err(Error::Refused);
        }
        result.check(observed_primary, &observed_token)
    }

    pub(super) async fn lock_completion_seal(&mut self, admission: &Admission) -> Result<Uuid> {
        let slot = &admission.slot;
        let seal: Uuid = serde_json::from_value(self.control.value(
            sqlx::query_scalar("SELECT to_jsonb(organization_witness.deployment_store_seal_lock($1,$2,$3,$4,$5))")
                .bind(admission.deployment.0).bind(slot.slot).bind(slot.generation)
                .bind(slot.epoch).bind(slot.worker_id),
        ).await?)?;
        if seal.is_nil() {
            return Err(Error::Refused);
        }
        Ok(seal)
    }

    pub(super) async fn advance_completion_seal(
        &mut self,
        admission: &Admission,
        previous: Uuid,
        next: Uuid,
    ) -> Result<()> {
        let slot = &admission.slot;
        let actual: Uuid = serde_json::from_value(self.control.value(
            sqlx::query_scalar("SELECT to_jsonb(organization_witness.deployment_store_seal_advance($1,$2,$3,$4,$5,$6,$7))")
                .bind(admission.deployment.0).bind(slot.slot).bind(slot.generation).bind(slot.epoch)
                .bind(slot.worker_id).bind(previous).bind(next),
        ).await?)?;
        if actual != next {
            return Err(Error::Refused);
        }
        Ok(())
    }
}

pub(super) async fn compare_seals(
    primary: &mut Postgres,
    token: &mut Redis,
    deployment: DeploymentId,
    seal: Uuid,
) -> Result<()> {
    let actual_primary = primary
        .continuity_read(deployment.0)
        .await
        .map_err(|_| Error::StoreContinuityMismatch)?;
    let actual_token = token
        .continuity_read(deployment.0)
        .await
        .map_err(|_| Error::StoreContinuityMismatch)?;
    if seal.is_nil() || actual_primary != Some(seal) || actual_token != Some(seal) {
        return Err(Error::StoreContinuityMismatch);
    }
    Ok(())
}

fn restart_error(error: Error) -> Error {
    if matches!(&error, Error::Storage(sqlx::Error::Database(source))
        if source.code().as_deref() == Some("P0R01"))
    {
        Error::StoreRestartPending
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    #[ignore = "requires PostgreSQL; preflight SQL rollback versus uncertain completion"]
    async fn pg_organization_preflight_confirmed_rollback_keeps_admission_reusable(
    ) -> anyhow::Result<()> {
        let connection =
            sqlx::PgConnection::connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?).await?;
        // Test only the actual transaction-finalization path. Catalog and TLS
        // qualification are separate tests; this constructor is fixture-local.
        let mut control = DeploymentControl {
            control: Control {
                connection: Some(connection),
                role: Role::Runtime,
            },
        };
        for commit in [false, true] {
            let mut attempt = aegaeon_pure::organization_recovery::Preflight::default();
            assert!(attempt.begin_mutation());
            control.continuity_command("BEGIN").await?;
            control
                .continuity_command("SELECT set_config('application_name','preflight-test',true)")
                .await?;
            let result = control
                .finish_restart_transaction(
                    if commit {
                        Ok(())
                    } else {
                        Err(Error::StoreRestartPending)
                    },
                    &mut attempt,
                )
                .await;
            assert_eq!(result.is_ok(), commit);
            assert!(
                !attempt.requires_fence(),
                "confirmed SQL outcome must not poison capacity"
            );
            let application: String = sqlx::query_scalar("SHOW application_name")
                .fetch_one(control.control.connection.as_mut().unwrap())
                .await?;
            assert_ne!(application, "preflight-test", "transaction did not finish");
        }
        // No reply/connection is not a rollback confirmation.
        control.control.connection.take().unwrap().close().await?;
        for commit in [false, true] {
            let mut attempt = aegaeon_pure::organization_recovery::Preflight::default();
            assert!(attempt.begin_mutation());
            assert!(control
                .finish_restart_transaction(
                    if commit {
                        Ok(())
                    } else {
                        Err(Error::StoreRestartPending)
                    },
                    &mut attempt,
                )
                .await
                .is_err());
            assert!(attempt.requires_fence());
        }
        Ok(())
    }
}
