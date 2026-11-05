//! Retained maintenance owner for fixed history, snapshot and subject command graphs.
//! No public completion assertion, Drop cleanup, reconnect or arbitrary executor.
use super::{Control, Error, Role, Scope};
use crate::organizations::snapshot::custody::Artifacts;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    deployment_id: Uuid,
    generation: i64,
    pending: bool,
    fence_operation_id: Uuid,
    fence_revision: i64,
    work_id: Uuid,
    principal: String,
    kind: String,
    plan_sha256: String,
    completion_sha256: Option<String>,
}

pub(crate) struct Session {
    control: Control,
    slot: Slot,
    scope: Scope,
    primary_pending: bool,
}

pub(crate) struct Request<'a> {
    pub scope: Scope,
    pub parent_operation: Uuid,
    pub parent_revision: i64,
    pub work_id: Uuid,
    pub kind: &'a str,
    pub plan: &'a Value,
}

impl Session {
    pub(crate) async fn begin(
        endpoint: &str,
        ca: &Path,
        request: Request<'_>,
        output: &Artifacts,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !request.scope.environment_id.is_nil()
                && !request.scope.deployment_id.is_nil()
                && !request.parent_operation.is_nil()
                && !request.work_id.is_nil()
                && request.parent_revision > 0
                && matches!(
                    request.kind,
                    "history-import"
                        | "history-inspect"
                        | "history-restore"
                        | "snapshot-inspect"
                        | "snapshot-prepare"
                        | "subject-inventory"
                        | "subject-adopt"
                ),
            "explicit bounded maintenance request required"
        );
        let plan = serde_json::to_vec(request.plan)?;
        anyhow::ensure!(plan.len() <= 1024 * 1024, "maintenance plan bound");
        // Retain exact plan before acquiring; a lost response never admits a retry.
        output.write("maintenance-plan.json", &plan)?;
        let hash = super::history::hex(&aegaeon_crypto::hash::sha256_digest(&plan));
        let control = Control::connect(endpoint, ca, Role::Maintenance).await?;
        Self::acquire(control, request, output, &hash).await
    }

    async fn acquire(
        mut control: Control,
        request: Request<'_>,
        output: &Artifacts,
        hash: &str,
    ) -> anyhow::Result<Self> {
        let child = control.current(request.scope).await?;
        anyhow::ensure!(
            child.is_drained_fence(),
            "maintenance Environment fence required"
        );
        let value = control
            .value(
                sqlx::query_scalar(
                    "SELECT organization_witness.maintenance_acquire($1,$2,$3,$4,$5,$6)",
                )
                .bind(request.scope.deployment_id)
                .bind(request.parent_operation)
                .bind(request.parent_revision)
                .bind(request.work_id)
                .bind(request.kind)
                .bind(hash),
            )
            .await?;
        let slot: Slot = serde_json::from_value(value)?;
        anyhow::ensure!(
            slot.pending
                && slot.generation > 0
                && !slot.principal.is_empty()
                && slot.deployment_id == request.scope.deployment_id
                && slot.fence_operation_id == request.parent_operation
                && slot.fence_revision == request.parent_revision
                && slot.work_id == request.work_id
                && slot.kind == request.kind
                && slot.plan_sha256 == hash
                && slot.completion_sha256.is_none(),
            "maintenance acknowledgement differs"
        );
        output.write("maintenance-admission.json", &serde_json::to_vec(&slot)?)?;
        Ok(Self {
            control,
            slot,
            scope: request.scope,
            primary_pending: false,
        })
    }

    #[cfg(test)]
    pub(in crate::organizations) async fn isolated(
        control: Control,
        request: Request<'_>,
        output: &Artifacts,
    ) -> anyhow::Result<Self> {
        let plan = serde_json::to_vec(request.plan)?;
        output.write("maintenance-plan.json", &plan)?;
        let hash = super::history::hex(&aegaeon_crypto::hash::sha256_digest(&plan));
        Self::acquire(control, request, output, &hash).await
    }

    pub(in crate::organizations) fn control(&mut self) -> &mut Control {
        &mut self.control
    }

    // The only primary-opening path in this command graph. The direct connection
    // is consumed by restoration, which awaits each statement/transaction and
    // closes it before returning success. A cancelled or failed future never
    // clears primary_pending, so it cannot manufacture normal completion.
    pub(in crate::organizations) async fn restore(
        &mut self,
        request: super::history::restoration::Request<'_>,
    ) -> anyhow::Result<super::history::restoration::Preparation> {
        anyhow::ensure!(
            !self.primary_pending
                && self.slot.kind == "history-restore"
                && request.fence.scope.environment_id == self.scope.environment_id
                && request.fence.scope.deployment_id == self.scope.deployment_id,
            "maintenance target differs"
        );
        self.primary_pending = true;
        let primary = crate::organizations::snapshot::cli::connect(true)
            .await
            .map_err(anyhow::Error::msg)?;
        let result =
            super::history::restoration::prepare(primary, &mut self.control, request).await?;
        self.primary_pending = false;
        Ok(result)
    }

    /// Only the fixed synchronous history graph calls this after final input
    /// recheck, journal/receipt fsync and all owned primary work has completed.
    pub(crate) async fn finish(mut self, output: &Artifacts, receipt: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(!self.primary_pending, "primary work is unconfirmed");
        let completion = serde_json::to_vec(&json!({"version":1,"maintenance":self.slot,
            "receiptSha256":super::history::hex(&aegaeon_crypto::hash::sha256_digest(receipt)),
            "activationAuthorized":false}))?;
        output.write("maintenance-completion.json", &completion)?;
        let hash = super::history::hex(&aegaeon_crypto::hash::sha256_digest(&completion));
        let value = self
            .control
            .value(
                sqlx::query_scalar(
                    "SELECT organization_witness.maintenance_complete($1,$2,$3,$4,$5)",
                )
                .bind(self.slot.deployment_id)
                .bind(self.slot.generation)
                .bind(self.slot.work_id)
                .bind(&self.slot.plan_sha256)
                .bind(&hash),
            )
            .await?;
        let mut expected = serde_json::to_value(&self.slot)?;
        expected["pending"] = json!(false);
        expected["completion_sha256"] = json!(hash);
        if value != expected {
            return Err(Error::Refused.into());
        }
        self.control.close().await?;
        output.write("maintenance-released.json", &serde_json::to_vec(&value)?)?;
        Ok(())
    }
}
