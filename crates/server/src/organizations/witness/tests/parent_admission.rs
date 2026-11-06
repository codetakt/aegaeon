//! Low-level SQL fixture; observed Work tests separately exercise actual drivers.
use super::*;
use crate::organizations::witness::deployment::{Admission as ParentAdmission, DeploymentControl};

pub(super) struct Parent {
    pub(super) control: DeploymentControl,
    pub(super) admission: ParentAdmission,
    pub(super) scope: Scope,
    pub(super) selected: Selection,
    pub(super) epoch: Uuid,
}
impl Parent {
    /// Prepare the parent before its child. The child deliberately has no store
    /// checkpoint or activation: each test must establish those prerequisites.
    pub(super) async fn prepare(
        f: &mut Fixture,
    ) -> anyhow::Result<(Control, Scope, Uuid, Selection, Self)> {
        use crate::organizations::witness::deployment::DeploymentId;
        let scope = Scope {
            environment_id: Uuid::new_v4(),
            deployment_id: Uuid::new_v4(),
        };
        let deployment = DeploymentId::new(scope.deployment_id)?;
        let mut maintenance = deployment::connect(f, Role::Maintenance).await?;
        let operation = Uuid::new_v4();
        maintenance.initialize(deployment, operation).await?;
        maintenance.close().await?;
        let selected = selection();
        let parent = Self::from_fenced(f, scope, &selected).await?;
        let mut child = f.connect(Role::Maintenance).await?;
        child.initialize(scope, operation).await?;
        child.prepare(scope, operation, 1, &selected).await?;
        parent.bind(f).await?;
        Ok((child, scope, operation, selected, parent))
    }

    /// Existing children must remain fenced throughout parent preparation.
    pub(super) async fn from_fenced(
        f: &mut Fixture,
        scope: Scope,
        selected: &Selection,
    ) -> anyhow::Result<Self> {
        use crate::organizations::witness::deployment::DeploymentId;
        let deployment = DeploymentId::new(scope.deployment_id)?;
        let mut maintenance = deployment::connect(f, Role::Maintenance).await?;
        let state = maintenance.current(deployment).await?;
        anyhow::ensure!(state.phase == "fenced" && state.pending == 0);
        let parent = Selection {
            epoch: Uuid::new_v4(),
            ..selected.clone()
        };
        let prepared = maintenance
            .prepare(deployment, state.operation_id, state.revision, &parent)
            .await?;
        store_supplier::control(f, scope.deployment_id).await?;
        let (mut primary, mut token) = store_progress::links(f, 0).await?;
        maintenance
            .pin_store_progress(
                deployment,
                state.operation_id,
                prepared.revision,
                &mut primary,
                &mut token,
            )
            .await?;
        maintenance
            .activate(
                deployment,
                state.operation_id,
                prepared.revision,
                &parent.acceptance_sha256,
            )
            .await?;
        primary.close().await?;
        token.close();
        maintenance.close().await?;
        let mut control = deployment::connect(f, Role::Runtime).await?;
        let admission = control.acquire(deployment, &parent, Uuid::new_v4()).await?;
        Ok(Self {
            control,
            admission,
            scope,
            selected: selected.clone(),
            epoch: parent.epoch,
        })
    }

    pub(super) async fn bind(&self, f: &Fixture) -> Result<()> {
        use crate::organizations::witness::deployment::DeploymentId;
        let mut maintenance = deployment::connect(f, Role::Maintenance).await?;
        maintenance
            .bind_child(
                DeploymentId::new(self.scope.deployment_id)?,
                self.epoch,
                self.scope.environment_id,
                self.selected.epoch,
            )
            .await?;
        maintenance.close().await
    }
    pub(super) async fn acquire(&mut self) -> Result<Admission> {
        self.control
            .acquire_child(
                &self.admission,
                self.scope.environment_id,
                &self.selected,
                Uuid::new_v4(),
            )
            .await
    }
    pub(super) async fn close(mut self, complete: bool) -> TestResult {
        let result = self.control.complete(&self.admission).await;
        // Low-level SQL inventory test: child ownership alone prevents parent
        // release. Actual observed driver cleanup is covered in observed_work.
        if complete {
            assert_eq!(result?.pending, 0);
        } else {
            assert!(
                matches!(result, Err(Error::Storage(sqlx::Error::Database(ref error)))
                if error.message() == "deployment child still pending"),
                "only a confirmed pending-child refusal satisfies this test"
            );
            let current = self
                .control
                .current(
                    crate::organizations::witness::deployment::DeploymentId::new(
                        self.scope.deployment_id,
                    )?,
                )
                .await?;
            assert_eq!(current.pending, 1);
        }
        self.control.close().await?;
        Ok(())
    }
}
