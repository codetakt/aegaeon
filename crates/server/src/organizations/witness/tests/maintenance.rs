//! Real restricted v9 coordinator tests. Production TLS uses the packaged journey.
use super::super::maintenance::{Request, Session};
use super::*;
use crate::organizations::snapshot::custody::Artifacts;
use serde_json::{json, Value};
use std::os::unix::fs::DirBuilderExt;

async fn control(f: &Fixture) -> anyhow::Result<Control> {
    Ok(f.connect(Role::Maintenance).await?)
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; real durable maintenance and custody"]
async fn pg_organizations_maintenance_history_owner_retains_uncertain_work() -> TestResult {
    let mut f = Fixture::new().await?;
    let parent = std::env::temp_dir().join(format!("aegaeon-maintenance-test-{}", Uuid::new_v4()));
    std::fs::DirBuilder::new().mode(0o700).create(&parent)?;
    let result = async {
        let deployment = Uuid::new_v4();
        let operation = Uuid::new_v4();
        sqlx::query("SELECT organization_witness.deployment_initialize($1,$2)")
            .bind(deployment)
            .bind(operation)
            .execute(&mut f.owner)
            .await?;
        let scope = Scope {
            environment_id: Uuid::new_v4(),
            deployment_id: deployment,
        };
        sqlx::query("SELECT organization_witness.initialize($1,$2,$3)")
            .bind(scope.environment_id)
            .bind(deployment)
            .bind(Uuid::new_v4())
            .execute(&mut f.owner)
            .await?;
        let plan = json!({"test":"fixed history inspection"});
        let output = Artifacts::create(&parent.join("normal"))?;
        let request = || Request {
            scope,
            parent_operation: operation,
            parent_revision: 1,
            work_id: Uuid::new_v4(),
            kind: "history-inspect",
            plan: &plan,
        };
        let mut owner = Session::isolated(control(&f).await?, request(), &output).await?;
        let state = owner
            .control()
            .value(
                sqlx::query_scalar("SELECT organization_witness.maintenance_state($1)")
                    .bind(deployment),
            )
            .await?;
        assert_eq!(state["pending"], true);
        let mut lifecycle = super::deployment::connect(&f, Role::Maintenance).await?;
        let deployment_id = super::super::deployment::DeploymentId::new(deployment)?;
        assert!(lifecycle
            .prepare(deployment_id, operation, 1, &selection())
            .await
            .is_err());
        assert_eq!(lifecycle.current(deployment_id).await?.phase, "fenced");
        lifecycle.close().await?;
        owner
            .finish(&output, b"normal completed journal receipt")
            .await?;
        let receipt: Value = serde_json::from_slice(&std::fs::read(
            parent.join("normal/maintenance-released.json"),
        )?)?;
        assert_eq!(receipt["pending"], false);
        drop(output);
        // No Drop acknowledgement: abandoning the actual control link keeps the
        // slot pending and prevents another invocation from entering.
        let output = Artifacts::create(&parent.join("abandoned"))?;
        let owner = Session::isolated(control(&f).await?, request(), &output).await?;
        drop(owner);
        drop(output);
        let output = Artifacts::create(&parent.join("competing"))?;
        assert!(Session::isolated(control(&f).await?, request(), &output)
            .await
            .is_err());
        let state: Value = sqlx::query_scalar("SELECT organization_witness.maintenance_state($1)")
            .bind(deployment)
            .fetch_one(&mut f.owner)
            .await?;
        assert_eq!(state["pending"], true);
        assert_eq!(state["generation"], 2);
        Ok(())
    }
    .await;
    f.finish().await?;
    std::fs::remove_dir_all(parent)?;
    result
}
