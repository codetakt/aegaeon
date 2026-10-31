use super::*;

async fn active(f: &Fixture) -> anyhow::Result<(Control, Control, Scope, Selection)> {
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let runtime = f.connect(Role::Runtime).await?;
    let scope = Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: Uuid::new_v4(),
    };
    let operation = Uuid::new_v4();
    let selected = selection();
    maintenance.initialize(scope, operation).await?;
    assert!(maintenance.pending(scope).await?.admissions.is_empty());
    maintenance.prepare(scope, operation, 1, &selected).await?;
    maintenance
        .activate(scope, operation, 2, &selected.acceptance_sha256)
        .await?;
    Ok((maintenance, runtime, scope, selected))
}

#[tokio::test]
#[ignore = "requires PostgreSQL; bounded pending inventory survives caller loss"]
async fn pg_organizations_pending_inventory_retains_every_admission() -> TestResult {
    let f = Fixture::new().await?;
    let result: TestResult = async {
        let (mut maintenance, mut runtime, scope, selected) = active(&f).await?;
        let mut admissions = Vec::new();
        for _ in 0..64 {
            admissions.push(runtime.acquire(scope, &selected, Uuid::new_v4()).await?);
        }
        assert!(runtime
            .acquire(scope, &selected, Uuid::new_v4())
            .await
            .is_err());
        let observed = maintenance.pending(scope).await?;
        assert_eq!(observed.state.pending, 64);
        for (slot, admission) in observed.admissions.iter().zip(&admissions) {
            assert_eq!(slot.slot, admission.slot.slot);
            assert_eq!(slot.generation, admission.slot.generation);
            assert_eq!(slot.worker_id, admission.slot.worker_id);
            assert_eq!(slot.epoch, selected.epoch);
            assert_eq!(slot.principal, f.runtime);
        }
        runtime.complete(&admissions.remove(0)).await?;
        runtime.close().await?;
        drop(admissions);
        maintenance.close().await?;
        let mut reconnected = f.connect(Role::Maintenance).await?;
        let before = reconnected.current(scope).await?;
        let observed = reconnected.pending(scope).await?;
        assert_eq!(observed.admissions.len(), 63);
        assert_eq!(observed.admissions[0].slot, 1);
        assert_eq!(
            serde_json::to_value(&observed.state)?,
            serde_json::to_value(&before)?
        );
        let fenced = reconnected
            .fence(scope, Uuid::new_v4(), before.revision)
            .await?;
        assert!(!fenced.is_drained_fence());
        let pending = reconnected.pending(scope).await?;
        assert_eq!(pending.state.phase, "fenced");
        assert_eq!(pending.state.pending, 63);
        assert!(reconnected
            .prepare(scope, fenced.operation_id, fenced.revision, &selection())
            .await
            .is_err());
        reconnected.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; pending inspection is maintenance-only and scoped"]
async fn pg_organizations_pending_privilege_and_scope_boundary() -> TestResult {
    let f = Fixture::new().await?;
    let result: TestResult = async {
        let (mut maintenance, mut runtime, scope, selected) = active(&f).await?;
        let admission = runtime.acquire(scope, &selected, Uuid::new_v4()).await?;
        assert!(runtime.pending(scope).await.is_err());
        assert!(runtime
            .value(
                sqlx::query_scalar("SELECT organization_witness.pending_work($1,$2)")
                    .bind(scope.environment_id)
                    .bind(scope.deployment_id)
            )
            .await
            .is_err());
        for foreign in [
            Scope {
                environment_id: Uuid::new_v4(),
                ..scope
            },
            Scope {
                deployment_id: Uuid::new_v4(),
                ..scope
            },
        ] {
            assert!(maintenance.pending(foreign).await.is_err());
        }
        assert!(maintenance
            .value(sqlx::query_scalar(
                "SELECT to_jsonb(s) FROM organization_witness.slots s LIMIT 1"
            ))
            .await
            .is_err());
        let pending = maintenance.pending(scope).await?;
        assert_eq!(pending.state.pending, 1);
        assert_eq!(pending.admissions[0].worker_id, admission.slot.worker_id);
        runtime.complete(&admission).await?;
        assert!(maintenance.pending(scope).await?.admissions.is_empty());
        runtime.close().await?;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; pending observation waits for the actual writer lock"]
async fn pg_organizations_pending_observation_serializes_with_completion() -> TestResult {
    let mut f = Fixture::new().await?;
    let result: TestResult = async {
        let (mut maintenance, mut runtime, scope, selected) = active(&f).await?;
        let admission = runtime.acquire(scope, &selected, Uuid::new_v4()).await?;
        let mut tx = runtime.connection.as_mut().ok_or(Error::Refused)?.begin().await?;
        sqlx::query("SELECT organization_witness.release($1,$2,$3,$4,$5,$6)")
            .bind(scope.environment_id).bind(scope.deployment_id)
            .bind(admission.slot.slot).bind(admission.slot.generation)
            .bind(admission.slot.epoch).bind(admission.slot.worker_id)
            .execute(&mut *tx).await?;
        let pending = tokio::spawn(async move {
            let result = maintenance.pending(scope).await;
            let close = maintenance.close().await;
            close?;
            result
        });
        let wait = async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=$1 AND usename=$2 AND wait_event_type='Lock')")
                    .bind(&f.database).bind(&f.maintenance).fetch_one(&mut f.admin).await?;
                if waiting { return Ok::<(),sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        let observed_lock = tokio::time::timeout(Duration::from_secs(5), wait).await;
        // Only commit makes the actual runtime release visible. The observation
        // must wait for that transaction, then report its complete pending set.
        tx.commit().await?;
        let observed = pending.await??;
        observed_lock??;
        assert_eq!(observed.state.pending, 0);
        assert!(observed.admissions.is_empty());
        runtime.close().await?;
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; old or altered control catalog refuses inspection"]
async fn pg_organizations_pending_catalog_drift_refuses_connection() -> TestResult {
    let mut f = Fixture::new().await?;
    let result: TestResult = async {
        sqlx::raw_sql("GRANT EXECUTE ON FUNCTION organization_witness.pending_work(uuid,uuid) TO aegaeon_organization_witness_runtime")
            .execute(&mut f.owner).await?;
        assert!(f.connect(Role::Runtime).await.is_err());
        assert!(f.connect(Role::Maintenance).await.is_err());
        sqlx::raw_sql("REVOKE EXECUTE ON FUNCTION organization_witness.pending_work(uuid,uuid) FROM aegaeon_organization_witness_runtime; DROP FUNCTION organization_witness.pending_work(uuid,uuid)")
            .execute(&mut f.owner).await?;
        assert!(f.connect(Role::Runtime).await.is_err());
        assert!(f.connect(Role::Maintenance).await.is_err());
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}
