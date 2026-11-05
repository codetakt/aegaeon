//! Current callers share one catalog; historical catalogs only qualify upgrades.
use super::deployment::connect as deployment;
use super::*;

async fn check_callers(f: &Fixture, accepted: bool) -> TestResult {
    for role in [Role::Runtime, Role::Maintenance] {
        let child = f.connect(role).await;
        let child_accepted = child.is_ok();
        if let Ok(control) = child {
            control.close().await?;
        }
        let parent = deployment(f, role).await;
        let parent_accepted = parent.is_ok();
        if let Ok(control) = parent {
            control.close().await?;
        }
        anyhow::ensure!(
            child_accepted == accepted && parent_accepted == accepted,
            "current parent/child catalog acceptance differs from the required version"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; all current roles reject legacy catalogs"]
async fn pg_organizations_current_callers_require_joint_catalog() -> TestResult {
    for version in [6, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
        let f = Fixture::with_version(version).await?;
        let result = check_callers(&f, version == 16).await;
        let cleanup = f.finish().await;
        result.and(cleanup)?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; upgrade retains current authority and rejects unsafe state"]
async fn pg_organizations_joint_catalog_upgrade_preserves_authority() -> TestResult {
    let mut f = Fixture::with_version(8).await?;
    let result = upgrade(&mut f).await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

async fn upgrade(f: &mut Fixture) -> TestResult {
    let scope = Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: Uuid::new_v4(),
    };
    let operation = Uuid::new_v4();
    // Historical setup uses the fixture administrator only. No production
    // constructor accepts the old schema, even during an upgrade.
    sqlx::query("SELECT organization_witness.deployment_initialize($1,$2)")
        .bind(scope.deployment_id)
        .bind(operation)
        .execute(&mut f.owner)
        .await?;
    let original: serde_json::Value =
        sqlx::query_scalar("SELECT organization_witness.initialize($1,$2,$3)")
            .bind(scope.environment_id)
            .bind(scope.deployment_id)
            .bind(operation)
            .fetch_one(&mut f.owner)
            .await?;
    let schema = include_str!("../../../../../../db/organization-witness/schema-v9.sql");
    sqlx::query(
        "UPDATE organization_witness.slots SET pending=true,generation=1,epoch=$2,worker_id=$3,principal=session_user WHERE environment_id=$1 AND slot=0",
    )
    .bind(scope.environment_id)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .execute(&mut f.owner)
    .await?;
    anyhow::ensure!(
        sqlx::raw_sql(schema).execute(&mut f.owner).await.is_err(),
        "migration accepted an outstanding child writer"
    );
    sqlx::raw_sql("ROLLBACK").execute(&mut f.owner).await?;
    check_callers(f, false).await?;
    // Only this fixture owns the fabricated outstanding writer; clearing it is
    // not a production reconciliation procedure.
    sqlx::query(
        "UPDATE organization_witness.slots SET pending=false WHERE environment_id=$1 AND slot=0",
    )
    .bind(scope.environment_id)
    .execute(&mut f.owner)
    .await?;
    sqlx::raw_sql(schema).execute(&mut f.owner).await?;
    check_callers(f, false).await?;
    sqlx::raw_sql(include_str!(
        "../../../../../../db/organization-witness/schema-v10.sql"
    ))
    .execute(&mut f.owner)
    .await?;
    check_callers(f, false).await?;
    sqlx::raw_sql(include_str!(
        "../../../../../../db/organization-witness/schema-v11.sql"
    ))
    .execute(&mut f.owner)
    .await?;
    check_callers(f, false).await?;
    sqlx::raw_sql(include_str!(
        "../../../../../../db/organization-witness/schema-v12.sql"
    ))
    .execute(&mut f.owner)
    .await?;
    check_callers(f, false).await?;
    sqlx::raw_sql(include_str!(
        "../../../../../../db/organization-witness/schema-v13.sql"
    ))
    .execute(&mut f.owner)
    .await?;
    check_callers(f, false).await?;
    sqlx::raw_sql(include_str!(
        "../../../../../../db/organization-witness/schema-v14.sql"
    ))
    .execute(&mut f.owner)
    .await?;
    check_callers(f, false).await?;
    sqlx::raw_sql(include_str!(
        "../../../../../../db/organization-witness/schema-v15.sql"
    ))
    .execute(&mut f.owner)
    .await?;
    check_callers(f, false).await?;
    sqlx::raw_sql(include_str!(
        "../../../../../../db/organization-witness/schema-v16.sql"
    ))
    .execute(&mut f.owner)
    .await?;
    check_callers(f, true).await?;
    let mut control = f.connect(Role::Maintenance).await?;
    let current = serde_json::to_value(control.current(scope).await?)?;
    anyhow::ensure!(
        current == original,
        "upgrade changed the original authority"
    );
    let slots: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organization_witness.slots WHERE environment_id=$1",
    )
    .bind(scope.environment_id)
    .fetch_one(&mut f.owner)
    .await?;
    anyhow::ensure!(slots == 64);
    control.close().await?;
    // A legacy exact-catalog client also rejects the new schema; retaining its
    // old manifest does not authorize a mixed-version runtime.
    let actual: serde_json::Value = sqlx::query_scalar(include_str!(
        "../../../../../../db/organization-witness/catalog-v5.sql"
    ))
    .fetch_one(&mut f.owner)
    .await?;
    let previous: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../db/organization-witness/catalog-v8.json"
    ))?;
    anyhow::ensure!(actual != previous);
    Ok(())
}
