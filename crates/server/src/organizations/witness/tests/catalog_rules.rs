use super::*;

const RULE: &str = "CREATE RULE erase_pending AS ON UPDATE TO organization_witness.authorities DO ALSO UPDATE organization_witness.slots SET pending=false WHERE environment_id=NEW.environment_id";
const DROP_RULE: &str = "DROP RULE erase_pending ON organization_witness.authorities";

async fn both_roles_refuse(f: &Fixture) -> TestResult {
    let mut accepted = false;
    for role in [Role::Runtime, Role::Maintenance] {
        if let Ok(control) = f.connect(role).await {
            control.close().await?;
            accepted = true;
        }
    }
    anyhow::ensure!(!accepted, "rewrite-rule catalog drift was accepted");
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual rule removes pending work during fence"]
async fn pg_organizations_witness_rules_refuse_false_drain() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = false_drain(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn false_drain(f: &mut Fixture) -> TestResult {
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let mut runtime = f.connect(Role::Runtime).await?;
    let scope = Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: Uuid::new_v4(),
    };
    let operation = Uuid::new_v4();
    let selected = selection();
    maintenance.initialize(scope, operation).await?;
    maintenance.prepare(scope, operation, 1, &selected).await?;
    maintenance
        .activate(scope, operation, 2, &selected.acceptance_sha256)
        .await?;
    let admission = runtime.acquire(scope, &selected, Uuid::new_v4()).await?;
    anyhow::ensure!(maintenance.current(scope).await?.pending == 1);

    // Only the fixture administrator introduces drift. Neither service role
    // can install it. Mutation after a checked connection is not a supported
    // deployment operation; it demonstrates the actual SQL consequence.
    sqlx::raw_sql(RULE).execute(&mut f.owner).await?;
    let refusal = both_roles_refuse(f).await;
    let falsely_drained = maintenance.fence(scope, Uuid::new_v4(), 3).await?;
    anyhow::ensure!(
        falsely_drained.is_drained_fence(),
        "the malicious-rule control must erase real outstanding work"
    );
    drop(admission); // Deliberately never completes the real pending owner.
    runtime.close().await?;
    maintenance.close().await?;
    sqlx::raw_sql(DROP_RULE).execute(&mut f.owner).await?;
    f.connect(Role::Runtime).await?.close().await?;
    f.connect(Role::Maintenance).await?.close().await?;
    refusal
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; disabled and replica rules are still drift"]
async fn pg_organizations_witness_rules_refuse_every_enable_mode() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = enable_modes(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn enable_modes(f: &mut Fixture) -> TestResult {
    sqlx::raw_sql(RULE).execute(&mut f.owner).await?;
    let mut accepted = false;
    for setting in ["DISABLE", "ENABLE REPLICA", "ENABLE ALWAYS", "ENABLE"] {
        sqlx::raw_sql(&format!(
            "ALTER TABLE organization_witness.authorities {setting} RULE erase_pending"
        ))
        .execute(&mut f.owner)
        .await?;
        accepted |= both_roles_refuse(f).await.is_err();
    }
    sqlx::raw_sql(DROP_RULE).execute(&mut f.owner).await?;
    f.connect(Role::Runtime).await?.close().await?;
    f.connect(Role::Maintenance).await?.close().await?;
    anyhow::ensure!(
        !accepted,
        "a rewrite-rule enable mode escaped catalog checking"
    );
    Ok(())
}
