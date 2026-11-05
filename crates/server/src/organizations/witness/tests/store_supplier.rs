//! Explicit administrator setup for serial, disposable store suppliers only.
use super::*;

fn continuity() -> &'static str {
    include_str!("../../../../../../tests/organizations/legacy-store-continuity.sql")
}
const SUBJECT: &str =
    include_str!("../../../../../../db/migrations/20261029050000_subject_ownership.sql");
const KEY: &str = "aegaeon:organization-store-continuity:v1";

pub(super) async fn control(f: &mut Fixture, deployment: Uuid) -> TestResult {
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM organization_witness.deployment_slots WHERE pending) \
         OR EXISTS(SELECT FROM organization_witness.slots WHERE pending) \
         OR EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE pending)",
    )
    .fetch_one(&mut f.owner)
    .await?;
    anyhow::ensure!(!pending, "test supplier reset requires all owners drained");
    // This database supplies store-observation tests, not application history.
    // Keep the exact production seal catalog and namespace-entry definition.
    // Only successful setup by this fixture suppresses a duplicate installation;
    // production paths still check the actual catalog on every new opaque link.
    if !f.control_store_supplier_installed {
        install_control(f).await?;
        f.control_store_supplier_installed = true;
    }
    let token = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    reset(&mut f.owner, &token, deployment).await
}

async fn install_control(f: &mut Fixture) -> TestResult {
    sqlx::raw_sql("CREATE SCHEMA aegaeon; GRANT USAGE ON SCHEMA aegaeon TO aegaeon_subject_owner,aegaeon_subject_maintenance")
        .execute(&mut f.owner).await?;
    let continuity = continuity()
        .split_once("-- Advance only the exact Atlas prefix")
        .ok_or_else(|| anyhow::anyhow!("continuity installation boundary absent"))?
        .0;
    sqlx::raw_sql(&format!("BEGIN;{continuity}COMMIT;"))
        .execute(&mut f.owner)
        .await?;
    let namespace = SUBJECT
        .split_once("CREATE FUNCTION aegaeon.validate_subject_ownership_namespace_v1(")
        .and_then(|(_, body)| body.split_once("$function$;"))
        .ok_or_else(|| anyhow::anyhow!("namespace-entry definition absent"))?
        .0;
    sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.validate_subject_ownership_namespace_v1({namespace}$function$; ALTER FUNCTION aegaeon.validate_subject_ownership_namespace_v1(uuid) OWNER TO aegaeon_subject_owner; REVOKE ALL ON FUNCTION aegaeon.validate_subject_ownership_namespace_v1(uuid) FROM PUBLIC; GRANT USAGE ON SCHEMA aegaeon TO {runtime}; GRANT EXECUTE ON FUNCTION aegaeon.validate_subject_ownership_namespace_v1(uuid),aegaeon.organization_store_continuity_read_v1(uuid),aegaeon.organization_store_continuity_replace_v1(uuid,uuid,uuid) TO {runtime};",runtime=f.runtime))
        .execute(&mut f.owner).await?;
    Ok(())
}

pub(super) async fn application(
    primary: &PgConnectOptions,
    token: &redis::Client,
    deployment: Uuid,
) -> TestResult {
    // Existing test drivers serialize fixtures. The administrator resets only
    // the retained seal state before this new deployment has any open owners.
    // Runtime sessions never receive reset or initialization authority.
    let database = primary
        .get_database()
        .ok_or_else(|| anyhow::anyhow!("explicit test primary database required"))?;
    let options: PgConnectOptions = std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?.parse()?;
    let mut admin = PgConnection::connect_with(&options.database(database)).await?;
    // Retired contract fixtures install their own legacy catalog. The product
    // migration and provisioning no longer contain or grant continuity seals.
    let present: bool = sqlx::query_scalar(
        "SELECT to_regclass('aegaeon.organization_store_continuity') IS NOT NULL",
    )
    .fetch_one(&mut admin)
    .await?;
    if !present {
        sqlx::raw_sql(continuity()).execute(&mut admin).await?;
    }
    let grant: String = sqlx::query_scalar("SELECT format('GRANT EXECUTE ON FUNCTION aegaeon.organization_store_continuity_read_v1(uuid),aegaeon.organization_store_continuity_replace_v1(uuid,uuid,uuid) TO %I',$1::text)")
        .bind(primary.get_username()).fetch_one(&mut admin).await?;
    sqlx::raw_sql(&grant).execute(&mut admin).await?;
    let result = reset(&mut admin, token, deployment).await;
    let close = admin.close().await;
    result?;
    close?;
    Ok(())
}

async fn reset(admin: &mut PgConnection, token: &redis::Client, deployment: Uuid) -> TestResult {
    anyhow::ensure!(!deployment.is_nil());
    let seal = Uuid::new_v4();
    sqlx::raw_sql("TRUNCATE aegaeon.organization_store_continuity")
        .execute(&mut *admin)
        .await?;
    let initialized: Uuid =
        sqlx::query_scalar("SELECT aegaeon.organization_store_continuity_replace_v1($1,NULL,$2)")
            .bind(deployment)
            .bind(seal)
            .fetch_one(&mut *admin)
            .await?;
    anyhow::ensure!(initialized == seal);
    let mut connection = token.get_multiplexed_async_connection().await?;
    redis::cmd("DEL")
        .arg(KEY)
        .query_async::<usize>(&mut connection)
        .await?;
    redis::cmd("SET")
        .arg(KEY)
        .arg(format!("{deployment}:{seal}"))
        .query_async::<()>(&mut connection)
        .await?;
    let acknowledged: Vec<i64> = redis::cmd("WAITAOF")
        .arg(1)
        .arg(0)
        .arg(4000)
        .query_async(&mut connection)
        .await?;
    anyhow::ensure!(
        acknowledged.len() == 2 && acknowledged[0] == 1 && acknowledged[1] >= 0,
        "test Redis must durably fsync the initialized seal"
    );
    Ok(())
}
