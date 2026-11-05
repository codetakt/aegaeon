//! SQL-only continuity rules; actual durable primary/Redis seals are checked by Rust.
use super::startup_preflight::{scope, selected, snapshot};
use super::*;
use serde_json::{json, Value};

const SEED: &str = include_str!("../../../../../../tests/organizations/store_continuity.sql");
const ACQUIRE: &str = "SELECT organization_witness.deployment_acquire('10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000003','10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000006','10000000-0000-0000-0000-000000000008')";
const RELEASE: &str = "SELECT organization_witness.deployment_release('10000000-0000-0000-0000-000000000001',0,1,'10000000-0000-0000-0000-000000000003','10000000-0000-0000-0000-000000000008')";
const BEGIN_OBSERVATION: &str = "SELECT organization_witness.deployment_store_progress_begin('10000000-0000-0000-0000-000000000001',0,1,'10000000-0000-0000-0000-000000000003','10000000-0000-0000-0000-000000000008')";
const SEAL_LOCK: &str = "SELECT organization_witness.deployment_store_seal_lock('10000000-0000-0000-0000-000000000001',0,1,'10000000-0000-0000-0000-000000000003','10000000-0000-0000-0000-000000000008')";
const ADVANCE: &str = "SELECT organization_witness.deployment_store_seal_advance('10000000-0000-0000-0000-000000000001',0,1,'10000000-0000-0000-0000-000000000003','10000000-0000-0000-0000-000000000008','10000000-0000-0000-0000-000000000011','10000000-0000-0000-0000-000000000021')";

fn id(suffix: u128) -> Uuid {
    Uuid::from_u128(0x10000000000000000000000000000000 | suffix)
}

fn primary(restarted: bool) -> Value {
    json!({"cluster_id":1,"database_oid":1,"database_name":"store_continuity_fixture",
        "started_us":if restarted {2} else {1},"timeline":1,"wal_position":40})
}

fn token(restarted: bool) -> Value {
    json!({"run_id":if restarted {"e".repeat(40)} else {"d".repeat(40)},"database":0})
}

async fn restart(
    connection: &mut PgConnection,
    primary: &Value,
    token: &Value,
) -> std::result::Result<Value, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT organization_witness.deployment_store_restart_finish($1,$2,$3,$4,$5,$6)",
    )
    .bind(scope().deployment_id)
    .bind(selected(true))
    .bind(primary)
    .bind(token)
    .bind(id(0x11))
    .bind(id(0x22))
    .fetch_one(connection)
    .await
}

async fn finish_observation(connection: &mut PgConnection) -> anyhow::Result<()> {
    sqlx::query("SELECT organization_witness.deployment_store_progress_finish($1,0,1,$2,$3,$4,$5)")
        .bind(scope().deployment_id)
        .bind(id(3))
        .bind(id(8))
        .bind(primary(false))
        .bind(token(false))
        .execute(connection)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; activation and admission require an exact prepared seal"]
async fn pg_organizations_store_continuity_requires_exact_prepared_seal() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        sqlx::raw_sql(SEED).execute(&mut f.owner).await?;
        let before = snapshot(&mut f).await?;
        let pin = "SELECT organization_witness.deployment_store_seal_pin('10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000007',2,'10000000-0000-0000-0000-000000000011')";
        // Administrator-only fixture state: verify both first pin and exact replay.
        sqlx::raw_sql("BEGIN; UPDATE organization_witness.deployments SET phase='prepared',revision=2; DELETE FROM organization_witness.deployment_store_seals")
            .execute(&mut f.owner).await?;
        for _ in 0..2 {
            sqlx::query(pin).execute(&mut f.owner).await?;
        }
        sqlx::raw_sql("ROLLBACK").execute(&mut f.owner).await?;
        for seal in [None, Some(Uuid::nil()), Some(id(0x21))] {
            sqlx::raw_sql("BEGIN; UPDATE organization_witness.deployments SET phase='prepared',revision=2")
                .execute(&mut f.owner).await?;
            let refused = sqlx::query("SELECT organization_witness.deployment_store_seal_pin($1,$2,2,$3)")
                .bind(scope().deployment_id).bind(id(7)).bind(seal)
                .execute(&mut f.owner).await.is_err();
            sqlx::raw_sql("ROLLBACK").execute(&mut f.owner).await?;
            anyhow::ensure!(refused, "nil/conflicting seal pin accepted");
        }
        for (setup, query) in [
            ("BEGIN; UPDATE organization_witness.deployments SET phase='prepared',revision=2; DELETE FROM organization_witness.deployment_store_seals", "SELECT organization_witness.deployment_activate('10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000007',2,repeat('c',64))"),
            ("BEGIN; DELETE FROM organization_witness.deployment_store_seals", ACQUIRE),
        ] {
            sqlx::raw_sql(setup).execute(&mut f.owner).await?;
            let refused = sqlx::query(query).execute(&mut f.owner).await.is_err();
            sqlx::raw_sql("ROLLBACK").execute(&mut f.owner).await?;
            anyhow::ensure!(refused, "unpinned activation/admission accepted");
        }
        anyhow::ensure!(before == snapshot(&mut f).await?, "pin/refusal changed fixture state");
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; restart rebinds every child and retains previous checkpoints"]
async fn pg_organizations_store_continuity_restart_is_atomic_and_retains_history() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        sqlx::raw_sql(SEED).execute(&mut f.owner).await?;
        let before = snapshot(&mut f).await?;
        let mut runtime = f.connect(Role::Runtime).await?;
        for (key, value) in [
            ("cluster_id", json!(2)),
            ("database_oid", json!(2)),
            ("database_name", json!("foreign")),
            ("timeline", json!(2)),
            ("wal_position", json!(9)),
            ("wal_position", json!(29)),
        ] {
            let mut changed = primary(true);
            changed[key] = value;
            anyhow::ensure!(restart(runtime.connection.as_mut().unwrap(), &changed, &token(true)).await.is_err(), "foreign/regressed primary accepted");
        }
        let mut changed_token = token(true);
        changed_token["database"] = json!(1);
        anyhow::ensure!(restart(runtime.connection.as_mut().unwrap(), &primary(true), &changed_token).await.is_err(), "foreign Redis database accepted");
        // Each fabricated corruption is rolled back, and no real worker exists.
        for mutation in [
            "DELETE FROM organization_witness.deployment_children WHERE environment_id='10000000-0000-0000-0000-000000000002'",
            "UPDATE organization_witness.store_checkpoints SET wal_position=50 WHERE environment_id='10000000-0000-0000-0000-000000000002'",
        ] {
            sqlx::raw_sql("BEGIN").execute(&mut f.owner).await?;
            sqlx::raw_sql(mutation).execute(&mut f.owner).await?;
            let refused = restart(&mut f.owner, &primary(true), &token(true)).await.is_err();
            sqlx::raw_sql("ROLLBACK").execute(&mut f.owner).await?;
            anyhow::ensure!(refused, "incomplete/regressed child inventory accepted");
        }
        sqlx::raw_sql("BEGIN").execute(runtime.connection.as_mut().unwrap()).await?;
        restart(runtime.connection.as_mut().unwrap(), &primary(true), &token(true)).await?;
        sqlx::raw_sql("ROLLBACK").execute(runtime.connection.as_mut().unwrap()).await?;
        anyhow::ensure!(before == snapshot(&mut f).await?, "aborted restart mutated state");
        restart(runtime.connection.as_mut().unwrap(), &primary(true), &token(true)).await?;
        let after = snapshot(&mut f).await?;
        anyhow::ensure!(after["deployment_store_restarts"].as_array().unwrap().len() == 1);
        anyhow::ensure!(after["deployment_store_restarts"][0]["previous_checkpoints"] == json!({
            "parent":before["deployment_store_checkpoints"][0],"children":before["store_checkpoints"]
        }), "restart did not retain exact prior checkpoints");
        anyhow::ensure!(after["store_checkpoints"].as_array().unwrap().len() == 2);
        for table in ["deployment_store_checkpoints", "store_checkpoints"] {
            for checkpoint in after[table].as_array().unwrap() {
                anyhow::ensure!(checkpoint["primary_incarnation"]["started_us"] == 2
                    && checkpoint["token_incarnation"] == token(true)
                    && checkpoint["wal_position"] == 40, "restart omitted a selected checkpoint");
            }
        }
        restart(runtime.connection.as_mut().unwrap(), &primary(true), &token(true)).await?;
        anyhow::ensure!(after == snapshot(&mut f).await?, "restart replay changed state");
        for query in [
            "SELECT * FROM organization_witness.deployment_store_seals",
            "SELECT * FROM organization_witness.deployment_store_restarts",
            "SELECT * FROM organization_witness.deployment_store_completions",
            "SELECT organization_witness.deployment_store_seal_pin(NULL,NULL,NULL,NULL)",
        ] {
            anyhow::ensure!(sqlx::query(query).execute(runtime.connection.as_mut().unwrap()).await.is_err(), "runtime acquired raw/maintenance privileges");
        }
        runtime.close().await?;
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; observed completion and durable seal share one transaction"]
async fn pg_organizations_store_continuity_observed_release_requires_seal_completion() -> TestResult
{
    let mut f = Fixture::new().await?;
    let result = async {
        sqlx::raw_sql(SEED).execute(&mut f.owner).await?;
        let mut runtime = f.connect(Role::Runtime).await?;
        sqlx::query(ACQUIRE)
            .execute(runtime.connection.as_mut().unwrap())
            .await?;
        // Different session_user cannot finalize another principal's slot.
        anyhow::ensure!(sqlx::query(SEAL_LOCK).execute(&mut f.owner).await.is_err());
        sqlx::query(BEGIN_OBSERVATION)
            .execute(runtime.connection.as_mut().unwrap())
            .await?;
        anyhow::ensure!(
            sqlx::query(RELEASE)
                .execute(runtime.connection.as_mut().unwrap())
                .await
                .is_err(),
            "unfinished observation released"
        );
        let before = snapshot(&mut f).await?;
        sqlx::raw_sql("BEGIN")
            .execute(runtime.connection.as_mut().unwrap())
            .await?;
        finish_observation(runtime.connection.as_mut().unwrap()).await?;
        anyhow::ensure!(
            sqlx::query(RELEASE)
                .execute(runtime.connection.as_mut().unwrap())
                .await
                .is_err(),
            "observed work released without seal completion"
        );
        sqlx::raw_sql("ROLLBACK")
            .execute(runtime.connection.as_mut().unwrap())
            .await?;
        anyhow::ensure!(before == snapshot(&mut f).await?);
        for commit in [false, true] {
            sqlx::raw_sql("BEGIN")
                .execute(runtime.connection.as_mut().unwrap())
                .await?;
            sqlx::query(SEAL_LOCK)
                .execute(runtime.connection.as_mut().unwrap())
                .await?;
            finish_observation(runtime.connection.as_mut().unwrap()).await?;
            sqlx::query(ADVANCE)
                .execute(runtime.connection.as_mut().unwrap())
                .await?;
            sqlx::query(RELEASE)
                .execute(runtime.connection.as_mut().unwrap())
                .await?;
            sqlx::raw_sql(if commit { "COMMIT" } else { "ROLLBACK" })
                .execute(runtime.connection.as_mut().unwrap())
                .await?;
            if !commit {
                anyhow::ensure!(
                    before == snapshot(&mut f).await?,
                    "lost finalization transaction changed state"
                );
            }
        }
        let after = snapshot(&mut f).await?;
        anyhow::ensure!(after["deployment_store_seals"][0]["seal"] == id(0x21).to_string());
        anyhow::ensure!(after["deployment_store_completions"][0]["generation"] == 1);
        anyhow::ensure!(after["deployment_store_checkpoints"][0]["wal_position"] == 40);
        anyhow::ensure!(after["deployment_slots"]
            .as_array()
            .unwrap()
            .iter()
            .all(|slot| slot["pending"] == false));
        runtime.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; finalizers and restart serialize on the independent control row"]
async fn pg_organizations_store_continuity_serializes_finalization_and_restart() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        sqlx::raw_sql(SEED).execute(&mut f.owner).await?;
        let mut first = f.connect(Role::Runtime).await?;
        let mut second = f.connect(Role::Runtime).await?;
        sqlx::query(ACQUIRE).execute(first.connection.as_mut().unwrap()).await?;
        sqlx::raw_sql("BEGIN").execute(first.connection.as_mut().unwrap()).await?;
        sqlx::query(SEAL_LOCK).execute(first.connection.as_mut().unwrap()).await?;
        sqlx::raw_sql("SET lock_timeout='50ms'").execute(second.connection.as_mut().unwrap()).await?;
        let error = restart(second.connection.as_mut().unwrap(), &primary(true), &token(true)).await.unwrap_err();
        anyhow::ensure!(matches!(error, sqlx::Error::Database(ref error) if error.code().as_deref() == Some("55P03")), "restart did not block on finalizer lock");
        let error = sqlx::query(SEAL_LOCK).execute(second.connection.as_mut().unwrap()).await.unwrap_err();
        anyhow::ensure!(matches!(error, sqlx::Error::Database(ref error) if error.code().as_deref() == Some("55P03")), "second finalizer did not block");
        sqlx::raw_sql("ROLLBACK").execute(first.connection.as_mut().unwrap()).await?;
        sqlx::query(SEAL_LOCK).execute(second.connection.as_mut().unwrap()).await?;
        // The component started no observation or external effects.
        sqlx::query(RELEASE).execute(first.connection.as_mut().unwrap()).await?;
        first.close().await?;
        second.close().await?;
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}
