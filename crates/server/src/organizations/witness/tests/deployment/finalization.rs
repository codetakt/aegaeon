//! Actual finalizer faults after data-store writes, and serialized completions.
use super::*;
mod commit_loss;
use crate::organizations::store_observation::{Postgres, Redis};
use redis::aio::MultiplexedConnection;
use serde_json::Value;

const MARKER: &str = "aegaeon:organization-store-continuity:v1";

async fn token_connection(client: &redis::Client) -> anyhow::Result<MultiplexedConnection> {
    let config = redis::AsyncConnectionConfig::new()
        .set_connection_timeout(Duration::from_secs(3))
        .set_response_timeout(Duration::from_secs(3));
    let mut connection = client
        .get_multiplexed_async_connection_with_config(&config)
        .await?;
    redis::cmd("SELECT")
        .arg(0)
        .query_async::<()>(&mut connection)
        .await?;
    Ok(connection)
}

async fn restricted_links(
    f: &Fixture,
    client: &redis::Client,
) -> anyhow::Result<(Postgres, Redis)> {
    let primary = Postgres::observe(
        PgConnection::connect_with(
            &f.options
                .clone()
                .username(&f.runtime)
                .password(&f.runtime_password)
                .application_name("aegaeon-finalization-test"),
        )
        .await?,
    )
    .await?;
    Ok((
        primary,
        Redis::observe(token_connection(client).await?).await?,
    ))
}

async fn control_snapshot(f: &mut Fixture, deployment: DeploymentId) -> anyhow::Result<Value> {
    let mut snapshot = serde_json::Map::new();
    for table in [
        "deployments",
        "deployment_store_seals",
        "deployment_store_checkpoints",
        "deployment_slots",
        "deployment_store_observations",
        "deployment_store_completions",
    ] {
        let rows: Value = sqlx::query_scalar(&format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) \
             FROM organization_witness.{table} r WHERE deployment_id=$1"
        ))
        .bind(deployment.uuid())
        .fetch_one(&mut f.owner)
        .await?;
        snapshot.insert(table.into(), rows);
    }
    Ok(Value::Object(snapshot))
}

async fn completion_counts(
    f: &mut Fixture,
    deployment: DeploymentId,
) -> anyhow::Result<(i64, i64, i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM organization_witness.deployment_slots WHERE deployment_id=$1 AND pending), \
         (SELECT count(*) FROM organization_witness.deployment_store_observations WHERE deployment_id=$1 AND finished_wal IS NOT NULL), \
         (SELECT count(*) FROM organization_witness.deployment_store_observations WHERE deployment_id=$1 AND finished_wal IS NULL), \
         (SELECT count(*) FROM organization_witness.deployment_store_completions WHERE deployment_id=$1)",
    )
    .bind(deployment.uuid())
    .fetch_one(&mut f.owner)
    .await?)
}

async fn primary_seal(f: &mut Fixture, deployment: DeploymentId) -> anyhow::Result<Uuid> {
    let seal: Option<Uuid> =
        sqlx::query_scalar("SELECT aegaeon.organization_store_continuity_read_v1($1)")
            .bind(deployment.uuid())
            .fetch_one(&mut f.owner)
            .await?;
    seal.ok_or_else(|| anyhow::anyhow!("actual primary seal missing"))
}

async fn token_seal(
    connection: &mut MultiplexedConnection,
    deployment: DeploymentId,
) -> anyhow::Result<Uuid> {
    let marker: String = redis::cmd("GET")
        .arg(MARKER)
        .query_async(connection)
        .await?;
    let (_, seal) = marker
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("actual token seal malformed"))?;
    let seal = Uuid::parse_str(seal)?;
    anyhow::ensure!(marker == format!("{}:{seal}", deployment.uuid()) && !seal.is_nil());
    Ok(seal)
}

async fn token_failure(denied: &str) -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (maintenance, deployment, selected, _, _) = setup(&mut f).await?;
        let endpoint = std::env::var("AEGAEON_TEST_REDIS_URL")?;
        let admin = redis::Client::open(endpoint.as_str())?;
        let mut connection = token_connection(&admin).await?;
        let user = format!("finalizer-permission-{}", Uuid::new_v4());
        let password = Uuid::new_v4().to_string();
        let mut url = url::Url::parse(&endpoint)?;
        url.set_username(&user)
            .map_err(|()| anyhow::anyhow!("fixture username"))?;
        url.set_password(Some(&password))
            .map_err(|()| anyhow::anyhow!("fixture password"))?;
        let restricted = redis::Client::open(url.as_str())?;
        let result: TestResult = async {
            redis::cmd("ACL")
                .arg("SETUSER")
                .arg(&user)
                .arg("on")
                .arg(format!(">{password}"))
                .arg(format!("~{MARKER}"))
                .arg("+@all")
                .arg(denied)
                .query_async::<()>(&mut connection)
                .await?;
            let control = connect(&f, Role::Runtime).await?;
            let parent = Work::begin(
                control,
                request_work::Admission::isolated_for_test()?,
                deployment,
                &selected,
                || async {
                    restricted_links(&f, &restricted)
                        .await
                        .map_err(|_| Error::Refused)
                },
            )
            .await?;
            let before = control_snapshot(&mut f, deployment).await?;
            let old = primary_seal(&mut f, deployment).await?;
            anyhow::ensure!(token_seal(&mut connection, deployment).await? == old);
            anyhow::ensure!(completion_counts(&mut f, deployment).await? == (1, 0, 1, 0));
            let probe = parent.admission().closure_probe_for_test();
            let completed = parent.complete().await;
            let primary = primary_seal(&mut f, deployment).await?;
            let token = token_seal(&mut connection, deployment).await?;
            anyhow::ensure!(
                matches!(completed, Err(Error::StoreContinuityMismatch)) && probe.is_closed()
            );
            anyhow::ensure!(primary != old, "fault must follow the actual primary write");
            anyhow::ensure!(
                token == if denied == "-set" { old } else { primary },
                "SET refusal preserves the old token seal; ACK refusal follows its write"
            );
            anyhow::ensure!(control_snapshot(&mut f, deployment).await? == before);
            anyhow::ensure!(completion_counts(&mut f, deployment).await? == (1, 0, 1, 0));
            Ok(())
        }
        .await;
        // The unique user is removed even when a fault assertion fails. Never
        // change the shared/default user's permissions to inject this failure.
        let remove_user = redis::cmd("ACL")
            .arg("DELUSER")
            .arg(&user)
            .query_async::<u64>(&mut connection)
            .await;
        drop(connection);
        let close = maintenance.close().await;
        result?;
        remove_user?;
        close?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis ACL/AOF; actual partial seal writes retain pending work"]
async fn shared_redis_organizations_deployment_finalizer_token_write_and_ack_refusals() -> TestResult
{
    // Separate disposable control databases and distinct ACL users. The first
    // refusal intentionally leaves different seals in the two actual stores.
    for denied in ["-set", "-waitaof"] {
        token_failure(denied).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis AOF; actual data writes survive a rolled-back control finalization"]
async fn shared_redis_organizations_deployment_finalizer_control_rollback_retains_pending(
) -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (maintenance, deployment, selected, _, _) = setup(&mut f).await?;
        let parent = begin(&mut f, deployment, &selected).await?;
        let before = control_snapshot(&mut f, deployment).await?;
        let old = primary_seal(&mut f, deployment).await?;
        let admin = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let mut connection = token_connection(&admin).await?;
        anyhow::ensure!(token_seal(&mut connection, deployment).await? == old);
        anyhow::ensure!(completion_counts(&mut f, deployment).await? == (1, 0, 1, 0));
        // Catalog checking and Work::begin must finish before adding this
        // fixture-only trigger; otherwise construction would reject its schema.
        sqlx::raw_sql(
            "CREATE FUNCTION organization_witness.test_finalizer_fault() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected finalizer control failure'; END $$; \
             CREATE TRIGGER test_finalizer_fault BEFORE UPDATE ON organization_witness.deployment_store_seals \
             FOR EACH ROW EXECUTE FUNCTION organization_witness.test_finalizer_fault()",
        )
        .execute(&mut f.owner)
        .await?;
        let probe = parent.admission().closure_probe_for_test();
        let completed = parent.complete().await;
        let remove_trigger = sqlx::raw_sql(
            "DROP TRIGGER test_finalizer_fault ON organization_witness.deployment_store_seals; \
             DROP FUNCTION organization_witness.test_finalizer_fault()",
        )
        .execute(&mut f.owner)
        .await;
        let primary = primary_seal(&mut f, deployment).await?;
        let token = token_seal(&mut connection, deployment).await?;
        anyhow::ensure!(
            matches!(&completed, Err(Error::Storage(sqlx::Error::Database(error)))
                if error.message() == "injected finalizer control failure")
                && probe.is_closed()
        );
        anyhow::ensure!(primary != old && token == primary);
        anyhow::ensure!(control_snapshot(&mut f, deployment).await? == before);
        anyhow::ensure!(completion_counts(&mut f, deployment).await? == (1, 0, 1, 0));
        remove_trigger?;
        drop(connection);
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis AOF; real concurrent finalizers serialize seal compare-and-swap"]
async fn shared_redis_organizations_deployment_finalizers_serialize_actual_seals() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut maintenance, deployment, selected, _, _) = setup(&mut f).await?;
        // Both durable admissions precede the blocker. Acquisition itself takes
        // the deployment row lock and must not be mistaken for finalization.
        let first = begin(&mut f, deployment, &selected).await?;
        let second = begin(&mut f, deployment, &selected).await?;
        let first_probe = first.admission().closure_probe_for_test();
        let second_probe = second.admission().closure_probe_for_test();
        let mut blocker = PgConnection::connect_with(&f.options).await?;
        sqlx::query("BEGIN").execute(&mut blocker).await?;
        let _: Uuid = sqlx::query_scalar(
            "SELECT deployment_id FROM organization_witness.deployments WHERE deployment_id=$1 FOR UPDATE",
        )
        .bind(deployment.uuid())
        .fetch_one(&mut blocker)
        .await?;
        let mut first = tokio::spawn(first.complete());
        let mut second = tokio::spawn(second.complete());
        let waiters = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let count: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 \
                     AND wait_event_type='Lock' AND query LIKE '%organization_witness.deployment_store_seal_lock%'",
                )
                .bind(&f.runtime)
                .fetch_one(&mut f.owner)
                .await?;
                if count == 2 {
                    return Ok::<(), sqlx::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        // Always unblock and drain both tasks before evaluating the waiter
        // evidence, including SQL errors or an elapsed observation deadline.
        let release = sqlx::query("ROLLBACK").execute(&mut blocker).await;
        let close = blocker.close().await;
        let completed = tokio::time::timeout(Duration::from_secs(35), async {
            tokio::join!(&mut first, &mut second)
        })
        .await;
        if completed.is_err() {
            first.abort();
            second.abort();
            let _ = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(first, second)
            })
            .await;
        }
        release?;
        close?;
        waiters??;
        let (first, second) = completed?;
        let first = first??;
        let second = second??;
        let mut returned_pending = [first.pending, second.pending];
        returned_pending.sort_unstable();
        anyhow::ensure!(returned_pending == [0, 1]);
        anyhow::ensure!(
            !first_probe.is_closed()
                && first_probe.available_permits() == 1
                && !second_probe.is_closed()
                && second_probe.available_permits() == 1
        );
        anyhow::ensure!(maintenance.pending(deployment).await?.state.pending == 0);
        anyhow::ensure!(completion_counts(&mut f, deployment).await? == (0, 2, 0, 2));
        let primary = primary_seal(&mut f, deployment).await?;
        let admin = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let mut connection = token_connection(&admin).await?;
        anyhow::ensure!(token_seal(&mut connection, deployment).await? == primary);
        let control: Uuid = sqlx::query_scalar(
            "SELECT seal FROM organization_witness.deployment_store_seals WHERE deployment_id=$1 AND epoch=$2",
        )
        .bind(deployment.uuid())
        .bind(selected.epoch)
        .fetch_one(&mut f.owner)
        .await?;
        anyhow::ensure!(control == primary);
        drop(connection);
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}
