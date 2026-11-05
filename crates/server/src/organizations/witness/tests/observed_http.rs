use super::*;
use crate::organizations::{request_work, witness::work::HttpExecution};
use axum::{
    body::{Body, Bytes},
    http::{Method, StatusCode},
    response::Response,
};
use http_body::Frame;
use sqlx::postgres::PgPoolOptions;

async fn setup(
    f: &mut Fixture,
) -> anyhow::Result<(deployment::Start, Control, Scope, sqlx::PgPool)> {
    let (parent_maintenance, deployment, selected, scope, child) = deployment::setup(f).await?;
    parent_maintenance.close().await?;
    let starter = deployment::Start::new(f, deployment, selected, scope, child)?;
    let maintenance = f.connect(Role::Maintenance).await?;
    f.owner
        .execute("CREATE TABLE public.observed_http_effects(value text NOT NULL)")
        .await?;
    f.owner
        .execute(
            format!(
                "GRANT INSERT,SELECT ON public.observed_http_effects TO {}",
                f.runtime
            )
            .as_str(),
        )
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(
            f.options
                .clone()
                .username(&f.runtime)
                .password(&f.runtime_password),
        )
        .await?;
    Ok((starter, maintenance, scope, pool))
}

fn start(
    starter: deployment::Start,
    snapshot: bool,
    operation: impl std::future::Future<Output = Response> + Send + 'static,
) -> HttpExecution {
    let class = if snapshot {
        request_work::CapacityClass::Snapshot
    } else {
        request_work::CapacityClass::Ordinary
    };
    HttpExecution::owned(
        starter,
        request_work::Admission::isolated_class_for_test(class).unwrap(),
        Method::GET,
        operation,
    )
}

async fn effects(pool: sqlx::PgPool, client: redis::Client, key: String) -> anyhow::Result<()> {
    let owner = request_work::async_store::current_owner()?;
    let mut connection = owner.connection(&pool).await?;
    sqlx::query("INSERT INTO public.observed_http_effects VALUES($1)")
        .bind(&key)
        .execute(connection.as_mut()?)
        .await?;
    connection.release().await;
    let reply: String = request_work::async_store::blocking(move || {
        redis::cmd("SET")
            .arg(key)
            .arg("written")
            .query(&mut crate::redis_io::connect(&client)?)
    })
    .await??;
    anyhow::ensure!(reply == "OK");
    Ok(())
}

async fn verify_effects(f: &mut Fixture, client: &redis::Client, key: &str) -> TestResult {
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.observed_http_effects WHERE value=$1")
            .bind(key)
            .fetch_one(&mut f.owner)
            .await?;
    anyhow::ensure!(count == 1);
    let mut connection = client.get_multiplexed_async_connection().await?;
    let value: String = redis::cmd("GET")
        .arg(key)
        .query_async(&mut connection)
        .await?;
    anyhow::ensure!(value == "written");
    redis::cmd("DEL")
        .arg(key)
        .query_async::<i64>(&mut connection)
        .await?;
    Ok(())
}
fn response(result: anyhow::Result<()>) -> Response {
    Response::builder()
        .status(if result.is_ok() {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        })
        .body(Body::from("completed"))
        .unwrap()
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; finite HTTP success follows actual committed stores"]
async fn shared_redis_organizations_observed_http_store_selection_normal() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (starter, mut maintenance, scope, pool) = setup(&mut f).await?;
        let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let key = format!("observed-http:{}", Uuid::new_v4());
        let (data_pool, data_client, data_key) = (pool.clone(), client.clone(), key.clone());
        let reply = start(starter, false, async move {
            response(effects(data_pool, data_client, data_key).await)
        })
        .response()
        .await?;
        anyhow::ensure!(reply.status() == StatusCode::OK);
        let bytes = axum::body::to_bytes(reply.into_body(), 1024).await?;
        anyhow::ensure!(bytes.as_ref() == b"completed");
        anyhow::ensure!(maintenance.current(scope).await?.pending == 0);
        anyhow::ensure!(super::observed_work::parent_pending(&f, scope).await? == 0);
        verify_effects(&mut f, &client, &key).await?;
        pool.close().await;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; observed HTTP cannot use a foreign token database"]
async fn shared_redis_organizations_observed_http_store_selection_wrong_redis() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (starter, mut maintenance, scope, pool) = setup(&mut f).await?;
        let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let mut info = client.get_connection_info().clone();
        info.redis.db = 1;
        let other = redis::Client::open(info)?;
        let reply = start(starter, false, async move {
            let result =
                request_work::async_store::blocking(move || -> redis::RedisResult<String> {
                    redis::cmd("PING").query(&mut crate::redis_io::connect(&other)?)
                })
                .await;
            response(
                result
                    .map_err(anyhow::Error::from)
                    .and_then(|r| r.map(|_| ()).map_err(anyhow::Error::from)),
            )
        })
        .response()
        .await;
        anyhow::ensure!(
            reply.is_err(),
            "HTTP reported completion using a foreign token database"
        );
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        anyhow::ensure!(super::observed_work::parent_pending(&f, scope).await? == 1);
        pool.close().await;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; committed effects cannot hide lost final observation"]
async fn shared_redis_organizations_observed_http_final_observer_loss_refuses_success() -> TestResult
{
    let mut f = Fixture::new().await?;
    let result = async {
        let (starter, mut maintenance, scope, pool) = setup(&mut f).await?;
        let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let key = format!("observed-http:{}", Uuid::new_v4());
        let (data_pool, data_client, data_key) = (pool.clone(), client.clone(), key.clone());
        let (options, runtime) = (f.options.clone(), f.runtime.clone());
        let reply = start(starter, false, async move {
            let result = async {
                effects(data_pool, data_client, data_key).await?;
                let mut fault = PgConnection::connect_with(&options).await?;
                let killed: Vec<bool> = sqlx::query_scalar("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND application_name='aegaeon-child-progress-test'")
                    .bind(runtime).fetch_all(&mut fault).await?;
                fault.close().await?;
                anyhow::ensure!(killed == vec![true]);
                Ok(())
            }.await;
            response(result)
        }).response().await;
        anyhow::ensure!(reply.is_err());
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        anyhow::ensure!(super::observed_work::parent_pending(&f, scope).await? == 1);
        verify_effects(&mut f, &client, &key).await?;
        pool.close().await; maintenance.close().await?;
        Ok(())
    }.await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; lazy HTTP body owns actual stores until terminal completion"]
async fn shared_redis_organizations_observed_http_stream_checks_lazy_stores() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (starter, mut maintenance, scope, pool) = setup(&mut f).await?;
        let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let key = format!("observed-http:{}", Uuid::new_v4());
        let (data_pool, data_client, data_key) = (pool.clone(), client.clone(), key.clone());
        let reply = start(starter, true, async move {
            Response::new(Body::new(super::http_execution::LazyBody(Some(Box::pin(
                async move {
                    effects(data_pool, data_client, data_key)
                        .await
                        .map_err(std::io::Error::other)?;
                    Ok(Frame::data(Bytes::from_static(b"streamed")))
                },
            )))))
        })
        .response()
        .await?;
        let bytes = axum::body::to_bytes(reply.into_body(), 1024).await?;
        anyhow::ensure!(bytes.as_ref() == b"streamed");
        anyhow::ensure!(maintenance.current(scope).await?.pending == 0);
        anyhow::ensure!(super::observed_work::parent_pending(&f, scope).await? == 0);
        verify_effects(&mut f, &client, &key).await?;
        pool.close().await;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; dropping HTTP response wait cannot cancel owned work"]
async fn shared_redis_organizations_observed_http_cancelled_response_retains_work() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (starter, mut maintenance, scope, pool) = setup(&mut f).await?;
        let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let key = format!("observed-http:{}", Uuid::new_v4());
        let (data_pool, data_client, data_key) = (pool.clone(), client.clone(), key.clone());
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, resumed) = tokio::sync::oneshot::channel();
        let execution = start(starter, false, async move {
            let result = effects(data_pool, data_client, data_key).await;
            let _ = entered.send(());
            let _ = resumed.await;
            response(result)
        });
        tokio::time::timeout(Duration::from_secs(5), waiting).await??;
        drop(execution);
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        anyhow::ensure!(super::observed_work::parent_pending(&f, scope).await? == 1);
        release
            .send(())
            .map_err(|_| anyhow::anyhow!("HTTP worker lost"))?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while maintenance.current(scope).await?.pending != 0
                || super::observed_work::parent_pending(&f, scope).await? != 0
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await??;
        verify_effects(&mut f, &client, &key).await?;
        pool.close().await;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}
