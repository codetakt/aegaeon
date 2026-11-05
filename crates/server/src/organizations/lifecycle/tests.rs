use super::*;
use anyhow::Context;
use sqlx::{Connection, Executor};
mod close;
mod creation;
mod maintenance;
mod proofs;

async fn wait_runtime_release(pool: &PgPool) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            // Autocommit releases this probe's transaction lock before reply.
            // Socket close need not have reached PostgreSQL when pool.close returns.
            let released: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1,$2)")
                .bind(LOCK_DOMAIN)
                .bind(LOCK_KEY)
                .fetch_one(pool)
                .await?;
            if released {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("runtime SQL sessions did not release the generation fence")??;
    Ok(())
}

struct Fixture {
    admin: PgPool,
    database: PgPool,
    endpoint: PgConnectOptions,
    name: String,
    role: String,
    selected: Selection,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
            .await?;
        let suffix = Uuid::new_v4().simple().to_string();
        let name = format!("lifecycle_{suffix}");
        let role = format!("life_runtime_{suffix}");
        let password = Uuid::new_v4().simple().to_string();
        admin
            .execute(format!("CREATE DATABASE {name}").as_str())
            .await?;
        admin.execute(format!("CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}'").as_str()).await?;
        let options = admin.connect_options().as_ref().clone().database(&name);
        let database = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options.clone())
            .await?;
        sqlx::raw_sql(crate::organization_schema::component!("runtime_lifecycle"))
            .execute(&database)
            .await?;
        sqlx::raw_sql(&format!("GRANT USAGE ON SCHEMA aegaeon_lifecycle TO {role}; GRANT SELECT ON aegaeon_lifecycle.current TO {role};"))
            .execute(&database).await?;
        let selected = Selection::new(Uuid::new_v4(), Uuid::new_v4())?;
        let fixture = Self {
            admin,
            database,
            endpoint: options.username(&role).password(&password),
            name,
            role,
            selected,
        };
        fixture.activate(None, selected.generation).await?;
        Ok(fixture)
    }
    async fn activate(&self, previous: Option<Uuid>, next: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4)")
            .bind(self.selected.deployment)
            .bind(previous)
            .bind(next)
            .bind(Uuid::new_v4())
            .execute(&self.database)
            .await?;
        Ok(())
    }
    fn pool(&self, selection: Selection) -> PgPool {
        selection.pool(
            PgPoolOptions::new()
                .max_connections(2)
                .min_connections(0)
                .acquire_timeout(Duration::from_millis(350)),
            self.endpoint.clone(),
        )
    }
    async fn finish(self) -> anyhow::Result<()> {
        close_pool(&self.database).await;
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let closed: bool = sqlx::query_scalar(
                    "SELECT NOT EXISTS(SELECT FROM pg_stat_activity WHERE datname=$1)",
                )
                .bind(&self.name)
                .fetch_one(&self.admin)
                .await?;
                if closed {
                    return Ok::<_, sqlx::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("lifecycle fixture database sessions did not close")??;
        self.admin
            .execute(format!("DROP DATABASE {}", self.name).as_str())
            .await?;
        self.admin
            .execute(format!("DROP ROLE {}", self.role).as_str())
            .await?;
        close_pool(&self.admin).await;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_lifecycle_connections_fence_activation_and_old_reconnect() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let old = f.pool(f.selected);
    let mut first = old.acquire().await?;
    let second = old.acquire().await?;
    let next = Uuid::new_v4();
    assert!(matches!(f.activate(Some(f.selected.generation),next).await,
        Err(sqlx::Error::Database(e)) if e.code().as_deref()==Some("55006")));
    let mut tx = first.begin().await?;
    tx.execute("SELECT 1").await?;
    tx.rollback().await?;
    drop((first, second));
    // Even an idle pooled connection retains its shared fence across rollback.
    assert!(f.activate(Some(f.selected.generation), next).await.is_err());
    close_pool(&old).await;
    wait_runtime_release(&f.database).await?;
    f.activate(Some(f.selected.generation), next).await?;
    let stale = f.pool(f.selected);
    assert!(stale.acquire().await.is_err());
    close_pool(&stale).await;
    let current = f.pool(Selection::new(f.selected.deployment, next)?);
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&current)
            .await?,
        1
    );
    close_pool(&current).await;
    let (count,generation): (i64,Uuid) = sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon_lifecycle.activations),generation FROM aegaeon_lifecycle.current")
        .fetch_one(&f.database).await?;
    assert_eq!(count, 2);
    assert_eq!(generation, next);
    f.finish().await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_lifecycle_exclusive_activation_refuses_new_session_and_bad_predecessor(
) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let mut tx = f.database.begin().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1,$2)")
        .bind(LOCK_DOMAIN)
        .bind(LOCK_KEY)
        .fetch_one(&mut *tx)
        .await?;
    assert!(locked);
    let pool = f.pool(f.selected);
    assert!(pool.acquire().await.is_err());
    tx.rollback().await?;
    assert!(
        pool.acquire().await.is_ok(),
        "capacity recovers without changing selection"
    );
    close_pool(&pool).await;
    for previous in [None, Some(Uuid::new_v4())] {
        assert!(f.activate(previous, Uuid::new_v4()).await.is_err());
    }
    assert!(f
        .activate(Some(f.selected.generation), f.selected.generation)
        .await
        .is_err());
    let foreign = f.pool(Selection::new(Uuid::new_v4(), f.selected.generation)?);
    assert!(foreign.acquire().await.is_err());
    close_pool(&foreign).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM aegaeon_lifecycle.activations")
            .fetch_one(&f.database)
            .await?,
        1
    );
    f.finish().await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_lifecycle_refuses_runtime_activation_privilege_and_checks_replacement(
) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let pool = f.pool(f.selected);
    // Keep every privilege probe on the physical session we terminate. Pool
    // returns are asynchronous and sequential queries may otherwise use two
    // different sessions, leaving a legitimate shared fence alive.
    let mut connection = pool.acquire().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await?;
    assert!(
        sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4)")
            .bind(f.selected.deployment)
            .bind(f.selected.generation)
            .bind(Uuid::new_v4())
            .bind(Uuid::new_v4())
            .execute(&mut *connection)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE aegaeon_lifecycle.current SET generation=$1")
            .bind(Uuid::new_v4())
            .execute(&mut *connection)
            .await
            .is_err()
    );
    let stopped: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1,1000)")
        .bind(pid)
        .fetch_one(&f.database)
        .await?;
    assert!(stopped);
    drop(connection);
    let next = Uuid::new_v4();
    f.activate(Some(f.selected.generation), next).await?;
    assert!(
        pool.acquire().await.is_err(),
        "replacement physical connection cannot retain old authority"
    );
    close_pool(&pool).await;
    sqlx::query(&format!(
        "GRANT EXECUTE ON FUNCTION aegaeon_lifecycle.activate_v1(uuid,uuid,uuid,uuid,jsonb) TO {}",
        f.role
    ))
    .execute(&f.database)
    .await?;
    let overprivileged = f.pool(Selection::new(f.selected.deployment, next)?);
    assert!(overprivileged.acquire().await.is_err());
    close_pool(&overprivileged).await;
    f.finish().await
}

#[test]
fn lifecycle_selection_requires_nonzero_identifiers() {
    assert!(Selection::new(Uuid::nil(), Uuid::new_v4()).is_err());
    assert!(Selection::new(Uuid::new_v4(), Uuid::nil()).is_err());
}

#[test]
fn lifecycle_generation_separates_continuations_and_binding_formats() {
    let environment = Uuid::new_v4();
    let first = Selection::new(Uuid::new_v4(), Uuid::new_v4()).unwrap();
    let next = Selection::new(first.deployment, Uuid::new_v4()).unwrap();
    let a = first.namespace(environment).unwrap();
    let b = next.namespace(environment).unwrap();
    assert_ne!(
        a.flow_namespace("oauth", "grant"),
        b.flow_namespace("oauth", "grant")
    );
    assert_ne!(a.replay_namespace("proof"), b.replay_namespace("proof"));
    let binding =
        crate::organizations::witness::epoch::EpochBinding::current(environment, first).unwrap();
    let encoded = serde_json::to_value(&binding).unwrap();
    assert_eq!(encoded["version"], 2);
    assert!(encoded.get("token_store_id").is_none());
    let decoded: crate::organizations::witness::epoch::EpochBinding =
        serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(binding, decoded);
    let mut mixed = encoded;
    mixed["primary_id"] = serde_json::json!(Uuid::new_v4());
    assert!(
        serde_json::from_value::<crate::organizations::witness::epoch::EpochBinding>(mixed)
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL supplier"]
async fn pg_lifecycle_owned_runtime_bounds_work_and_isolates_request_failure() -> anyhow::Result<()>
{
    use crate::organizations::request_work::{async_store, CapacityClass};
    let f = Fixture::new().await?;
    let environment = Uuid::new_v4();
    let runtime = Runtime::checked(
        f.selected,
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(1)),
        f.endpoint.clone(),
        vec![(environment, "https://issuer.example/".into())],
        Limits {
            ordinary: 1,
            revocation: 1,
            snapshot: 1,
        },
    )
    .await?;
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let pool = runtime.pool.clone();
    let first = runtime.start(
        Some(environment),
        CapacityClass::Ordinary,
        move || async move {
            let owner = async_store::current_epoch_owner(environment).unwrap();
            let mut connection = owner.connection(&pool).await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i32>("SELECT 17")
                    .fetch_one(connection.as_mut().unwrap())
                    .await
                    .unwrap(),
                17
            );
            entered.send(()).unwrap();
            waiting.await.unwrap();
            connection.release().await;
        },
    )?;
    started.await?;
    assert!(runtime
        .start(Some(environment), CapacityClass::Ordinary, || async {})
        .is_err());
    let revocation_pool = runtime.pool().clone();
    runtime
        .start(
            Some(environment),
            CapacityClass::Revocation,
            move || async move {
                let owner = async_store::current_epoch_owner(environment).unwrap();
                let mut connection = owner.connection(&revocation_pool).await.unwrap();
                assert_eq!(
                    sqlx::query_scalar::<_, i32>("SELECT 23")
                        .fetch_one(connection.as_mut().unwrap())
                        .await
                        .unwrap(),
                    23,
                    "reserved SQL capacity works while every ordinary connection is held"
                );
                connection.release().await;
            },
        )?
        .result()
        .await?;
    release.send(()).unwrap();
    first.result().await?;
    let failed = runtime
        .start(Some(environment), CapacityClass::Ordinary, || async {
            async_store::current_owner().unwrap().close_until_restart();
        })?
        .result()
        .await;
    assert!(failed.is_err());
    let foreign = f.database.clone();
    runtime
        .start(
            Some(environment),
            CapacityClass::Ordinary,
            move || async move {
                assert!(async_store::current_owner()
                    .unwrap()
                    .connection(&foreign)
                    .await
                    .is_err());
            },
        )?
        .result()
        .await?;
    let dispatcher =
        crate::organizations::witness::deployment::dispatch::Dispatcher::current(runtime.clone());
    let dispatch = dispatcher.clone();
    let child_pool = runtime.pool().clone();
    runtime
        .start(None, CapacityClass::Ordinary, move || async move {
            assert!(dispatch
                .start_child_http(
                    Uuid::new_v4(),
                    axum::http::Method::POST,
                    crate::organizations::witness::work::ResponseLimit::Organization,
                    || async { axum::response::Response::new(axum::body::Body::empty()) }
                )
                .is_err());
            let child_dispatch = dispatch.clone();
            let child = dispatch
                .start_child_http(
                    environment,
                    axum::http::Method::POST,
                    crate::organizations::witness::work::ResponseLimit::Organization,
                    move || async move {
                        let owner = async_store::current_epoch_owner(environment).unwrap();
                        // A child cannot silently change to another Environment scope.
                        assert!(child_dispatch
                            .start_child_http(
                                environment,
                                axum::http::Method::POST,
                                crate::organizations::witness::work::ResponseLimit::Organization,
                                || async {
                                    axum::response::Response::new(axum::body::Body::empty())
                                }
                            )
                            .is_err());
                        let mut connection = owner.connection(&child_pool).await.unwrap();
                        sqlx::query("SELECT 1")
                            .execute(connection.as_mut().unwrap())
                            .await
                            .unwrap();
                        connection.release().await;
                        axum::response::Response::new(axum::body::Body::from("current child"))
                    },
                )
                .unwrap();
            let response = child.response().await.unwrap();
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 128)
                    .await
                    .unwrap(),
                "current child"
            );
            assert!(async_store::current_owner()
                .unwrap()
                .epoch_binding()
                .is_err());
        })?
        .result()
        .await?;
    runtime.close().await;
    assert!(runtime
        .start(Some(environment), CapacityClass::Ordinary, || async {})
        .is_err());
    f.finish().await
}
