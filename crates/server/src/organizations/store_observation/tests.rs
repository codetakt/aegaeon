use super::*;
use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;

struct Fixture {
    admin: PgConnection,
    options: sqlx::postgres::PgConnectOptions,
    databases: [String; 2],
    login: String,
    password: String,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let options: sqlx::postgres::PgConnectOptions =
            std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?.parse()?;
        let mut admin = PgConnection::connect_with(&options).await?;
        let id = Uuid::new_v4().simple().to_string();
        let login = format!("observation_{id}");
        let password = Uuid::new_v4().simple().to_string();
        admin
            .execute(format!("CREATE ROLE {login} LOGIN NOINHERIT PASSWORD '{password}'").as_str())
            .await?;
        let databases = [format!("observation_a_{id}"), format!("observation_b_{id}")];
        for database in &databases {
            admin
                .execute(format!("CREATE DATABASE {database}").as_str())
                .await?;
            let mut scoped =
                PgConnection::connect_with(&options.clone().database(database)).await?;
            scoped
                .execute("REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC")
                .await?;
            scoped.close().await?;
        }
        Ok(Self {
            admin,
            options,
            databases,
            login,
            password,
        })
    }
    async fn connect(&self, database: usize) -> anyhow::Result<PgConnection> {
        Ok(PgConnection::connect_with(
            &self
                .options
                .clone()
                .database(&self.databases[database])
                .username(&self.login)
                .password(&self.password),
        )
        .await?)
    }
    async fn privilege(&self, database: usize, grant: bool) -> anyhow::Result<()> {
        let mut admin =
            PgConnection::connect_with(&self.options.clone().database(&self.databases[database]))
                .await?;
        let command = if grant { "GRANT" } else { "REVOKE" };
        let relation = if grant { "TO" } else { "FROM" };
        admin
            .execute(
                format!(
                    "{command} EXECUTE ON FUNCTION pg_catalog.pg_control_system() {relation} {}",
                    self.login
                )
                .as_str(),
            )
            .await?;
        admin.close().await?;
        Ok(())
    }
    async fn finish(mut self) -> anyhow::Result<()> {
        for database in &self.databases {
            tokio::time::timeout(DEADLINE, async {
                loop {
                    let count: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname=$1",
                    )
                    .bind(database)
                    .fetch_one(&mut self.admin)
                    .await?;
                    if count == 0 {
                        return Ok::<_, sqlx::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await??;
            self.admin
                .execute(format!("DROP DATABASE {database}").as_str())
                .await?;
        }
        self.admin
            .execute(format!("DROP ROLE {}", self.login).as_str())
            .await?;
        self.admin.close().await?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL administrator; owns databases and least-privilege login"]
async fn pg_store_observation_rejects_foreign_database_and_lost_privilege() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = primary_scope(&f).await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}
async fn primary_scope(f: &Fixture) -> anyhow::Result<()> {
    assert!(
        Postgres::observe(f.connect(0).await?).await.is_err(),
        "no implicit monitoring grant"
    );
    f.privilege(0, true).await?;
    f.privilege(1, true).await?;
    let mut unsafe_link = f.connect(0).await?;
    unsafe_link.execute("SET synchronous_commit=off").await?;
    assert!(Postgres::observe(unsafe_link).await.is_err());
    let mut first = Postgres::observe(f.connect(0).await?).await?;
    let expected = first.observation().clone();
    first.recheck(&expected).await?;
    let mut next = Postgres::observe(f.connect(0).await?).await?;
    next.recheck(&expected).await?;
    let mut foreign = Postgres::observe(f.connect(1).await?).await?;
    assert!(!foreign.observation().follows(&expected));
    assert!(
        !foreign.observation().different_cluster(&expected),
        "two databases are not independent clusters"
    );
    assert!(foreign.recheck(&expected).await.is_err());
    assert!(
        matches!(foreign.recheck(&expected).await, Err(Error::Refused)),
        "no last-known fallback"
    );
    foreign.close().await?;
    next.close().await?;
    f.privilege(0, false).await?;
    assert!(first.recheck(&expected).await.is_err());
    f.privilege(0, true).await?;
    assert!(
        matches!(first.recheck(&expected).await, Err(Error::Refused)),
        "grant recovery cannot reopen a discarded link"
    );
    first.close().await?;
    let mut recovered = Postgres::observe(f.connect(0).await?).await?;
    recovered.recheck(&expected).await?;
    recovered.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; terminates only its own observation backend"]
async fn pg_store_observation_discards_terminated_backend() -> anyhow::Result<()> {
    let mut f = Fixture::new().await?;
    let result = primary_failure(&mut f).await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}
async fn primary_failure(f: &mut Fixture) -> anyhow::Result<()> {
    f.privilege(0, true).await?;
    let mut connection = f.connect(0).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut connection)
        .await?;
    let mut observed = Postgres::observe(connection).await?;
    let expected = observed.observation().clone();
    let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1,1000)")
        .bind(pid)
        .fetch_one(&mut f.admin)
        .await?;
    assert!(killed);
    assert!(observed.recheck(&expected).await.is_err());
    assert!(matches!(
        observed.recheck(&expected).await,
        Err(Error::Refused)
    ));
    observed.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated Redis; observes actual SELECT and restricted ACL"]
async fn redis_store_observation_rejects_actual_database_change_and_acl_loss() -> anyhow::Result<()>
{
    let client = ::redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    let mut admin = client.get_multiplexed_async_connection().await?;
    let mut target = client.get_multiplexed_async_connection().await?;
    let _: () = ::redis::cmd("SELECT")
        .arg(3)
        .query_async(&mut target)
        .await?;
    let mut other_clone = target.clone();
    let mut observed = Redis::observe(target).await?;
    let expected = observed.observation().clone();
    observed.recheck(&expected).await?;
    let mut foreign = Redis::observe(client.get_multiplexed_async_connection().await?).await?;
    assert!(!foreign.observation().same_incarnation(&expected));
    assert!(foreign.recheck(&expected).await.is_err());
    foreign.close();
    // Deliberately violate exclusive custody to exercise actual server db state.
    // The connection's cached get_db() remains its URL value and is insufficient.
    let _: () = ::redis::cmd("SELECT")
        .arg(4)
        .query_async(&mut other_clone)
        .await?;
    assert!(observed.recheck(&expected).await.is_err());
    let _: () = ::redis::cmd("SELECT")
        .arg(3)
        .query_async(&mut other_clone)
        .await?;
    assert!(matches!(
        observed.recheck(&expected).await,
        Err(Error::Refused)
    ));
    observed.close();
    drop(other_clone);
    let login = format!("observation_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    let _: String = ::redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&login)
        .arg("on")
        .arg(format!(">{password}"))
        .arg("-@all")
        .arg("+ping")
        .arg("+info")
        .arg("+client|info")
        .query_async(&mut admin)
        .await?;
    let result = redis_acl(&client, &mut admin, &login, &password).await;
    let removed: i64 = ::redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&login)
        .query_async(&mut admin)
        .await?;
    assert_eq!(removed, 1);
    result
}

async fn redis_acl(
    client: &::redis::Client,
    admin: &mut ::redis::aio::MultiplexedConnection,
    login: &str,
    password: &str,
) -> anyhow::Result<()> {
    let mut connection = client.get_multiplexed_async_connection().await?;
    let _: String = ::redis::cmd("AUTH")
        .arg(login)
        .arg(password)
        .query_async(&mut connection)
        .await?;
    let mut observed = Redis::observe(connection).await?;
    let expected = observed.observation().clone();
    observed.recheck(&expected).await?;
    let _: String = ::redis::cmd("ACL")
        .arg("SETUSER")
        .arg(login)
        .arg("-info")
        .query_async(admin)
        .await?;
    assert!(observed.recheck(&expected).await.is_err());
    let _: String = ::redis::cmd("ACL")
        .arg("SETUSER")
        .arg(login)
        .arg("+info")
        .query_async(admin)
        .await?;
    assert!(matches!(
        observed.recheck(&expected).await,
        Err(Error::Refused)
    ));
    observed.close();
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated Redis; terminates only its own observation connection"]
async fn redis_store_observation_discards_terminated_connection() -> anyhow::Result<()> {
    let client = ::redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    let mut admin = client.get_multiplexed_async_connection().await?;
    let mut connection = client.get_multiplexed_async_connection().await?;
    let id: i64 = ::redis::cmd("CLIENT")
        .arg("ID")
        .query_async(&mut connection)
        .await?;
    let mut observed = Redis::observe(connection).await?;
    let expected = observed.observation().clone();
    let killed: i64 = ::redis::cmd("CLIENT")
        .arg("KILL")
        .arg("ID")
        .arg(id)
        .query_async(&mut admin)
        .await?;
    assert_eq!(killed, 1);
    assert!(observed.recheck(&expected).await.is_err());
    assert!(matches!(
        observed.recheck(&expected).await,
        Err(Error::Refused)
    ));
    observed.close();
    Ok(())
}
