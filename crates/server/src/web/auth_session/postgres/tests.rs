use super::*;
use crate::test_utils::postgres_cleanup::quote_database_identifier;
use sqlx::{postgres::PgPoolOptions, Executor};
use uuid::Uuid;
fn migration() -> &'static str {
    crate::organization_schema::component!("runtime_browser_sessions")
}
struct Fixture {
    admin: PgPool,
    pool: PgPool,
    database: String,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let database = format!("browser_session_{}", Uuid::new_v4().simple());
        Self::initialize(database, migration()).await
    }

    async fn initialize(database: String, migration_sql: &str) -> anyhow::Result<Self> {
        let options: sqlx::postgres::PgConnectOptions =
            std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?.parse()?;
        let options = options.application_name(&database);
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options.clone())
            .await?;
        let created = tokio::time::timeout(Duration::from_secs(5), async {
            admin
                .execute(
                    format!("CREATE DATABASE {}", quote_database_identifier(&database)).as_str(),
                )
                .await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r);
        if let Err(error) = created {
            // CREATE was not acknowledged: do not claim or remove an existing DB.
            let cleanup =
                crate::test_utils::postgres_cleanup::close_pool(&admin, Duration::from_secs(5))
                    .await;
            return preserve(Err(error), cleanup.map_err(Into::into));
        }
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(5))
            .connect_lazy_with(options.database(&database));
        let fixture = Self {
            admin,
            pool,
            database,
        };
        let initialized = tokio::time::timeout(Duration::from_secs(5), async {
            fixture.pool.execute("CREATE SCHEMA aegaeon").await?;
            sqlx::raw_sql(migration_sql).execute(&fixture.pool).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r);
        match initialized {
            Ok(()) => Ok(fixture),
            Err(error) => fixture.finish(Err(error)).await,
        }
    }

    async fn finish<T>(self, result: anyhow::Result<T>) -> anyhow::Result<T> {
        let cleanup = crate::test_utils::postgres_cleanup::finish_database(
            &self.admin,
            &self.pool,
            &self.database,
            Duration::from_secs(5),
        )
        .await;
        preserve(result, cleanup.map_err(Into::into))
    }
}

fn preserve<T>(result: anyhow::Result<T>, cleanup: anyhow::Result<()>) -> anyhow::Result<T> {
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => Err(error.context(format!(
            "additional browser fixture cleanup failure: {cleanup:#}"
        ))),
        (Err(error), Ok(())) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error),
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; initialization errors must remove the owned database"]
async fn pg_browser_fixture_initialization_failure_removes_database() -> anyhow::Result<()> {
    use sqlx::{Connection, PgConnection};
    let mut observer =
        PgConnection::connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?).await?;
    let database = format!("browser_session_{}", Uuid::new_v4().simple());
    let mut initialized_here = false;
    let result = async {
        let error =
            match Fixture::initialize(database.clone(), "SELECT missing_browser_fixture_column")
                .await
            {
                Err(error) => error,
                Ok(fixture) => {
                    return fixture
                        .finish(Err(anyhow::anyhow!("invalid migration succeeded")))
                        .await
                }
            };
        let Some(sqlx::Error::Database(cause)) = error.downcast_ref::<sqlx::Error>() else {
            anyhow::bail!("initialization error type was lost: {error:#}");
        };
        anyhow::ensure!(cause.code().as_deref() == Some("42703"));
        initialized_here = true;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let live: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE application_name=$1)",
                )
                .bind(&database)
                .fetch_one(&mut observer)
                .await?;
                if !live {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)")
                    .bind(&database)
                    .fetch_one(&mut observer)
                    .await?;
            anyhow::ensure!(
                !exists,
                "browser initialization failure leaked its database"
            );
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }
    .await;
    let cleanup = if initialized_here {
        tokio::time::timeout(Duration::from_secs(5), async {
            sqlx::query(&format!(
                "DROP DATABASE IF EXISTS {}",
                quote_database_identifier(&database)
            ))
            .execute(&mut observer)
            .await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r)
    } else {
        Ok(())
    };
    let close = tokio::time::timeout(Duration::from_secs(5), observer.close())
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r.map_err(Into::into));
    preserve(preserve(result, cleanup), close)
}

fn session(now: u64, subject: &str) -> AuthSession {
    AuthSession {
        user_id: subject.into(),
        created_at_epoch_secs: now,
        auth_time_epoch_secs: now - 10,
        expires_at_epoch_secs: now + 60,
        acr: Some("urn:example:acr".into()),
        original_authentication: None,
        claim_release_policy: None,
        upstream_logout: None,
    }
}
fn sid() -> String {
    Uuid::new_v4().to_string()
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; transactional counters and bounded bulk revocation"]
async fn pg_browser_counter_and_bulk_refusal_are_atomic() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        fixture.pool.execute("INSERT INTO aegaeon.runtime_browser_session_scopes(namespace) VALUES('bounded')").await?;
        fixture.pool.execute("INSERT INTO aegaeon.runtime_browser_sessions SELECT 'bounded',sha256(i::text::bytea),sha256('subject'::bytea),decode(repeat('00',65),'hex'),'{\"auth_time_epoch_secs\":0}',0,clock_timestamp()+interval '1 hour' FROM generate_series(1,4097) i").await?;
        let retained = || sqlx::query_scalar::<_, i64>("SELECT retained FROM aegaeon.runtime_browser_session_scopes WHERE namespace='bounded'").fetch_one(&fixture.pool);
        assert_eq!(retained().await?,4097);
        assert!(sqlx::query("SELECT aegaeon.delete_runtime_browser_sessions('bounded',NULL,sha256('subject'::bytea))").execute(&fixture.pool).await.is_err());
        assert_eq!(retained().await?,4097);
        let mut tx=fixture.pool.begin().await?;
        sqlx::query("SELECT aegaeon.delete_runtime_browser_sessions('bounded',sha256('1'::bytea),NULL)").execute(&mut *tx).await?;
        tx.rollback().await?;
        assert_eq!(retained().await?,4097);
        sqlx::query("SELECT aegaeon.delete_runtime_browser_sessions('bounded',sha256('1'::bytea),NULL)").execute(&fixture.pool).await?;
        assert_eq!(retained().await?,4096);
        let removed:i64=sqlx::query_scalar("SELECT aegaeon.delete_runtime_browser_sessions('bounded',NULL,sha256('subject'::bytea))").fetch_one(&fixture.pool).await?;
        assert_eq!(removed,4096);
        assert_eq!(retained().await?,0);
        Ok::<_,anyhow::Error>(())
    }.await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; shared browser identity, inventory and revocation"]
async fn pg_browser_sessions_shared_identity_inventory_and_revocation() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let a = PostgresAuthSessions::new(fixture.pool.clone(), "browser-tests".into(), [0x41; 32]);
        let b = PostgresAuthSessions::new(fixture.pool.clone(), "browser-tests".into(), [0x41; 32]);
        let foreign =
            PostgresAuthSessions::new(fixture.pool.clone(), "foreign-browser".into(), [0x41; 32]);
        let now = super::super::now_epoch_secs().map_err(anyhow::Error::msg)?;
        let mut value = session(now, "user-A");
        let facts = crate::organizations::authentication::OriginalAuthentication::fixture(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "user-A",
            i64::try_from(now - 10)?,
            i64::try_from(now)?,
        );
        value.original_authentication = Some(facts);
        let id = sid();
        a.create(&id, &value, 10)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(b.get(&id).await.map_err(anyhow::Error::msg)? == Some(value.clone()));
        anyhow::ensure!(
            b.list("user-A").await.map_err(anyhow::Error::msg)?
                == vec![(id.clone(), value.clone())]
        );
        anyhow::ensure!(b
            .list("user-B")
            .await
            .map_err(anyhow::Error::msg)?
            .is_empty());
        anyhow::ensure!(foreign
            .get(&id)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(
            foreign
                .delete(Some(&id), None)
                .await
                .map_err(anyhow::Error::msg)?
                == 0
        );
        anyhow::ensure!(
            b.delete(Some(&id), Some("user-B"))
                .await
                .map_err(anyhow::Error::msg)?
                == 0
        );
        let raw: (Vec<u8>, Vec<u8>, String) = sqlx::query_as(
            "SELECT token_digest,session_envelope,payload FROM aegaeon.runtime_browser_sessions",
        )
        .fetch_one(&fixture.pool)
        .await?;
        anyhow::ensure!(
            raw.0 == sha256_digest(id.as_bytes()) && raw.1.len() == 65 && !raw.2.contains(&id)
        );
        let mut locked = fixture.pool.begin().await?;
        sqlx::query("SELECT 1 FROM aegaeon.runtime_browser_session_scopes FOR UPDATE")
            .execute(&mut *locked)
            .await?;
        anyhow::ensure!(tokio::time::timeout(Duration::from_secs(1), b.get(&id))
            .await?
            .map_err(anyhow::Error::msg)?
            .is_some());
        locked.rollback().await?;
        anyhow::ensure!(
            b.delete(Some(&id), Some("user-A"))
                .await
                .map_err(anyhow::Error::msg)?
                == 1
        );
        anyhow::ensure!(a.get(&id).await.map_err(anyhow::Error::msg)?.is_none());
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let a = a.clone();
            let value = value.clone();
            jobs.spawn(async move { a.create(&sid(), &value, 4).await });
        }
        while let Some(result) = jobs.join_next().await {
            result?.map_err(anyhow::Error::msg)?;
        }
        anyhow::ensure!(b.list("user-A").await.map_err(anyhow::Error::msg)?.len() == 4);
        anyhow::ensure!(
            b.delete(None, Some("user-A"))
                .await
                .map_err(anyhow::Error::msg)?
                == 4
        );
        anyhow::ensure!(a
            .list("user-A")
            .await
            .map_err(anyhow::Error::msg)?
            .is_empty());
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; bound payload, corruption, expiry and unavailable storage"]
async fn pg_browser_sessions_corruption_and_expiry_fail_closed() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let backend=PostgresAuthSessions::new(fixture.pool.clone(),"browser-tests".into(),[0x41;32]);
        let now=super::super::now_epoch_secs().map_err(anyhow::Error::msg)?;
        let id=sid();let value=session(now,"user-A");backend.create(&id,&value,10).await.map_err(anyhow::Error::msg)?;
        let wrong_key=PostgresAuthSessions::new(fixture.pool.clone(),"browser-tests".into(),[0x42;32]);
        anyhow::ensure!(wrong_key.get(&id).await.is_err());
        let mut invalid=value.clone();invalid.auth_time_epoch_secs=now+1;
        anyhow::ensure!(backend.create(&sid(),&invalid,10).await.is_err());
        for update in [
            "UPDATE aegaeon.runtime_browser_sessions SET payload=jsonb_set(payload::jsonb,'{user_id}','\"user-B\"')::text",
            "UPDATE aegaeon.runtime_browser_sessions SET payload=jsonb_set(payload::jsonb,'{auth_time_epoch_secs}',to_jsonb(created_at_epoch_secs+1))::text",
            "UPDATE aegaeon.runtime_browser_sessions SET session_envelope=set_byte(session_envelope,14,get_byte(session_envelope,14)#1)",
            "UPDATE aegaeon.runtime_browser_sessions SET created_at_epoch_secs=created_at_epoch_secs-1",
        ] {
            let mut tx=fixture.pool.begin().await?;sqlx::query(update).execute(&mut *tx).await?;tx.commit().await?;
            anyhow::ensure!(backend.get(&id).await.is_err());anyhow::ensure!(backend.list("user-A").await.is_err());
            backend.delete(Some(&id),None).await.map_err(anyhow::Error::msg)?;
            backend.create(&id,&value,10).await.map_err(anyhow::Error::msg)?;
        }
        sqlx::query("UPDATE aegaeon.runtime_browser_sessions SET expires_at=clock_timestamp()-interval '1 second'").execute(&fixture.pool).await?;
        anyhow::ensure!(backend.get(&id).await.map_err(anyhow::Error::msg)?.is_none());
        backend.cleanup().await.map_err(anyhow::Error::msg)?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_browser_sessions").fetch_one(&fixture.pool).await?;anyhow::ensure!(count==0);
        sqlx::query("DROP TABLE aegaeon.runtime_browser_sessions").execute(&fixture.pool).await?;
        anyhow::ensure!(backend.get(&id).await.is_err());anyhow::ensure!(backend.create(&id,&value,10).await.is_err());
        anyhow::ensure!(backend.delete(Some(&id),None).await.is_err());anyhow::ensure!(backend.list("user-A").await.is_err());
        Ok(())
    }.await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; collision and failed insertion must not evict existing session"]
async fn pg_browser_sessions_collision_and_failed_insert_preserve_capacity() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let backend=PostgresAuthSessions::new(fixture.pool.clone(),"browser-tests".into(),[0x41;32]);
        let now=super::super::now_epoch_secs().map_err(anyhow::Error::msg)?;
        let id=sid();let value=session(now,"user-A");backend.create(&id,&value,1).await.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(backend.create(&id,&session(now,"user-B"),1).await.is_err());
        anyhow::ensure!(backend.get(&id).await.map_err(anyhow::Error::msg)?==Some(value.clone()));
        let failure=sqlx::query("SELECT aegaeon.create_runtime_browser_session('browser-tests',$1,$2,$3,'{}',$4,clock_timestamp()+interval '1 minute',1)")
            .bind(vec![1u8;32]).bind(vec![2u8;32]).bind(vec![0u8;64]).bind(i64::try_from(now)?).execute(&fixture.pool).await;
        anyhow::ensure!(failure.is_err());
        anyhow::ensure!(backend.get(&id).await.map_err(anyhow::Error::msg)?==Some(value.clone()));
        let mut tx=fixture.pool.begin().await?;
        sqlx::query("SELECT aegaeon.create_runtime_browser_session('browser-tests',$1,$2,$3,'{}',$4,clock_timestamp()+interval '1 minute',1)")
            .bind(vec![1u8;32]).bind(vec![2u8;32]).bind(vec![0u8;65]).bind(i64::try_from(now)?).execute(&mut *tx).await?;
        tx.rollback().await?;
        anyhow::ensure!(backend.get(&id).await.map_err(anyhow::Error::msg)?==Some(value));
        Ok(())
    }.await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; keyset pagination, direct revocation lookup and payload bounds"]
async fn pg_browser_sessions_bounded_inventory_and_direct_selector() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        use crate::web::auth_session::inventory::SessionCursor;
        let backend =
            PostgresAuthSessions::new(fixture.pool.clone(), "browser-tests".into(), [0x41; 32]);
        let now = super::super::now_epoch_secs().map_err(anyhow::Error::msg)?;
        let value = session(now, "user-A");
        let mut expected = std::collections::BTreeSet::new();
        for _ in 0..7 {
            let id = sid();
            backend
                .create(&id, &value, 10)
                .await
                .map_err(anyhow::Error::msg)?;
            expected.insert(id);
        }
        let first = backend
            .page("user-A", None, 2)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(first.sessions.len() == 2 && first.next.is_some());
        let first_id = first.sessions[0].0.clone();
        let digest = sha256_digest(first_id.as_bytes());
        anyhow::ensure!(
            backend
                .find("user-A", &digest)
                .await
                .map_err(anyhow::Error::msg)?
                == Some(first_id.clone())
        );
        anyhow::ensure!(backend
            .find("user-B", &digest)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        backend
            .delete(Some(&first_id), None)
            .await
            .map_err(anyhow::Error::msg)?;
        let mut seen = first
            .sessions
            .into_iter()
            .map(|(id, _)| id)
            .collect::<std::collections::BTreeSet<_>>();
        let mut cursor = first.next;
        for _ in 0..5 {
            let Some(current) = cursor else { break };
            let page = backend
                .page("user-A", Some(&current), 2)
                .await
                .map_err(anyhow::Error::msg)?;
            anyhow::ensure!(page.sessions.len() <= 2);
            for (id, _) in page.sessions {
                anyhow::ensure!(seen.insert(id));
            }
            cursor = page.next;
        }
        anyhow::ensure!(cursor.is_none() && seen == expected);
        anyhow::ensure!(backend
            .page("user-B", None, 2)
            .await
            .map_err(anyhow::Error::msg)?
            .sessions
            .is_empty());
        anyhow::ensure!(backend.page("user-A", None, 201).await.is_err());
        anyhow::ensure!(backend
            .page(
                "user-A",
                Some(&SessionCursor {
                    auth_time: -1,
                    digest: [0; 32]
                }),
                2
            )
            .await
            .is_err());
        let mut oversized = value;
        oversized.acr = Some("x".repeat(65536));
        anyhow::ensure!(backend.create(&sid(), &oversized, 1).await.is_err());
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_browser_sessions")
                .fetch_one(&fixture.pool)
                .await?;
        anyhow::ensure!(count == 6);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
