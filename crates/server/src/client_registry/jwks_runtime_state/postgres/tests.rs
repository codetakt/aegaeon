use super::*;
use sqlx::{postgres::PgPoolOptions, Executor};
struct Fixture {
    admin: PgPool,
    pool: PgPool,
    name: String,
    state: PostgresJwksState,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
            .await?;
        let name = format!("jwks_state_{}", Uuid::new_v4().simple());
        admin
            .execute(format!("CREATE DATABASE {name}").as_str())
            .await?;
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect_with(admin.connect_options().as_ref().clone().database(&name))
            .await?;
        pool.execute("CREATE SCHEMA aegaeon").await?;
        sqlx::raw_sql(crate::organization_schema::component!(
            "runtime_jwks_admission"
        ))
        .execute(&pool)
        .await?;
        let state = PostgresJwksState::new(
            pool.clone(),
            &crate::config::RuntimeStateNamespace::from_environment_id(Uuid::new_v4()),
        );
        Ok(Self {
            admin,
            pool,
            name,
            state,
        })
    }
    async fn permit(&self) -> anyhow::Result<FetchPermit> {
        self.state
            .acquire("https://issuer.example/jwks", &JwksRuntimePolicy::default())
            .await
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("permit unavailable"))
    }
    async fn finish(self) -> anyhow::Result<()> {
        self.pool.close().await;
        self.admin
            .execute(format!("DROP DATABASE {}", self.name).as_str())
            .await?;
        self.admin.close().await;
        Ok(())
    }
}
fn keys(value: &str) -> AdmittedKeys {
    AdmittedKeys {
        fingerprints: HashMap::from([("kid".into(), value.into())]),
        body_digest: sha256_digest(value.as_bytes()),
    }
}
#[tokio::test]
#[ignore = "requires PostgreSQL; one fetch owner, retained kid binding and stale completion refusal"]
async fn pg_jwks_single_owner_binding_and_stale_completion() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let state = f.state.clone();
            jobs.spawn(async move {
                state
                    .acquire("https://issuer.example/jwks", &JwksRuntimePolicy::default())
                    .await
            });
        }
        let mut permits = Vec::new();
        let mut busy = 0;
        while let Some(r) = jobs.join_next().await {
            match r?.map_err(anyhow::Error::msg)? {
                Some(p) => permits.push(p),
                None => busy += 1,
            }
        }
        anyhow::ensure!(permits.len() == 1 && busy == 31);
        let first = permits
            .pop()
            .ok_or_else(|| anyhow::anyhow!("missing permit"))?;
        anyhow::ensure!(
            f.state
                .finish(&first, Some(&keys("first")))
                .await
                .map_err(anyhow::Error::msg)?
                == Completion::Admitted
        );
        let second = f.permit().await?;
        anyhow::ensure!(
            f.state.finish(&first, None).await.is_err(),
            "old owner cannot change successor circuit"
        );
        anyhow::ensure!(
            f.state
                .finish(&second, Some(&keys("changed")))
                .await
                .map_err(anyhow::Error::msg)?
                == Completion::ChangedKey
        );
        let raw: String = sqlx::query_scalar("SELECT bindings FROM aegaeon.runtime_jwks_bindings")
            .fetch_one(&f.pool)
            .await?;
        anyhow::ensure!(
            serde_json::from_str::<HashMap<String, String>>(&raw)? == keys("first").fingerprints
        );
        let third = f.permit().await?;
        anyhow::ensure!(
            f.state
                .finish(&third, Some(&keys("first")))
                .await
                .map_err(anyhow::Error::msg)?
                == Completion::Admitted
        );
        Ok(())
    }
    .await;
    f.finish().await?;
    result
}
#[tokio::test]
#[ignore = "requires PostgreSQL; accumulated failures, expired ownership and exactly one recovery probe"]
async fn pg_jwks_circuit_failures_and_expired_owner() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        for expected in 1..=3i64 {
            let permit = f.permit().await?;
            anyhow::ensure!(
                f.state
                    .finish(&permit, None)
                    .await
                    .map_err(anyhow::Error::msg)?
                    == Completion::Failed
            );
            let failures: i64 =
                sqlx::query_scalar("SELECT failures FROM aegaeon.runtime_jwks_fetches")
                    .fetch_one(&f.pool)
                    .await?;
            anyhow::ensure!(failures == expected);
        }
        anyhow::ensure!(f
            .state
            .acquire("https://issuer.example/jwks", &JwksRuntimePolicy::default())
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        sqlx::query("UPDATE aegaeon.runtime_jwks_fetches SET open_until_us=1")
            .execute(&f.pool)
            .await?;
        let probe = f.permit().await?;
        anyhow::ensure!(f
            .state
            .acquire("https://issuer.example/jwks", &JwksRuntimePolicy::default())
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        sqlx::query("UPDATE aegaeon.runtime_jwks_fetches SET lease_until_us=1")
            .execute(&f.pool)
            .await?;
        anyhow::ensure!(f.state.finish(&probe, Some(&keys("key"))).await.is_err());
        anyhow::ensure!(f
            .state
            .acquire("https://issuer.example/jwks", &JwksRuntimePolicy::default())
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        let failures: i64 = sqlx::query_scalar("SELECT failures FROM aegaeon.runtime_jwks_fetches")
            .fetch_one(&f.pool)
            .await?;
        anyhow::ensure!(failures == 4);
        sqlx::query("UPDATE aegaeon.runtime_jwks_fetches SET open_until_us=1")
            .execute(&f.pool)
            .await?;
        let final_probe = f.permit().await?;
        anyhow::ensure!(
            f.state
                .finish(&final_probe, Some(&keys("key")))
                .await
                .map_err(anyhow::Error::msg)?
                == Completion::Admitted
        );
        let row: (i64, Option<Uuid>, Option<i64>) =
            sqlx::query_as("SELECT failures,owner,open_until_us FROM aegaeon.runtime_jwks_fetches")
                .fetch_one(&f.pool)
                .await?;
        anyhow::ensure!(row == (0, None, None));
        Ok(())
    }
    .await;
    f.finish().await?;
    result
}
#[tokio::test]
#[ignore = "requires PostgreSQL; bounded binding growth, namespace identity and cleanup preserve live state"]
async fn pg_jwks_capacity_identity_and_cleanup() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result=async {
        let permit=f.permit().await?;
        let foreign=PostgresJwksState::new(f.pool.clone(),&crate::config::RuntimeStateNamespace::from_environment_id(Uuid::new_v4()));
        anyhow::ensure!(foreign.finish(&permit,Some(&keys("key"))).await.is_err());
        anyhow::ensure!(f.state.finish(&permit,Some(&keys(&"x".repeat(MAX_BINDING_BYTES)))).await.map_err(anyhow::Error::msg)?==Completion::Capacity);
        let permit=f.permit().await?;anyhow::ensure!(f.state.finish(&permit,Some(&keys("key"))).await.map_err(anyhow::Error::msg)?==Completion::Admitted);
        sqlx::query("INSERT INTO aegaeon.runtime_jwks_bindings(namespace,uri_digest,bindings,expires_us,body_digest,admission_expires_us) SELECT $1,decode(lpad(to_hex(n),64,'0'),'hex'),'{}',1,decode(lpad(to_hex(n),64,'0'),'hex'),1 FROM generate_series(1,8193) n").bind(f.state.namespace.as_ref()).execute(&f.pool).await?;
        f.state.cleanup().await.map_err(anyhow::Error::msg)?;
        let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.runtime_jwks_bindings),(SELECT count(*) FROM aegaeon.runtime_jwks_fetches)").fetch_one(&f.pool).await?;anyhow::ensure!(counts==(1,1));
        f.pool.close().await;anyhow::ensure!(f.state.acquire("https://issuer.example/other",&JwksRuntimePolicy::default()).await.is_err());
        Ok(())
    }.await;
    f.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; cached body needs positive current unexpired database authority"]
async fn pg_jwks_cached_body_requires_current_authority() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let uri = "https://issuer.example/jwks";
        let first = keys("first");
        anyhow::ensure!(!f
            .state
            .current_body(uri, &first.body_digest)
            .await
            .map_err(anyhow::Error::msg)?);
        let permit = f.permit().await?;
        f.state
            .finish(&permit, Some(&first))
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(f
            .state
            .current_body(uri, &first.body_digest)
            .await
            .map_err(anyhow::Error::msg)?);
        anyhow::ensure!(!f
            .state
            .current_body("https://issuer.example/other", &first.body_digest)
            .await
            .map_err(anyhow::Error::msg)?);
        let next = AdmittedKeys {
            fingerprints: HashMap::from([
                ("kid".into(), "first".into()),
                ("new".into(), "second".into()),
            ]),
            body_digest: sha256_digest(b"next-body"),
        };
        let permit = f.permit().await?;
        f.state
            .finish(&permit, Some(&next))
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(!f
            .state
            .current_body(uri, &first.body_digest)
            .await
            .map_err(anyhow::Error::msg)?);
        anyhow::ensure!(f
            .state
            .current_body(uri, &next.body_digest)
            .await
            .map_err(anyhow::Error::msg)?);
        sqlx::query("UPDATE aegaeon.runtime_jwks_bindings SET admission_expires_us=1")
            .execute(&f.pool)
            .await?;
        anyhow::ensure!(!f
            .state
            .current_body(uri, &next.body_digest)
            .await
            .map_err(anyhow::Error::msg)?);
        let permit = f.permit().await?;
        f.state
            .finish(&permit, Some(&next))
            .await
            .map_err(anyhow::Error::msg)?;
        sqlx::query("DELETE FROM aegaeon.runtime_jwks_bindings")
            .execute(&f.pool)
            .await?;
        anyhow::ensure!(!f
            .state
            .current_body(uri, &next.body_digest)
            .await
            .map_err(anyhow::Error::msg)?);
        Ok(())
    }
    .await;
    f.finish().await?;
    result
}
