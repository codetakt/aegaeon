mod rollback;
use super::*;
use crate::authcode::code_store::{
    ParAuthorizationCodeCommit, RequestObjectJtiAuthorizationCodeCommit,
};
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};
use std::sync::Arc;
use uuid::Uuid;

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    name: String,
    database: PostgresGrantDatabase,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
            .await?;
        let name = format!("code_state_{}", Uuid::new_v4().simple());
        admin
            .execute(format!("CREATE DATABASE {name}").as_str())
            .await?;
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(admin.connect_options().as_ref().clone().database(&name))
            .await?;
        pool.execute("CREATE SCHEMA aegaeon").await?;
        sqlx::raw_sql(crate::organization_schema::component!("runtime_par"))
            .execute(&pool)
            .await?;
        sqlx::raw_sql(crate::organization_schema::component!(
            "runtime_authorization_codes"
        ))
        .execute(&pool)
        .await?;
        let database = PostgresGrantDatabase::new(
            pool.clone(),
            &crate::config::RuntimeStateNamespace::from_environment_id(Uuid::new_v4()),
        );
        Ok(Self {
            admin,
            pool,
            name,
            database,
        })
    }
    fn backend(&self) -> anyhow::Result<PostgresAuthCodeBackend> {
        Ok(PostgresAuthCodeBackend::new(
            self.database.clone(),
            Duration::from_secs(300),
        )?)
    }
    async fn finish(self) -> anyhow::Result<()> {
        self.pool.close().await;
        self.admin
            .execute(format!("DROP DATABASE {}", self.name).as_str())
            .await?;
        self.admin.close().await;
        Ok(())
    }
    fn jti(&self, value: &str) -> anyhow::Result<RequestObjectJtiAuthorizationCodeCommit> {
        let store = crate::request_object_store::RequestObjectJtiStore::from_postgres(
            300,
            self.database.clone(),
        )?;
        store
            .authorization_code_commit_context_for("client", value, Duration::from_secs(60))?
            .ok_or_else(|| anyhow::anyhow!("missing commit context"))
    }
    async fn par(&self) -> anyhow::Result<ParAuthorizationCodeCommit> {
        let store = Arc::new(crate::par::ParStore::from_postgres(
            60,
            self.database.clone(),
        )?);
        let metrics =
            aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?;
        let endpoint = crate::par::ParEndpoint::new(
            Arc::new(crate::metrics_integration::MetricsIntegration::new(
                Arc::new(metrics),
            )),
            store.clone(),
        );
        let request = serde_json::from_value(
            serde_json::json!({"client_id":"client","response_type":"code","redirect_uri":"https://client.example/cb", "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","dpop_jkt":null}),
        )?;
        let response = endpoint
            .handle_admitted_request(request, None)
            .await
            .map_err(|error| anyhow::anyhow!(error.error))?;
        let reserved = store
            .clone()
            .reserve_request_for_client_async(response.request_uri.clone(), "client".into())
            .await
            .map_err(|error| anyhow::anyhow!(error.error))?;
        store
            .authorization_code_commit_context(&response.request_uri, &reserved.continuation)
            .ok_or_else(|| anyhow::anyhow!("missing PAR context"))
    }
}
fn code() -> AuthorizationCode {
    crate::authcode::code_store::tests::sample_code(Some("shared-state"), Some("shared-nonce"))
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; atomic PAR/code publication and exact reservation binding"]
async fn pg_code_par_atomic_issue_and_binding() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let backend = Arc::new(fixture.backend()?);
        let par = fixture.par().await?;
        let inputs = AuthorizationCodeOneTimeInputCommit { par: Some(par.clone()), request_object_jti: None };
        let mut wrong = par;
        if let ParAuthorizationCodeCommit::Postgres { expected_continuation, .. } = &mut wrong { *expected_continuation="x".repeat(43); }
        anyhow::ensure!(matches!(backend.issue(code(), AuthorizationCodeOneTimeInputCommit { par: Some(wrong), request_object_jti: None }).await, Err(StoreCodeError::PushedAuthorizationRequestMissing)));
        let mut wrong_client = code(); wrong_client.client_id="other".into();
        anyhow::ensure!(matches!(backend.issue(wrong_client, inputs.clone()).await, Err(StoreCodeError::PushedAuthorizationRequestMissing)));
        let other_database = PostgresGrantDatabase::new(fixture.pool.clone(), &crate::config::RuntimeStateNamespace::from_environment_id(Uuid::new_v4()));
        let foreign = PostgresAuthCodeBackend::new(other_database, Duration::from_secs(300))?;
        anyhow::ensure!(foreign.issue(code(),inputs.clone()).await.is_err());
        let original: String = sqlx::query_scalar("SELECT payload FROM aegaeon.runtime_par_requests").fetch_one(&fixture.pool).await?;
        sqlx::query("UPDATE aegaeon.runtime_par_requests SET payload=payload||' '").execute(&fixture.pool).await?;
        anyhow::ensure!(matches!(backend.issue(code(),inputs.clone()).await,Err(StoreCodeError::PushedAuthorizationRequestMissing)));
        sqlx::query("UPDATE aegaeon.runtime_par_requests SET payload=$1").bind(original).execute(&fixture.pool).await?;
        let mut jobs=tokio::task::JoinSet::new();
        for _ in 0..32 { let backend=backend.clone();let inputs=inputs.clone();jobs.spawn(async move{ backend.issue(code(),inputs).await }); }
        let mut winners=0;
        while let Some(result)=jobs.join_next().await { match result? { Ok(_) => winners+=1, Err(StoreCodeError::PushedAuthorizationRequestMissing)=>{}, Err(error)=>return Err(error.into()) } }
        anyhow::ensure!(winners==1);
        let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.runtime_par_requests),(SELECT count(*) FROM aegaeon.runtime_authorization_codes),(SELECT count(*) FROM aegaeon.runtime_authorization_observations)").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(counts==(0,1,2));
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; JAR collision rollback, repeated state/nonce and single code consume"]
async fn pg_code_jar_collision_rollback_and_single_consume() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let backend = Arc::new(fixture.backend()?);
        let first = code();
        backend
            .issue(
                first.clone(),
                AuthorizationCodeOneTimeInputCommit::default(),
            )
            .await?;
        let inputs = AuthorizationCodeOneTimeInputCommit {
            par: None,
            request_object_jti: Some(fixture.jti("one-time-jti")?),
        };
        anyhow::ensure!(matches!(
            backend.issue(first.clone(), inputs.clone()).await,
            Err(StoreCodeError::CodeCollision)
        ));
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_request_object_jtis")
                .fetch_one(&fixture.pool)
                .await?;
        anyhow::ensure!(count == 0);
        let mut wrong_client = code();
        wrong_client.client_id = "other-client".into();
        anyhow::ensure!(matches!(
            backend.issue(wrong_client, inputs.clone()).await,
            Err(StoreCodeError::Storage(_))
        ));
        let second = code();
        backend.issue(second.clone(), inputs.clone()).await?;
        anyhow::ensure!(matches!(
            backend.issue(code(), inputs).await,
            Err(StoreCodeError::RequestObjectJtiReplay)
        ));
        let observation_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_authorization_observations")
                .fetch_one(&fixture.pool)
                .await?;
        anyhow::ensure!(observation_count == 2);
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let backend = backend.clone();
            let code = second.code.clone();
            jobs.spawn(async move { backend.consume(&code).await });
        }
        let mut winners = 0;
        while let Some(result) = jobs.join_next().await {
            winners += usize::from(result??.is_some());
        }
        anyhow::ensure!(winners == 1);
        sqlx::query("UPDATE aegaeon.runtime_authorization_codes SET client_digest=$1")
            .bind(vec![0u8; 32])
            .execute(&fixture.pool)
            .await?;
        anyhow::ensure!(backend.read(&first.code).await.is_err());
        let facade = crate::authcode::AuthCodeStore::from_postgres(
            fixture.database.clone(),
            Duration::from_secs(300),
        )
        .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(facade.try_get_code(&first.code).is_err());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}
