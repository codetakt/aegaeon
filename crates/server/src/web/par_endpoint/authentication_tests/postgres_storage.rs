use super::*;
use std::time::Duration;

async fn postgres_state(
    pool: &sqlx::PgPool,
    env: &super::super::super::test_support::TestEnvironment,
) -> TestResult<AppState> {
    let mut state = fixture(pool, env).await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(env.environment_id);
    let database =
        crate::authcode::store::PostgresGrantDatabase::new(state.db_pool.clone(), &namespace);
    let store = Arc::new(crate::par::ParStore::from_postgres(90, database.clone())?);
    state.protocol.request_object_jti_store =
        Arc::new(crate::request_object_store::RequestObjectJtiStore::from_postgres(300, database)?);
    let metrics = aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?;
    state.protocol.par_endpoint = Arc::new(crate::par::ParEndpoint::new(
        Arc::new(crate::metrics_integration::MetricsIntegration::new(
            Arc::new(metrics),
        )),
        store.clone(),
    ));
    state.protocol.par_store = store;
    Ok(state)
}

async fn signed_push(state: &AppState, jwt: &str) -> TestResult<(StatusCode, Value)> {
    let assertion = assertion(state)?;
    let fields = [
        ("client_id", "private_key_jwt"),
        ("request", jwt),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion.as_str()),
    ];
    let app = super::super::super::router::build_router(state.clone()).layer(Extension(
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))),
    ));
    let response = app
        .oneshot(
            Request::post("/par")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(serde_urlencoded::to_string(fields)?))?,
        )
        .await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    Ok((
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?,
    ))
}

#[tokio::test]
#[ignore = "requires PostgreSQL and shared Redis for remaining fixture stores; signed PAR and JAR commit atomically"]
async fn pg_par_signed_http_replay_publishes_one_request() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = postgres_state(&pool,&env).await?;
        let now = crate::util::now_unix_epoch_secs()?;
        let claims = json!({"iss":"private_key_jwt","aud":state.issuer.as_str(),"client_id":"private_key_jwt",
            "response_type":"code","redirect_uri":"https://client.example.com/callback","scope":"openid","state":"signed-par-state",
            "iat":now,"exp":now+60,"jti":Uuid::new_v4().to_string(),
            "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"});
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.typ = Some("oauth-authz-req+jwt".into());
        let jwt = jsonwebtoken::encode(&header, &claims, &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!("../../../../tests/fixtures/rsa2048-private.pk8.pem"))?)?;
        let (status,body) = signed_push(&state,&jwt).await?;
        assert_eq!(status,StatusCode::CREATED,"{body}");
        let uri=body["request_uri"].as_str().ok_or("request_uri missing")?.to_owned();
        let (status,body) = signed_push(&state,&jwt).await?;
        assert_eq!(status,StatusCode::BAD_REQUEST,"{body}");
        assert_eq!(body["error"],"invalid_request");
        let namespace=crate::config::RuntimeStateNamespace::from_environment_id(env.environment_id).flow_namespace("oauth","grant");
        let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.runtime_par_requests WHERE namespace=$1),(SELECT count(*) FROM aegaeon.runtime_request_object_jtis WHERE namespace=$1)").bind(namespace).fetch_one(&pool).await?;
        assert_eq!(counts,(1,1));
        let reserved=state.protocol.par_store.clone().reserve_request_for_client_async(uri,"private_key_jwt".into()).await.map_err(|error|std::io::Error::other(error.error))?;
        assert_eq!(reserved.request.state.as_deref(),Some("signed-par-state"));
        assert!(reserved.request.client_secret.is_none());
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and shared Redis for remaining fixture stores; native SQL PAR HTTP persistence"]
async fn pg_par_http_persistence_and_client_binding() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = postgres_state(&pool, &env).await?;
        let (status, body) = send(&state, "none", None, &[]).await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let uri = body["request_uri"]
            .as_str()
            .ok_or("request_uri missing")?
            .to_owned();
        assert!(state
            .protocol
            .par_store
            .clone()
            .reserve_request_for_client_async(uri.clone(), "wrong".into())
            .await
            .is_err());
        let request = state
            .protocol
            .par_store
            .clone()
            .reserve_request_for_client_async(uri, "none".into())
            .await
            .map_err(|error| std::io::Error::other(error.error))?;
        assert_eq!(request.request.state.as_deref(), Some("par-state"));
        assert!(request.request.client_secret.is_none());
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and shared Redis for remaining fixture stores; cancelled caller retains PAR worker slot"]
async fn pg_par_cancelled_caller_retains_worker_until_storage_finishes() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = postgres_state(&pool, &env).await?;
        let namespace = crate::config::RuntimeStateNamespace::from_environment_id(env.environment_id).flow_namespace("oauth", "grant");
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1)
            .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?).await?;
        let request: crate::par::ParRequest = serde_json::from_value(json!({
            "client_id":"none", "redirect_uri":"https://client.example.com/callback", "response_type":"code", "state":"cancelled-par",
            "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method":"S256", "dpop_jkt":null
        }))?;
        let mut tx = pool.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.runtime_par_requests IN ACCESS EXCLUSIVE MODE").execute(&mut *tx).await?;
        let caller = tokio::spawn(super::super::storage::persist(state, request));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT aegaeon.publish_runtime_par%')")
                    .bind(pool.connect_options().get_database()).fetch_one(&admin).await?;
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, sqlx::Error>(())
        }).await??;
        caller.abort();
        assert!(caller.await.is_err());
        assert!(super::super::storage::reserve_for_test().is_err());
        tx.commit().await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(permit) = super::super::storage::reserve_for_test() { drop(permit); break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_par_requests WHERE namespace=$1")
            .bind(namespace).fetch_one(&pool).await?;
        assert_eq!(count, 1);
        admin.close().await;
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
