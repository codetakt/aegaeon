//! Actual signed assertions/JAR and HTTP refusal in the selected recovery runtime.
use super::*;
use crate::organizations::{
    lifecycle::{Limits, Runtime, Selection},
    request_work::CapacityClass,
};

#[tokio::test]
#[ignore = "requires PostgreSQL and legacy fixture Redis; actual current-runtime HTTP admission"]
async fn pg_recovery_external_proofs_return_temporary_http_refusal() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("database required")?;
    let env = setup_test_environment(&pool).await?;
    let admin = test_admin_pool(&pool).await?;
    let previous: Option<(Uuid, Uuid)> =
        sqlx::query_as("SELECT deployment_id,generation FROM aegaeon_lifecycle.current")
            .fetch_optional(&admin)
            .await?;
    let selected = Selection::new(previous.map_or_else(Uuid::new_v4, |x| x.0), Uuid::new_v4())?;
    sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4)")
        .bind(selected.deployment_id())
        .bind(previous.map(|x| x.1))
        .bind(selected.generation())
        .bind(Uuid::new_v4())
        .execute(&admin)
        .await?;
    let runtime = Runtime::checked(
        selected,
        sqlx::postgres::PgPoolOptions::new().max_connections(8),
        pool.connect_options().as_ref().clone(),
        vec![(env.environment_id, env.issuer_url.clone())],
        Limits {
            ordinary: 8,
            revocation: 2,
            snapshot: 1,
        },
    )
    .await?;
    let result = async {
        let mut state = fixture(runtime.pool(), &env).await?;
        let database = crate::authcode::store::PostgresGrantDatabase::new(
            runtime.pool().clone(),
            &selected.namespace(env.environment_id)?,
        );
        state.protocol.request_object_jti_store = Arc::new(
            crate::request_object_store::RequestObjectJtiStore::from_postgres(3600, database)?,
        );
        runtime
            .start(
                Some(env.environment_id),
                CapacityClass::Ordinary,
                move || async move {
                    let result: TestResult = async {
                        for path in PATHS {
                            let jwt = sign(&claims(&state, path)?)?;
                            let mut pairs = fields(path, &jwt);
                            if path == "/par" {
                                pairs.push(("iss", state.issuer.as_str()));
                            }
                            let (status, body) = send(&state, path, &pairs, None).await?;
                            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}: {body}");
                            assert_eq!(body["error"], "temporarily_unavailable");
                        }
                        let mut c = claims(&state, "/token")?;
                        c["iss"] = json!(BASIC);
                        c["sub"] = json!("form-user");
                        let jwt = sign(&c)?;
                        let (status, body) = send(
                            &state,
                            "/token",
                            &[
                                ("grant_type", crate::policy::JWT_BEARER_GRANT_TYPE),
                                ("assertion", &jwt),
                                ("scope", "api.read"),
                            ],
                            Some(&basic()),
                        )
                        .await?;
                        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
                        assert_eq!(body["error"], "temporarily_unavailable");
                        let request = par::request_object(&state, BASIC)?;
                        let (status, body) = send(
                            &state,
                            "/par",
                            &[
                                ("client_id", BASIC),
                                ("request", &request),
                                ("iss", state.issuer.as_str()),
                            ],
                            Some(&basic()),
                        )
                        .await?;
                        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
                        assert_eq!(body["error"], "temporarily_unavailable");
                        Ok(())
                    }
                    .await;
                    result.map_err(|e| e.to_string())
                },
            )?
            .result()
            .await?
            .map_err(Into::into)
    }
    .await;
    runtime.close().await;
    admin.close().await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
