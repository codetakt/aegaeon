use super::connection::load_upstream_connection;
use crate::upstream::UpstreamJitProvisioningCollisionPolicy;
use crate::web::test_support::{
    cleanup_test_environment, finish_test, setup_test_environment, test_app_state, test_pg_pool,
    TestResult,
};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    routing::get,
    Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL"]
async fn pg_jit_active_connection_and_authorize_preserve_policy_remediation() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let result: TestResult = async {
        let version: uuid::Uuid = sqlx::query_scalar(
            "SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1",
        )
        .bind(env.environment_id)
        .fetch_one(&pool)
        .await?;
        sqlx::query("INSERT INTO aegaeon.connections(environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_auth_method,status) VALUES($1,$2,'jit-policy','jit-policy','https://upstream.example','client','none','ACTIVE')")
            .bind(env.environment_id).bind(version).execute(&pool).await?;
        let state = test_app_state(pool.clone(), &env).await?;
        let app = Router::new()
            .route("/oauth/upstream/:connection/authorize", get(super::upstream_authorize))
            .with_state(state);
        for (policy, expected) in [
            (json!({"enabled":true,"collisionPolicy":"reuse_existing_email"}),
                UpstreamJitProvisioningCollisionPolicy::LEGACY_REUSE_REMEDIATION),
            (json!({"enabled":true,"collisionPolicy":17}),
                "configurationDocument.federation.jitProvisioning.collisionPolicy must be a non-empty string"),
        ] {
            // Simulate an already-active configuration installed by an older writer.
            sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document = jsonb_set(configuration_document, '{federation}', $2) WHERE id=$1")
                .bind(version).bind(json!({"jitProvisioning":policy})).execute(&pool).await?;
            let error = load_upstream_connection(&pool, &env.issuer_url, "jit-policy")
                .await.err().ok_or("invalid policy was loaded")?;
            assert_eq!(error, expected);
            let response = app.clone().oneshot(
                Request::builder()
                    .uri("/oauth/upstream/jit-policy/authorize")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 12345))))
                    .body(Body::empty())?,
            ).await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(response.headers().get(header::LOCATION).is_none());
            assert!(response.headers().get(header::SET_COOKIE).is_none());
            let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 16384).await?)?;
            assert_eq!(body["error"], "invalid_request");
            assert_eq!(body["error_description"], expected);
            assert_eq!(body["iss"], env.issuer_url);
        }
        for enabled in [false, true] {
            let collision = if enabled { "reject_existing_email" } else { "reuse_existing_email" };
            sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document = jsonb_set(configuration_document, '{federation}', $2) WHERE id=$1")
                .bind(version).bind(json!({"jitProvisioning":{"enabled":enabled,"collisionPolicy":collision}})).execute(&pool).await?;
            let loaded = load_upstream_connection(&pool, &env.issuer_url, "jit-policy").await?;
            assert_eq!(loaded.jit_provisioning_policy.ok_or("policy missing")?.enabled, enabled);
        }
        let users: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.end_users WHERE environment_id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(users, 0);
        Ok(())
    }.await;
    sqlx::query("DELETE FROM aegaeon.connections WHERE environment_id=$1")
        .bind(env.environment_id)
        .execute(&pool)
        .await?;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
