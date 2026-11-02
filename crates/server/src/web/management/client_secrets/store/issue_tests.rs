use super::issue::insert_client_secret_row;
use crate::dcr_persistence::test_database::Database;
use crate::web::test_support::{sample_registered_client, setup_test_environment, TestResult};
use sqlx::PgPool;
use uuid::Uuid;

async fn issue(
    pool: &PgPool,
    environment: Uuid,
    client: Uuid,
    version: Uuid,
) -> Result<(), axum::response::Response> {
    let mut tx = pool.begin().await.expect("fixture transaction");
    // Same serialization as the management workflow. The production store chooses
    // the slot only after these locks; the unique index also protects direct writers.
    sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE")
        .bind(environment)
        .execute(&mut *tx)
        .await
        .expect("environment lock");
    sqlx::query("SELECT id FROM aegaeon.clients WHERE id=$1 FOR UPDATE")
        .bind(client)
        .execute(&mut *tx)
        .await
        .expect("client lock");
    insert_client_secret_row(
        &mut tx,
        environment,
        client,
        version,
        "test-only-unused-hash",
        1,
        "slots-test",
    )
    .await?;
    tx.commit().await.expect("fixture commit");
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; concurrent production store slot admission"]
async fn pg_client_secret_issuance_serializes_last_slot_and_retains_expired_rows() -> TestResult {
    let db = Database::create(false).await?;
    let result = async {
        let env = setup_test_environment(&db.pool).await?;
        let mut client = sample_registered_client("slot-race");
        client.token_endpoint_auth_method = "client_secret_basic".into();
        client.client_secret = Some("original-issued-secret".into());
        crate::dcr_persistence::create_dynamic_registration(&db.pool, &env.issuer_host, &client, &["code".into()], "owner-token", "slots-test").await?;
        let (id, version): (Uuid, Uuid) = sqlx::query_as("SELECT id,configuration_version_id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier='slot-race'").bind(env.environment_id).fetch_one(&db.pool).await?;
        let (a, b) = tokio::join!(issue(&db.pool, env.environment_id, id, version), issue(&db.pool, env.environment_id, id, version));
        let mut successes = 0;
        let mut refused = 0;
        for outcome in [a, b] {
            match outcome {
                Ok(()) => successes += 1,
                Err(response) => {
                    assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
                    let body = axum::body::to_bytes(response.into_body(), 4096).await?;
                    let body: serde_json::Value = serde_json::from_slice(&body)?;
                    assert_eq!(body["errorCode"], "client_secret_capacity_exceeded");
                    refused += 1;
                }
            }
        }
        assert_eq!((successes, refused), (1, 1));
        sqlx::query("UPDATE aegaeon.client_secrets SET expires_at=statement_timestamp()-interval '1 hour' WHERE client_id=$1 AND active_slot=1").bind(id).execute(&db.pool).await?;
        assert_eq!(issue(&db.pool, env.environment_id, id, version).await.expect_err("expired ACTIVE still occupies its slot").status(), axum::http::StatusCode::CONFLICT);
        let expired_status: String = sqlx::query_scalar("SELECT status::text FROM aegaeon.client_secrets WHERE client_id=$1 AND active_slot=1").bind(id).fetch_one(&db.pool).await?;
        assert_eq!(expired_status, "ACTIVE", "no implicit credential revocation");
        sqlx::query("UPDATE aegaeon.client_secrets SET status='REVOKED',revoked_at=statement_timestamp() WHERE client_id=$1 AND active_slot=1").bind(id).execute(&db.pool).await?;
        issue(&db.pool, env.environment_id, id, version).await.map_err(|_| "reclaimed slot")?;
        let (total, active): (i64, i64) = sqlx::query_as("SELECT count(*),count(*) FILTER (WHERE status='ACTIVE') FROM aegaeon.client_secrets WHERE client_id=$1").bind(id).fetch_one(&db.pool).await?;
        assert_eq!((total, active), (3, 2));
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
