use super::super::test_database::Database;
use crate::web::test_support::{
    sample_registered_client, setup_test_environment, TestEnvironment, TestResult,
};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const UPGRADE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/migrations/20261029020000_client_secret_active_slots.sql"
));

async fn seed(pool: &PgPool, env: &TestEnvironment, name: &str) -> TestResult<Uuid> {
    let mut client = sample_registered_client(name);
    client.token_endpoint_auth_method = "client_secret_basic".into();
    client.client_secret = Some("slots-original-secret".into());
    super::super::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        &format!("rat-{name}"),
        "slots-test",
    )
    .await?;
    Ok(sqlx::query_scalar(
        "SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2",
    )
    .bind(env.environment_id)
    .bind(name)
    .fetch_one(pool)
    .await?)
}

async fn insert(pool: &PgPool, client: Uuid, slot: Option<i16>) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO aegaeon.client_secrets(environment_id,client_id,configuration_version_id,secret_hash,active_slot,expires_at) SELECT environment_id,id,configuration_version_id,'test-only-unused-hash',$2,statement_timestamp()+interval '1 hour' FROM aegaeon.clients WHERE id=$1 RETURNING id")
        .bind(client).bind(slot).fetch_one(pool).await
}

async fn snapshot(pool: &PgPool) -> TestResult<Value> {
    Ok(sqlx::query_scalar("SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM aegaeon.client_secrets s").fetch_one(pool).await?)
}

async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::raw_sql(UPGRADE).execute(&mut *tx).await?;
    tx.commit().await
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; actual predecessor upgrade and credential retention"]
async fn client_secret_slot_upgrade_preserves_credentials_and_existing_slots() -> TestResult {
    let db = Database::before_client_secret_upgrade().await?;
    let result = async {
        let env = setup_test_environment(&db.pool).await?;
        let first = seed(&db.pool, &env, "legacy-null").await?;
        sqlx::query("UPDATE aegaeon.client_secrets SET active_slot=NULL WHERE client_id=$1")
            .bind(first)
            .execute(&db.pool)
            .await?;
        insert(&db.pool, first, None).await?;
        let second = seed(&db.pool, &env, "legacy-fixed").await?;
        sqlx::query("UPDATE aegaeon.client_secrets SET active_slot=2 WHERE client_id=$1")
            .bind(second)
            .execute(&db.pool)
            .await?;
        insert(&db.pool, second, None).await?;
        let mut before = snapshot(&db.pool).await?;
        migrate(&db.pool).await?;
        let mut after = snapshot(&db.pool).await?;
        for (old, new) in before
            .as_array_mut()
            .ok_or("before")?
            .iter_mut()
            .zip(after.as_array_mut().ok_or("after")?)
        {
            assert!(matches!(new["active_slot"].as_i64(), Some(1 | 2)));
            if !old["active_slot"].is_null() {
                assert_eq!(old["active_slot"], new["active_slot"]);
            }
            old.as_object_mut().ok_or("old row")?.remove("active_slot");
            new.as_object_mut().ok_or("new row")?.remove("active_slot");
            assert_eq!(old, new, "upgrade may only fill missing slot assignments");
        }
        assert!(
            migrate(&db.pool).await.is_err(),
            "Atlas owns once-only versions"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; atomic refusal of legacy excess credentials"]
async fn client_secret_slot_upgrade_refuses_excess_without_revocation_or_partial_assignment(
) -> TestResult {
    let db = Database::before_client_secret_upgrade().await?;
    let result = async {
        let env = setup_test_environment(&db.pool).await?;
        let id = seed(&db.pool, &env, "legacy-excess").await?;
        insert(&db.pool, id, None).await?;
        let third = insert(&db.pool, id, None).await?;
        let before = snapshot(&db.pool).await?;
        assert!(migrate(&db.pool).await.is_err());
        assert_eq!(before, snapshot(&db.pool).await?);
        let constraints: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_constraint WHERE conrelid='aegaeon.client_secrets'::regclass AND conname='client_secrets_active_slot_required'").fetch_one(&db.pool).await?;
        assert_eq!(constraints, 0);
        // Explicit fixture/operator choice; the migration never picks a credential.
        sqlx::query("UPDATE aegaeon.client_secrets SET status='REVOKED',revoked_at=statement_timestamp() WHERE id=$1").bind(third).execute(&db.pool).await?;
        migrate(&db.pool).await?;
        assert_eq!(snapshot(&db.pool).await?.as_array().ok_or("rows")?.len(), 3);
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; database active cardinality and slot reuse"]
async fn client_secret_slots_reject_null_duplicate_and_third_active_credentials() -> TestResult {
    let db = Database::create(false).await?;
    let result = async {
        let env = setup_test_environment(&db.pool).await?;
        let id = seed(&db.pool, &env, "current-slots").await?;
        let before = snapshot(&db.pool).await?;
        assert!(insert(&db.pool, id, None).await.is_err());
        assert!(insert(&db.pool, id, Some(1)).await.is_err());
        assert!(insert(&db.pool, id, Some(3)).await.is_err());
        assert_eq!(before, snapshot(&db.pool).await?);
        let second = insert(&db.pool, id, Some(2)).await?;
        let both = snapshot(&db.pool).await?;
        for slot in [None, Some(1), Some(2), Some(3)] { assert!(insert(&db.pool, id, slot).await.is_err()); }
        assert!(sqlx::query("UPDATE aegaeon.client_secrets SET active_slot=NULL WHERE id=$1").bind(second).execute(&db.pool).await.is_err());
        assert_eq!(both, snapshot(&db.pool).await?);
        sqlx::query("UPDATE aegaeon.client_secrets SET status='REVOKED',revoked_at=statement_timestamp() WHERE id=$1").bind(second).execute(&db.pool).await?;
        insert(&db.pool, id, Some(2)).await?;
        assert!(sqlx::query("UPDATE aegaeon.client_secrets SET status='ACTIVE' WHERE id=$1").bind(second).execute(&db.pool).await.is_err());
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
