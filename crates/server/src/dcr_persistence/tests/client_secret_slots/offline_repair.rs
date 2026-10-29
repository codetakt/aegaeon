use super::*;
use serde_json::json;

const REPAIR: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/operations/client-secret-capacity-repair.sql"
));

async fn repair(pool: &PgPool, input: &Value, commit: bool) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::raw_sql("CREATE TEMP TABLE IF NOT EXISTS client_secret_repair_input(request jsonb NOT NULL); TRUNCATE client_secret_repair_input;").execute(&mut *conn).await?;
    sqlx::query("INSERT INTO client_secret_repair_input VALUES($1)")
        .bind(input)
        .execute(&mut *conn)
        .await?;
    let sql = if commit {
        REPAIR.replace("\nROLLBACK;", "\nCOMMIT;")
    } else {
        REPAIR.to_owned()
    };
    let result = sqlx::raw_sql(&sql).execute(&mut *conn).await;
    if result.is_err() {
        sqlx::query("ROLLBACK").execute(&mut *conn).await?;
    }
    result.map(|_| ())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; explicit offline revocation of inaccessible legacy credentials"]
async fn client_secret_capacity_repair_is_scoped_audited_and_atomic() -> TestResult {
    let db = Database::before_client_secret_upgrade().await?;
    let result = async {
        let env = setup_test_environment(&db.pool).await?;
        let retired = seed(&db.pool, &env, "old-configuration").await?;
        let deleted = seed(&db.pool, &env, "deleted-client").await?;
        sqlx::query("UPDATE aegaeon.clients SET status='DELETED' WHERE id=$1").bind(deleted).execute(&db.pool).await?;
        let old_configuration: Uuid = sqlx::query_scalar("SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1")
            .bind(env.environment_id).fetch_one(&db.pool).await?;
        let next = Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.configuration_versions(id,environment_id,version_number,configuration_hash,status,configuration_document) SELECT $1,environment_id,2,'capacity-repair-fixture','DRAFT',configuration_document FROM aegaeon.configuration_versions WHERE id=$2")
            .bind(next).bind(old_configuration).execute(&db.pool).await?;
        sqlx::query("UPDATE aegaeon.environments SET active_configuration_version_id=$1 WHERE id=$2").bind(next).bind(env.environment_id).execute(&db.pool).await?;
        // This is the immediate predecessor, including the RS256 access-key migration.
        let constraint: String = sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='aegaeon.runtime_keys'::regclass AND conname='runtime_keys_algorithm_matches_usage'").fetch_one(&db.pool).await?;
        assert!(constraint.contains("JWT_ACCESS_TOKEN_SIGNING") && constraint.matches("RS256").count() >= 3);
        for (client, status) in [(retired, "ACTIVE"), (deleted, "DELETED")] {
            insert(&db.pool, client, None).await?;
            let selected = insert(&db.pool, client, None).await?;
            let input = json!({"operator":"fixture-operator", "approval_reference":"fixture-capacity-review", "environment_id":env.environment_id, "client_id":client, "client_secret_id":selected, "expected_client_status":status, "expected_client_configuration_version_id":old_configuration, "expected_active_configuration_version_id":next});
            let before = snapshot(&db.pool).await?;
            assert!(migrate(&db.pool).await.is_err());
            for field in ["client_id", "environment_id", "client_secret_id", "expected_active_configuration_version_id", "expected_client_configuration_version_id"] {
                let mut wrong = input.clone(); wrong[field] = json!(Uuid::new_v4());
                assert!(repair(&db.pool, &wrong, true).await.is_err(), "wrong scope must refuse: {field}");
                assert_eq!(before, snapshot(&db.pool).await?);
            }
            let mut wrong = input.clone(); wrong["expected_client_status"] = json!("SUSPENDED");
            assert!(repair(&db.pool, &wrong, true).await.is_err());
            let mut wrong = input.clone(); wrong["approval_reference"] = json!("");
            assert!(repair(&db.pool, &wrong, true).await.is_err());
            repair(&db.pool, &input, false).await?;
            assert_eq!(before, snapshot(&db.pool).await?, "review script must roll back");
            // An audit failure must roll back the preceding revocation as well.
            sqlx::raw_sql("CREATE FUNCTION aegaeon.refuse_capacity_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit refusal'; END $$; CREATE TRIGGER capacity_audit_refusal BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.refuse_capacity_audit();").execute(&db.pool).await?;
            assert!(repair(&db.pool, &input, true).await.is_err());
            assert_eq!(before, snapshot(&db.pool).await?);
            sqlx::raw_sql("DROP TRIGGER capacity_audit_refusal ON aegaeon.audit_events; DROP FUNCTION aegaeon.refuse_capacity_audit();").execute(&db.pool).await?;
            repair(&db.pool, &input, true).await?;
            let after = snapshot(&db.pool).await?;
            for (old, new) in before.as_array().ok_or("before")?.iter().zip(after.as_array().ok_or("after")?) {
                if old["id"] == json!(selected) {
                    assert_eq!(new["status"], "REVOKED"); assert!(!new["revoked_at"].is_null());
                    let mut restored = new.clone(); restored["status"] = old["status"].clone(); restored["revoked_at"] = old["revoked_at"].clone();
                    assert_eq!(old, &restored);
                } else { assert_eq!(old, new); }
            }
            let audit: Value = sqlx::query_scalar("SELECT to_jsonb(a) FROM aegaeon.audit_events a WHERE event_type='operations.clientSecret.revoked.v1' AND target_id=$1").bind(selected.to_string()).fetch_one(&db.pool).await?;
            assert_eq!(audit["actor_id"], "fixture-operator");
            assert_eq!(audit["request_id"], "fixture-capacity-review");
            assert_eq!(audit["data"]["clientId"], json!(client));
            assert!(!audit.to_string().contains("slots-original-secret"));
            assert!(!audit.to_string().contains("secret_hash"));
            assert!(repair(&db.pool, &input, true).await.is_err(), "already revoked selection cannot be replayed");
        }
        migrate(&db.pool).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
