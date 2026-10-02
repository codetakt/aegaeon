use super::super::test_database::{Database, MIGRATION, PREFLIGHT, REPAIR};
use crate::web::test_support::{
    sample_registered_client, setup_test_environment, TestEnvironment, TestResult,
};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

async fn snapshot(pool: &PgPool) -> TestResult<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('clients',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM aegaeon.clients c),'registrations',(SELECT jsonb_agg(to_jsonb(d) ORDER BY client_id) FROM aegaeon.dynamic_client_registrations d),'secrets',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM aegaeon.client_secrets s))")
        .fetch_one(pool).await?)
}

async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::raw_sql(MIGRATION).execute(&mut *tx).await?;
    tx.commit().await
}

async fn seed(pool: &PgPool, env: &TestEnvironment, name: &str) -> TestResult {
    let mut client = sample_registered_client(name);
    client.token_endpoint_auth_method = "client_secret_basic".into();
    client.client_secret = Some("fixture-secret-never-print".into());
    super::super::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        &format!("rat-{name}"),
        "fixture",
    )
    .await?;
    Ok(())
}

async fn repair_input(pool: &PgPool, name: &str) -> TestResult<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('operator_approval_reference','private-fixture-approval','environment_id',c.environment_id,'client_id',c.id,'expected_client_identifier',c.client_identifier,'expected_configuration_version_id',c.configuration_version_id,'expected_active_configuration_version_id',e.active_configuration_version_id,'expected_status',c.status,'expected_metadata',jsonb_build_object('redirect_uris',c.redirect_uris,'grant_types',c.allowed_grant_types,'client_type',c.client_type,'auth_method',c.token_endpoint_authentication_method,'scopes',c.allowed_scopes,'name',c.name,'oauth_profile_id',c.oauth_profile_id,'response_types',d.response_types,'client_id_issued_at',d.client_id_issued_at,'post_logout_redirect_uris',d.post_logout_redirect_uris,'backchannel_logout_uri',d.backchannel_logout_uri,'backchannel_logout_session_required',d.backchannel_logout_session_required,'token_endpoint_auth_signing_alg',d.token_endpoint_auth_signing_alg,'jwks',d.jwks,'jwks_uri',d.jwks_uri),'replacement',jsonb_build_object('redirect_uris',c.redirect_uris,'grant_types',c.allowed_grant_types,'jwks',d.jwks,'jwks_uri',d.jwks_uri)) FROM aegaeon.clients c JOIN aegaeon.environments e ON e.id=c.environment_id JOIN aegaeon.dynamic_client_registrations d ON d.environment_id=c.environment_id AND d.client_id=c.id WHERE c.client_identifier=$1")
        .bind(name).fetch_one(pool).await?)
}

async fn repair(pool: &PgPool, input: &Value, commit: bool) -> Result<(), sqlx::Error> {
    let mut connection = pool.acquire().await?;
    sqlx::raw_sql("CREATE TEMP TABLE dcr_metadata_repair_input (request jsonb)")
        .execute(&mut *connection)
        .await?;
    sqlx::query("INSERT INTO dcr_metadata_repair_input VALUES ($1)")
        .bind(input)
        .execute(&mut *connection)
        .await?;
    let script = if commit {
        REPAIR.replace("\nROLLBACK;", "\nCOMMIT;")
    } else {
        REPAIR.to_string()
    };
    let result = sqlx::raw_sql(&script).execute(&mut *connection).await;
    sqlx::raw_sql("ROLLBACK; DROP TABLE dcr_metadata_repair_input")
        .execute(&mut *connection)
        .await?;
    result.map(|_| ())
}

async fn blocked_repairs(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    seed(pool, env, "missing-redirect").await?;
    seed(pool, env, "public-authenticated").await?;
    sqlx::query("UPDATE aegaeon.clients SET redirect_uris=ARRAY[]::text[] WHERE client_identifier='missing-redirect'").execute(pool).await?;
    sqlx::query("UPDATE aegaeon.clients SET client_type='PUBLIC', token_endpoint_authentication_method='none', allowed_grant_types=ARRAY['authorization_code','client_credentials'] WHERE client_identifier='public-authenticated'").execute(pool).await?;
    let findings = sqlx::query(PREFLIGHT).fetch_all(pool).await?;
    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .all(|row| row.get::<bool, _>("blocks_upgrade")));
    let before = snapshot(pool).await?;
    assert!(migrate(pool).await.is_err());
    assert_eq!(before, snapshot(pool).await?);
    assert!(super::super::preflight_dynamic_registration_schema(pool)
        .await
        .is_err());
    let mut approved = repair_input(pool, "missing-redirect").await?;
    approved["replacement"]["redirect_uris"] = json!(["https://client.example/approved"]);
    repair(pool, &approved, false).await?;
    assert_eq!(
        before,
        snapshot(pool).await?,
        "template rolls back by default"
    );
    for field in [
        "environment_id",
        "client_id",
        "expected_configuration_version_id",
        "expected_active_configuration_version_id",
    ] {
        let mut wrong = approved.clone();
        wrong[field] = json!(uuid::Uuid::new_v4());
        assert!(repair(pool, &wrong, true).await.is_err());
        assert_eq!(before, snapshot(pool).await?);
    }
    for (field, value) in [
        ("expected_status", json!("DELETED")),
        ("expected_client_identifier", json!("wrong")),
        ("expected_metadata", json!({})),
    ] {
        let mut wrong = approved.clone();
        wrong[field] = value;
        assert!(repair(pool, &wrong, true).await.is_err());
        assert_eq!(before, snapshot(pool).await?);
    }
    let mut added_right = approved.clone();
    added_right["replacement"]["grant_types"] = json!(["authorization_code", "client_credentials"]);
    assert!(repair(pool, &added_right, true).await.is_err());
    let mut type_change = approved.clone();
    type_change["replacement"]["client_type"] = json!("PUBLIC");
    assert!(repair(pool, &type_change, true).await.is_err());
    assert_eq!(before, snapshot(pool).await?);
    repair(pool, &approved, true).await?;
    assert!(
        repair(pool, &approved, true).await.is_err(),
        "stale retry must fail"
    );
    assert!(
        migrate(pool).await.is_err(),
        "remaining public grant blocks upgrade"
    );
    let mut public = repair_input(pool, "public-authenticated").await?;
    public["replacement"]["grant_types"] = json!(["authorization_code"]);
    repair(pool, &public, true).await?;
    let repaired = snapshot(pool).await?;
    assert_eq!(before["registrations"], repaired["registrations"]);
    assert_eq!(before["secrets"], repaired["secrets"]);
    for (old, new) in before["clients"]
        .as_array()
        .ok_or("clients")?
        .iter()
        .zip(repaired["clients"].as_array().ok_or("clients")?)
    {
        for field in [
            "id",
            "environment_id",
            "configuration_version_id",
            "status",
            "client_identifier",
            "allowed_scopes",
            "client_type",
            "token_endpoint_authentication_method",
        ] {
            // The fixture establishes the public state before the baseline snapshot.
            assert_eq!(old[field], new[field]);
        }
    }
    assert!(sqlx::query(PREFLIGHT).fetch_all(pool).await?.is_empty());
    migrate(pool).await?;
    super::super::preflight_dynamic_registration_schema(pool).await?;
    assert!(
        migrate(pool).await.is_err(),
        "Atlas owns once-only migration versions"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; actual predecessor and guarded offline SQL"]
async fn dcr_metadata_upgrade_atomic_refusal_guarded_repair_and_retry() -> TestResult {
    let db = Database::create(true).await?;
    let result = async {
        let env = setup_test_environment(&db.pool).await?;
        blocked_repairs(&db.pool, &env).await
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

async fn key_corrections(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    seed(pool, env, "dual-source").await?;
    seed(pool, env, "corrupt-source").await?;
    // Structurally valid predecessor key envelope. No cryptographic key-strength claim.
    let valid = json!({"keys":[{"kty":"RSA","kid":"fixture","n":"AQAB","e":"AQAB"}]});
    sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=$1,jwks_uri='https://client.example/unused' WHERE client_identifier='dual-source'").bind(&valid).execute(pool).await?;
    sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=$1 WHERE client_identifier='corrupt-source'").bind(json!({"keys":"broken"})).execute(pool).await?;
    sqlx::query("UPDATE aegaeon.clients SET allowed_grant_types=ARRAY['client_credentials'] WHERE client_identifier='dual-source'").execute(pool).await?;
    let original = snapshot(pool).await?;
    assert!(migrate(pool).await.is_err());
    assert_eq!(original, snapshot(pool).await?);
    let mut input = repair_input(pool, "corrupt-source").await?;
    input["replacement"]["jwks"] = valid;
    assert!(
        repair(pool, &input, true).await.is_err(),
        "no trustworthy backup reference"
    );
    assert_eq!(original, snapshot(pool).await?);
    input["verified_key_backup_reference"] = json!("private-verified-fixture");
    repair(pool, &input, true).await?;
    let before = snapshot(pool).await?;
    let prior_revision =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            pool,
            &env.issuer_host,
        )
        .await?;
    migrate(pool).await?;
    let after = snapshot(pool).await?;
    assert_eq!(before["clients"], after["clients"]);
    assert_eq!(before["secrets"], after["secrets"]);
    let new_revision =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            pool,
            &env.issuer_host,
        )
        .await?;
    assert_ne!(
        prior_revision, new_revision,
        "clearing unused URI changes captured authority fingerprint"
    );
    for (old, new) in before["registrations"]
        .as_array()
        .ok_or("registrations")?
        .iter()
        .zip(after["registrations"].as_array().ok_or("registrations")?)
    {
        for field in [
            "client_id",
            "environment_id",
            "client_identifier",
            "jwks",
            "registration_access_token_hash",
            "client_id_issued_at",
        ] {
            assert_eq!(old[field], new[field]);
        }
    }
    let stored = super::super::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        "dual-source",
        "rat-dual-source",
    )
    .await?
    .ok_or("stored registration")?;
    assert!(stored.response_types.is_empty());
    assert!(stored.client.jwks_uri.is_none());
    assert!(sqlx::query(PREFLIGHT).fetch_all(pool).await?.is_empty());
    assert!(sqlx::query(
        "UPDATE aegaeon.dynamic_client_registrations SET response_types=ARRAY['token']"
    )
    .execute(pool)
    .await
    .is_err());
    assert!(sqlx::query(
        "UPDATE aegaeon.dynamic_client_registrations SET jwks_uri='https://client.example/keys'"
    )
    .execute(pool)
    .await
    .is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; migration key restoration and fingerprint effects"]
async fn dcr_metadata_upgrade_key_envelopes_and_deterministic_corrections() -> TestResult {
    let db = Database::create(true).await?;
    let result = async {
        let env = setup_test_environment(&db.pool).await?;
        key_corrections(&db.pool, &env).await
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; fresh and migrated constraint parity"]
async fn dcr_metadata_upgrade_matches_fresh_schema_and_persistence_refuses_mismatch() -> TestResult
{
    let old = Database::create(true).await?;
    let fresh = Database::create(false).await?;
    let result = async {
        migrate(&old.pool).await?;
        let query = "SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='aegaeon.dynamic_client_registrations'::regclass ORDER BY conname";
        let migrated: Vec<(String,String)> = sqlx::query_as(query).fetch_all(&old.pool).await?;
        let desired: Vec<(String,String)> = sqlx::query_as(query).fetch_all(&fresh.pool).await?;
        assert_eq!(migrated,desired);
        let env = setup_test_environment(&fresh.pool).await?;
        let client = sample_registered_client("guarded-client");
        let before = snapshot(&fresh.pool).await?;
        let err = super::super::create_dynamic_registration(&fresh.pool,&env.issuer_host,&client,&[],"guard-token","guard-test").await.expect_err("mismatch must fail before storage");
        assert!(matches!(err,super::super::DcrDatabaseError::MetadataRelation(_)));
        assert_eq!(before,snapshot(&fresh.pool).await?);
        super::super::create_dynamic_registration(&fresh.pool,&env.issuer_host,&client,&["code".into()],"guard-token","guard-test").await?;
        let stored = super::super::load_dynamic_registration_by_token(&fresh.pool,&env.issuer_host,&client.client_id,"guard-token").await?.ok_or("stored")?;
        let before = snapshot(&fresh.pool).await?;
        let err = super::super::update_dynamic_registration(&fresh.pool,&stored,&client,&[],"rotated-token",super::super::DcrClientSecretChange::Preserve,None,"guard-test").await.expect_err("mismatch must fail before writes");
        assert!(matches!(err,super::super::DcrDatabaseError::MetadataRelation(_)));
        assert_eq!(before,snapshot(&fresh.pool).await?);
        sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET response_types=ARRAY[]::text[]").execute(&fresh.pool).await?;
        let err = super::super::load_dynamic_registration_by_token(&fresh.pool,&env.issuer_host,&client.client_id,"guard-token").await.expect_err("typed loader must refuse corrupt relation");
        assert!(matches!(err,super::super::DcrDatabaseError::CorruptRegistration(_)));
        Ok::<(),Box<dyn std::error::Error>>(())
    }.await;
    let old_cleanup = old.cleanup().await;
    let fresh_cleanup = fresh.cleanup().await;
    result?;
    old_cleanup?;
    fresh_cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; malformed predecessor envelope reporting"]
async fn dcr_metadata_preflight_reports_malformed_key_envelopes_without_key_values() -> TestResult {
    let db = Database::create(true).await?;
    let result = async {
        let env = setup_test_environment(&db.pool).await?;
        seed(&db.pool,&env,"envelope-case").await?;
        for value in [
            json!(null), json!([]), json!({}), json!({"keys":[]}),
            json!({"keys":[1]}), json!({"keys":[{"kty":"oct","k":"private-sentinel"}]}),
            json!({"keys":[{"kty":"RSA","n":1,"e":"AQAB"}]}),
            json!({"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","key_ops":"verify"}]}),
            json!({"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","key_ops":[1]}]}),
            json!({"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","use":"enc"}]}),
            json!({"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"duplicate"},{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"duplicate"}]}),
        ] {
            sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=$1").bind(value).execute(&db.pool).await?;
            let rows=sqlx::query(PREFLIGHT).fetch_all(&db.pool).await?;
            assert!(rows.iter().any(|r|r.get::<String,_>("reason")=="malformed_inline_key_envelope" && r.get::<bool,_>("blocks_upgrade")));
            assert!(rows.iter().all(|r|r.len()==7),"report only has identifier/status/reason columns");
            let before=snapshot(&db.pool).await?;
            assert!(migrate(&db.pool).await.is_err());
            assert_eq!(before,snapshot(&db.pool).await?);
        }
        Ok::<(),Box<dyn std::error::Error>>(())
    }.await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
