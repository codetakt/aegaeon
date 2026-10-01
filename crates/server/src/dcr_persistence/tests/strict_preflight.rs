use super::super::{
    strict_registration_metadata_preflight,
    test_database::{Database, PREFLIGHT},
};
use crate::web::test_support::{sample_registered_client, setup_test_environment, TestResult};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

async fn snapshot(pool: &PgPool) -> TestResult<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('clients',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM aegaeon.clients c),'registrations',(SELECT jsonb_agg(to_jsonb(d) ORDER BY client_id) FROM aegaeon.dynamic_client_registrations d),'secrets',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM aegaeon.client_secrets s),'environments',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM aegaeon.environments e))").fetch_one(pool).await?)
}

async fn check(pool: &PgPool, expected: &[&str]) -> TestResult {
    let before = snapshot(pool).await?;
    let report = strict_registration_metadata_preflight(pool).await?;
    assert_eq!(report.checked_registrations, 1);
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| finding.reason)
            .collect::<Vec<_>>(),
        expected
    );
    let rendered = serde_json::to_string(&report)?;
    for forbidden in [
        "private-sentinel",
        "fixture-token",
        "fixture-secret",
        "https://",
        "AQAB",
    ] {
        assert!(!rendered.contains(forbidden));
    }
    assert_eq!(before, snapshot(pool).await?);
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; strict local preflight over predecessor records"]
async fn dcr_strict_preflight_checks_retained_sources_without_writes_or_values() -> TestResult {
    let db = Database::create(true).await?;
    let result = async {
        let env = setup_test_environment(&db.pool).await?;
        let mut client = sample_registered_client("strict-preflight-fixture");
        client.token_endpoint_auth_method = "client_secret_basic".into();
        client.client_secret = Some("fixture-secret".into());
        super::super::create_dynamic_registration(&db.pool, &env.issuer_host, &client, &["code".into()], "fixture-token", "strict-preflight").await?;
        check(&db.pool, &[]).await?;
        // Valid retained dual sources and legacy responses are representation corrections.
        let valid = json!({"keys":[{"kty":"RSA","kid":"fixture","n":"AQAB","e":"AQAB"}]});
        sqlx::query("UPDATE aegaeon.clients SET allowed_grant_types=ARRAY['client_credentials'],status='DELETED'").execute(&db.pool).await?;
        sqlx::query("UPDATE aegaeon.environments SET active_configuration_version_id=NULL").execute(&db.pool).await?;
        sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=$1,jwks_uri='https://client.example:443/keys%2Fexact',post_logout_redirect_uris=ARRAY['https://client.example:443/logout%2Fexact'],backchannel_logout_uri='https://client.example/logout'").bind(&valid).execute(&db.pool).await?;
        check(&db.pool, &[]).await?;
        let corrections = sqlx::query(PREFLIGHT).fetch_all(&db.pool).await?;
        assert_eq!(corrections.len(), 2);
        assert!(corrections.iter().all(|row| !row.get::<bool, _>("blocks_upgrade")));
        for uri in ["https://client.example:bogus/private-sentinel", "https://[gg]/private-sentinel"] {
            sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks_uri=$1").bind(uri).execute(&db.pool).await?;
            assert!(sqlx::query(PREFLIGHT).fetch_all(&db.pool).await?.iter().all(|row| !row.get::<bool, _>("blocks_upgrade")), "SQL envelope deliberately does not duplicate URL parsing");
            check(&db.pool, &["invalid_jwks_uri"]).await?;
            assert!(strict_registration_metadata_preflight(&db.pool).await?.findings.iter().all(|finding| finding.status == "DELETED"));
        }
        sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks_uri='https://client.example/keys'").execute(&db.pool).await?;
        for value in [json!({"keys":"private-sentinel"}), json!({"keys":[{"kty":"oct","k":"private-sentinel"}]}), json!({"keys":[{"kty":"RSA","kid":"private-sentinel","n":"AQAB","e":"AQAB"},{"kty":"RSA","kid":"private-sentinel","n":"AQAB","e":"AQAB"}]})] {
            sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=$1").bind(value).execute(&db.pool).await?;
            check(&db.pool, &["invalid_stored_jwks"]).await?;
        }
        sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=$1").bind(valid).execute(&db.pool).await?;
        for uri in ["https://client.example/private-sentinel space", "https://client.example/private-sentinel\tcontrol"] {
            sqlx::query("UPDATE aegaeon.clients SET redirect_uris=ARRAY[$1]").bind(uri).execute(&db.pool).await?;
            check(&db.pool, &["invalid_redirect_uris"]).await?;
        }
        sqlx::query("UPDATE aegaeon.clients SET redirect_uris=ARRAY[]::text[]").execute(&db.pool).await?;
        check(&db.pool, &[]).await?;
        sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET post_logout_redirect_uris=ARRAY['https://client.example:bogus/private-sentinel'],backchannel_logout_uri='https://client.example:bogus/private-sentinel'").execute(&db.pool).await?;
        check(&db.pool, &["invalid_post_logout_redirect_uris", "invalid_backchannel_logout_uri"]).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
async fn dcr_strict_preflight_fails_on_backend_error() -> TestResult {
    let pool =
        sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://unused.example/unused")?;
    pool.close().await;
    assert!(strict_registration_metadata_preflight(&pool).await.is_err());
    Ok(())
}
