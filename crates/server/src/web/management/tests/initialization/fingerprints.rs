//! Test-owned databases only: extension placement must never be repaired in a
//! shared test/operator database. Retained legacy SQL is the compatibility oracle.
use super::*;
use crate::runtime_configuration::{
    load_active_runtime_configuration_revision_for_issuer_host as revision,
    load_database_runtime_configuration, RuntimeAuthorityRevision,
};
use sqlx::Row;

async fn legacy_revision(
    pool: &PgPool,
    host: &str,
    extension_schema: &str,
) -> anyhow::Result<RuntimeAuthorityRevision> {
    let authority = include_str!("fingerprints/legacy_authority.sql")
        .replace("aegaeon.digest", &format!("{extension_schema}.digest"));
    let clients = include_str!("fingerprints/legacy_clients.sql")
        .replace("aegaeon.digest", &format!("{extension_schema}.digest"));
    let row = sqlx::query(&authority).bind(host).fetch_one(pool).await?;
    let client_fingerprint: String = sqlx::query_scalar(&clients)
        .bind(host)
        .fetch_one(pool)
        .await?;
    Ok(RuntimeAuthorityRevision::try_new(
        row.try_get("active_configuration_version_id")?,
        row.try_get("active_configuration_document_fingerprint")?,
        row.try_get("active_runtime_key_set_fingerprint")?,
        client_fingerprint,
        row.try_get("active_dcr_bearer_token_fingerprint")?,
    )?)
}

async fn check_text_bytes(pool: &PgPool, schema: &str, encoding: &str) -> anyhow::Result<()> {
    let query = format!(
        "SELECT pg_catalog.encode({schema}.digest($1::text, 'sha256'), 'hex'),
        pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          $1::text, pg_catalog.getdatabaseencoding())), 'hex')"
    );
    for input in [
        None,
        Some(""),
        Some("abc"),
        Some("café"),
        Some(r"\x616263\000"),
        Some(r#"{"label":"café","escape":"\u00e9"}"#),
        Some("null"),
        Some("[]"),
        Some("{}"),
    ] {
        let (old, new): (Option<String>, Option<String>) =
            sqlx::query_as(&query).bind(input).fetch_one(pool).await?;
        assert_eq!(old, new, "input {input:?}, encoding {encoding}");
        match input {
            None => assert!(new.is_none()),
            Some("") => assert_eq!(
                new.as_deref(),
                Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            ),
            Some("abc") => assert_eq!(
                new.as_deref(),
                Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            ),
            _ => {}
        }
    }
    if encoding == "UTF8" {
        let (old, new): (String, String) = sqlx::query_as(&query)
            .bind("日本語🔑")
            .fetch_one(pool)
            .await?;
        assert_eq!(old, new);
    } else {
        // An explicit control detects the tempting but incompatible forced-UTF8 fix.
        let different: bool = sqlx::query_scalar(&format!(
            "SELECT {schema}.digest($1::text, 'sha256') <>
              pg_catalog.sha256(pg_catalog.convert_to($1::text, 'UTF8'))"
        ))
        .bind("café")
        .fetch_one(pool)
        .await?;
        assert!(different);
    }
    Ok(())
}

async fn shadow_functions(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(
        "CREATE SCHEMA fingerprint_shadow;
        CREATE FUNCTION fingerprint_shadow.digest(text,text) RETURNS bytea
          LANGUAGE SQL IMMUTABLE AS $$ SELECT '\\x00'::bytea $$;
        CREATE FUNCTION fingerprint_shadow.sha256(bytea) RETURNS bytea
          LANGUAGE SQL IMMUTABLE AS $$ SELECT '\\x00'::bytea $$;
        CREATE FUNCTION fingerprint_shadow.convert_to(text,name) RETURNS bytea
          LANGUAGE SQL IMMUTABLE AS $$ SELECT '\\x00'::bytea $$;
        CREATE FUNCTION fingerprint_shadow.getdatabaseencoding() RETURNS name
          LANGUAGE SQL IMMUTABLE AS $$ SELECT 'SQL_ASCII'::name $$;
        CREATE FUNCTION fingerprint_shadow.encode(bytea,text) RETURNS text
          LANGUAGE SQL IMMUTABLE AS $$ SELECT 'shadow-encode'::text $$;
        SET search_path = fingerprint_shadow, pg_catalog, public;",
    )
    .execute(pool)
    .await?;
    let intercepted: String = sqlx::query_scalar("SELECT encode('abc'::bytea, 'hex')")
        .fetch_one(pool)
        .await?;
    assert_eq!(
        intercepted, "shadow-encode",
        "shadow control must be effective"
    );
    Ok(())
}

async fn grant_runtime(admin: &PgPool, role: &str) -> anyhow::Result<()> {
    let grants: Vec<String> = sqlx::query_scalar(
        "SELECT format('GRANT USAGE ON SCHEMA %I TO %I', nspname, $1::text)
         FROM pg_namespace WHERE nspname IN ('aegaeon','extensions','public')
         UNION ALL SELECT format('GRANT %s ON aegaeon.%I TO %I',
           CASE WHEN relkind='v' OR relname IN ('subject_ownership_namespaces','subject_ownership_adoptions')
           THEN 'SELECT' ELSE 'SELECT,INSERT,UPDATE,DELETE' END, relname, $1::text)
         FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='aegaeon' AND relkind IN ('r','p','v') AND relname NOT IN ('end_user_identity_owners','end_user_subject_reservations')")
        .bind(role).fetch_all(admin).await?;
    for grant in grants {
        sqlx::query(&grant).execute(admin).await?;
    }
    Ok(())
}

async fn scenario(preinstall: Option<&str>, encoding: &str) -> ManagementTestResult {
    let control = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
        .await?;
    let name = format!("fingerprints_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE DATABASE {name} TEMPLATE template0 ENCODING '{encoding}' LC_COLLATE 'C' LC_CTYPE 'C'"
    ))
    .execute(&control)
    .await?;
    // One connection makes the explicit shadow search_path apply to every read.
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(control.connect_options().as_ref().clone().database(&name))
        .await?;
    let options: sqlx::postgres::PgConnectOptions =
        std::env::var("AEGAEON_DATABASE_URL")?.parse()?;
    let runtime_name = options.get_username().to_owned();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.database(&name))
        .await?;
    let result: ManagementTestResult = async {
        if let Some(schema) = preinstall {
            sqlx::raw_sql(&format!(
                "CREATE SCHEMA IF NOT EXISTS {schema}; CREATE EXTENSION pgcrypto WITH SCHEMA {schema};"
            ))
            .execute(&admin)
            .await?;
        }
        sqlx::raw_sql(include_str!("../../../../../../../db/schema.sql"))
            .execute(&admin)
            .await?;
        grant_runtime(&admin, &runtime_name).await?;
        let schema = preinstall.unwrap_or("aegaeon");
        let installed: String = sqlx::query_scalar(
            "SELECT n.nspname::text FROM pg_catalog.pg_extension e
             JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pgcrypto'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(installed, schema, "baseline must not relocate an existing extension");
        check_text_bytes(&pool, schema, encoding).await?;
        let initialized = initialize_management(&pool, &input()).await?;
        let host = &initialized.issuer_host;
        let expected_empty = legacy_revision(&pool, host, schema).await?;
        let loaded = load_database_runtime_configuration(&pool, host).await?;
        assert_eq!(loaded.authority_revision()?, expected_empty);

        // Non-empty projections exercise all five hash sites, including key_handle.
        // This is a projection fixture, not an encrypted signing-key import.
        sqlx::query("INSERT INTO aegaeon.runtime_keys (environment_id,configuration_version_id,usage,kid,algorithm,provider,status,public_jwk,key_handle)
            VALUES ($1,$2,'JWT_ACCESS_TOKEN_SIGNING','probe-café','EdDSA','databaseEncrypted','ACTIVE','{}'::jsonb,$3)")
            .bind(initialized.environment_id).bind(initialized.configuration_version_id)
            .bind(r"opaque-café-\x616263").execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.clients (environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method)
            VALUES ($1,$2,'fingerprint-café','Fingerprint probe','PUBLIC',ARRAY['https://client.example/café'],ARRAY['authorization_code'],ARRAY['openid'],'none')")
            .bind(initialized.environment_id).bind(initialized.configuration_version_id).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.environment_dcr_bearer_tokens (environment_id,token_hash,token_hash_algorithm) VALUES ($1,$2,'sha256')")
            .bind(initialized.environment_id).bind("a".repeat(64)).execute(&pool).await?;
        let expected = legacy_revision(&pool, host, schema).await?;
        assert_ne!(expected, expected_empty);
        assert_eq!(revision(&pool, host).await?, expected);
        assert_eq!(revision(&pool, host).await?, expected, "repeated reads are stable");

        sqlx::query("UPDATE aegaeon.runtime_keys SET key_handle=$2 WHERE environment_id=$1")
            .bind(initialized.environment_id).bind(r"changed-café-\000").execute(&pool).await?;
        let changed = legacy_revision(&pool, host, schema).await?;
        assert_ne!(changed.active_runtime_key_set_fingerprint(), expected.active_runtime_key_set_fingerprint());
        assert_eq!(revision(&pool, host).await?, changed);
        shadow_functions(&admin).await?;
        let usage: String = sqlx::query_scalar("SELECT format('GRANT USAGE ON SCHEMA fingerprint_shadow TO %I', $1::text)")
            .bind(&runtime_name).fetch_one(&admin).await?;
        sqlx::query(&usage).execute(&admin).await?;
        sqlx::query("SET search_path = fingerprint_shadow, pg_catalog, public").execute(&pool).await?;
        assert_eq!(revision(&pool, host).await?, changed, "explicit pg_catalog binding resists shadowing");
        // Removal is confined to this test-owned database. Runtime hashing uses core functions.
        sqlx::query("DROP EXTENSION pgcrypto").execute(&admin).await?;
        assert_eq!(revision(&pool, host).await?, changed, "runtime hash reads need no extension");
        Ok(())
    }
    .await;
    admin.close().await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_runtime_fingerprints_with_public_pgcrypto() -> ManagementTestResult {
    scenario(Some("public"), "UTF8").await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_runtime_fingerprints_with_alternate_pgcrypto() -> ManagementTestResult {
    scenario(Some("extensions"), "UTF8").await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_runtime_fingerprints_with_baseline_pgcrypto() -> ManagementTestResult {
    scenario(None, "UTF8").await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_runtime_fingerprints_preserve_database_encoding() -> ManagementTestResult {
    scenario(Some("public"), "LATIN1").await
}
