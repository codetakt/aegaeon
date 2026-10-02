//! Exact preparation state and secret-presence decision controls.
use super::credential_admission::{issue, stored};
use super::*;
use crate::dcr_persistence::{
    delete_dynamic_registration, update_dynamic_registration, DcrClientSecretChange,
    DcrDatabaseError, DcrStoredClient,
};

async fn fixture(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    name: &str,
) -> TestResult<DcrStoredClient> {
    let mut client = sample_registered_client(name);
    client.token_endpoint_auth_method = "client_secret_basic".into();
    client.client_secret = None;
    create_test_registration(pool, env, &client, &format!("{name}-owner-token")).await?;
    reload(pool, env, name).await
}

async fn reload(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    name: &str,
) -> TestResult<DcrStoredClient> {
    stored(
        pool,
        env,
        &json!({"client_id":name,"registration_access_token":format!("{name}-owner-token")}),
    )
    .await
}

async fn put(
    pool: &PgPool,
    row: &DcrStoredClient,
    change: DcrClientSecretChange,
) -> Result<(), DcrDatabaseError> {
    update_dynamic_registration(
        pool,
        row,
        &row.client,
        &row.response_types,
        "preparation-replacement-token",
        change,
        None,
        "preparation-update",
    )
    .await
}

async fn refuses(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    row: &DcrStoredClient,
    change: DcrClientSecretChange,
) -> TestResult {
    let before = digest(pool, env).await?;
    let error = put(pool, row, change).await.expect_err("stale preparation");
    assert!(matches!(error, DcrDatabaseError::ConcurrentModification));
    assert!(!format!("{error:?}").contains("private-preparation-sentinel"));
    assert_eq!(before, digest(pool, env).await?);
    Ok(())
}

async fn secret_decisions(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let empty = fixture(pool, env, "empty-secret-preparation").await?;
    assert!(!empty.has_active_client_secret);
    issue(pool, &empty, "newly-issued-secret").await?;
    refuses(
        pool,
        env,
        &empty,
        DcrClientSecretChange::ReplaceWithPlaintext("obsolete-replacement".into()),
    )
    .await?;
    let hash: String = sqlx::query_scalar(
        "SELECT secret_hash FROM aegaeon.client_secrets WHERE client_id=$1 AND status='ACTIVE'",
    )
    .bind(empty.database_client_id)
    .fetch_one(pool)
    .await?;
    assert!(crate::local_credentials::verify_password(
        "newly-issued-secret",
        &hash
    ));
    let populated = reload(pool, env, "empty-secret-preparation").await?;
    assert!(populated.has_active_client_secret);
    sqlx::query("UPDATE aegaeon.client_secrets SET status='REVOKED', revoked_at=statement_timestamp() WHERE client_id=$1")
        .bind(empty.database_client_id).execute(pool).await?;
    refuses(pool, env, &populated, DcrClientSecretChange::Preserve).await
}

async fn semantic_fields(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    for (name, statement) in [
        ("name-drift", "UPDATE aegaeon.clients SET name='private-preparation-sentinel' WHERE id=$1"),
        ("issued-drift", "UPDATE aegaeon.dynamic_client_registrations SET client_id_issued_at=client_id_issued_at+interval '1 microsecond' WHERE client_id=$1"),
        ("key-drift", "UPDATE aegaeon.dynamic_client_registrations SET jwks_uri='https://client.example/new-keys' WHERE client_id=$1"),
    ] {
        let row = fixture(pool, env, name).await?;
        sqlx::query(statement).bind(row.database_client_id).execute(pool).await?;
        refuses(pool, env, &row, DcrClientSecretChange::Preserve).await?;
        let current = reload(pool, env, name).await?;
        let debug = format!("{current:?}");
        for private in ["private-preparation-sentinel", "preparation_snapshot", &current.registration_access_token_hash, "new-keys"] {
            assert!(!debug.contains(private));
        }
    }
    Ok(())
}

async fn timezone_and_bookkeeping(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let row = fixture(pool, env, "timezone-control").await?;
    sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET client_id_issued_at='2026-01-01 12:34:56.123456+00' WHERE client_id=$1")
        .bind(row.database_client_id).execute(pool).await?;
    let east = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET TIME ZONE 'Asia/Tokyo'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(pool.connect_options().as_ref().clone())
        .await?;
    let west = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET TIME ZONE 'America/New_York'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(pool.connect_options().as_ref().clone())
        .await?;
    let prepared = reload(&east, env, "timezone-control").await?;
    sqlx::query("UPDATE aegaeon.clients SET updated_at=updated_at+interval '1 day' WHERE id=$1")
        .bind(row.database_client_id)
        .execute(pool)
        .await?;
    sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET updated_at=updated_at+interval '1 day' WHERE client_id=$1")
        .bind(row.database_client_id).execute(pool).await?;
    let mut replacement = prepared.client.clone();
    replacement.redirect_uris = vec!["https://client.example/replacement".into()];
    update_dynamic_registration(
        &west,
        &prepared,
        &replacement,
        &prepared.response_types,
        "timezone-new-token",
        DcrClientSecretChange::ReplaceWithPlaintext("explicit-secret".into()),
        None,
        "timezone-update",
    )
    .await?;
    assert!(crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        "timezone-control",
        "timezone-control-owner-token"
    )
    .await?
    .is_none());
    let current = crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        "timezone-control",
        "timezone-new-token",
    )
    .await?
    .ok_or("rotated registration")?;
    assert_eq!(current.client.redirect_uris, replacement.redirect_uris);
    assert!(current.has_active_client_secret);
    east.close().await;
    west.close().await;
    Ok(())
}

async fn deletion_and_issuer(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let row = fixture(pool, env, "delete-drift").await?;
    sqlx::query("UPDATE aegaeon.clients SET name='changed-before-delete' WHERE id=$1")
        .bind(row.database_client_id)
        .execute(pool)
        .await?;
    delete_dynamic_registration(pool, &row, "metadata-drift-delete").await?;
    refuses(pool, env, &row, DcrClientSecretChange::Preserve).await?;
    let row = fixture(pool, env, "issuer-drift").await?;
    sqlx::query("UPDATE aegaeon.environments SET issuer_host='moved.example' WHERE id=$1")
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    refuses(pool, env, &row, DcrClientSecretChange::Preserve).await?;
    assert!(matches!(
        delete_dynamic_registration(pool, &row, "issuer-drift-delete").await,
        Err(DcrDatabaseError::ConcurrentModification)
    ));
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; exact preparation state and credential decisions"]
async fn owner_put_preparation_covers_semantic_state_and_secret_presence() -> TestResult {
    let db = Database::create(false).await?;
    let result = async {
        let env = setup_test_dcr_environment(&db.pool).await?;
        secret_decisions(&db.pool, &env).await?;
        semantic_fields(&db.pool, &env).await?;
        timezone_and_bookkeeping(&db.pool, &env).await?;
        deletion_and_issuer(&db.pool, &env).await
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
