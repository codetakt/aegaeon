//! Production persistence with observed PostgreSQL lock waits. These tests bypass
//! the mounted runtime guard; management-like fixture writes use its shared locks.
use super::credential_admission::{issue, stored};
use super::*;
use crate::dcr_persistence::{
    update_dynamic_registration, DcrClientSecretChange, DcrDatabaseError, DcrStoredClient,
};
use std::time::Duration;

async fn update(
    pool: &PgPool,
    row: &DcrStoredClient,
    secret: &str,
    token: &str,
) -> Result<(), DcrDatabaseError> {
    update_dynamic_registration(
        pool,
        row,
        &row.client,
        &row.response_types,
        token,
        DcrClientSecretChange::Preserve,
        Some(secret),
        "owner-credential-test",
    )
    .await
}

async fn fixture(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    name: &str,
) -> TestResult<DcrStoredClient> {
    let mut client = sample_registered_client(name);
    client.token_endpoint_auth_method = "client_secret_basic".into();
    client.client_secret = Some("issued-original-secret".into());
    let token = format!("{name}-owner-original-token");
    create_test_registration(pool, env, &client, &token).await?;
    stored(
        pool,
        env,
        &json!({"client_id":name,"registration_access_token":token}),
    )
    .await
}

async fn wait_for_lock(pool: &PgPool, blocker: i32) -> TestResult {
    tokio::time::timeout(Duration::from_secs(10),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%SELECT id FROM aegaeon.environments WHERE id = $1 FOR UPDATE%')").bind(blocker).fetch_one(pool).await?;
            if waiting { return Ok::<_,sqlx::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    Ok(())
}

async fn barrier(pool: &PgPool, env: &TestDcrEnvironment, kind: &str) -> TestResult {
    let row = fixture(pool, env, &format!("barrier-{kind}")).await?;
    let mut tx = pool.begin().await?;
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE")
        .bind(env.environment_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM aegaeon.clients WHERE id=$1 FOR UPDATE")
        .bind(row.database_client_id)
        .execute(&mut *tx)
        .await?;
    let other_pool = pool.clone();
    let stale = row.clone();
    let pending = tokio::spawn(async move {
        update(
            &other_pool,
            &stale,
            "issued-original-secret",
            "candidate-token",
        )
        .await
    });
    wait_for_lock(pool, blocker).await?;
    match kind {
        "revocation" => {
            sqlx::query("UPDATE aegaeon.client_secrets SET status='REVOKED',revoked_at=statement_timestamp() WHERE client_id=$1").bind(row.database_client_id).execute(&mut *tx).await?;
        }
        "expiry" => {
            // Set expiry only after PostgreSQL has observed the blocked update.
            // Transaction-start now() would still admit this credential later.
            sqlx::query("UPDATE aegaeon.client_secrets SET expires_at=statement_timestamp()+interval '100 milliseconds' WHERE client_id=$1").bind(row.database_client_id).execute(pool).await?;
            let started_before_expiry:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a JOIN aegaeon.client_secrets s ON s.client_id=$2 WHERE $1=ANY(pg_blocking_pids(a.pid)) AND a.query LIKE '%SELECT id FROM aegaeon.environments WHERE id = $1 FOR UPDATE%' AND a.xact_start<s.expires_at)").bind(blocker).bind(row.database_client_id).fetch_one(pool).await?;
            assert!(started_before_expiry);
            tokio::time::timeout(Duration::from_secs(10),async {
                loop {
                    let expired:bool=sqlx::query_scalar("SELECT bool_and(expires_at<=statement_timestamp()) FROM aegaeon.client_secrets WHERE client_id=$1").bind(row.database_client_id).fetch_one(pool).await?;
                    if expired {return Ok::<_,sqlx::Error>(());}
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await??;
        }
        "configuration" => {
            let next = uuid::Uuid::new_v4();
            sqlx::query("INSERT INTO aegaeon.configuration_versions(id,environment_id,version_number,configuration_hash,status,configuration_document) SELECT $1,environment_id,2,'credential-test-next','DRAFT',configuration_document FROM aegaeon.configuration_versions WHERE id=$2").bind(next).bind(row.configuration_version_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE aegaeon.clients SET configuration_version_id=$1 WHERE id=$2")
                .bind(next)
                .bind(row.database_client_id)
                .execute(&mut *tx)
                .await?;
        }
        _ => unreachable!(),
    }
    tx.commit().await?;
    let expected = digest(pool, env).await?;
    let result = tokio::time::timeout(Duration::from_secs(10), pending).await??;
    assert!(matches!(
        result,
        Err(DcrDatabaseError::ConcurrentModification)
    ));
    assert_eq!(expected, digest(pool, env).await?);
    let token:String=sqlx::query_scalar("SELECT registration_access_token_hash FROM aegaeon.dynamic_client_registrations WHERE client_id=$1").bind(row.database_client_id).fetch_one(pool).await?;
    assert_eq!(token, row.registration_access_token_hash);
    Ok(())
}

async fn eligible_sets(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let mut row = fixture(pool, env, "eligible-client").await?;
    let other = fixture(pool, env, "other-client").await?;
    issue(pool, &other, "other-client-secret").await?;
    let other_env = setup_test_dcr_environment(pool).await?;
    let outside = fixture(pool, &other_env, "eligible-client").await?;
    issue(pool, &outside, "other-environment-secret").await?;
    let other_token = "other-client-owner-original-token";
    let own_issuer = crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        &other.client.client_id,
        other_token,
    )
    .await?
    .ok_or("valid owner token must resolve under its true issuer")?;
    assert_eq!(own_issuer.database_client_id, other.database_client_id);
    assert_eq!(own_issuer.environment_id, env.environment_id);
    assert!(crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &other_env.issuer_host,
        &other.client.client_id,
        other_token,
    )
    .await?
    .is_none());
    for secret in [
        "other-client-secret",
        "other-environment-secret",
        "",
        " issued-original-secret ",
    ] {
        let before = digest(pool, env).await?;
        let error = update(pool, &row, secret, "refused-token")
            .await
            .expect_err("wrong scoped secret");
        assert!(matches!(error, DcrDatabaseError::ClientSecretMismatch));
        assert!(!format!("{error:?}").contains(secret) || secret.is_empty());
        assert_eq!(before, digest(pool, env).await?);
    }
    issue(pool, &row, "active-overlap-secret").await?;
    // Both the older and newer active issued secrets may match.
    update(pool, &row, "issued-original-secret", "older-overlap-token").await?;
    row = stored(
        pool,
        env,
        &json!({"client_id":"eligible-client","registration_access_token":"older-overlap-token"}),
    )
    .await?;
    // A malformed alternative is no match; it does not suppress a valid overlap.
    sqlx::query("UPDATE aegaeon.client_secrets SET secret_hash='unusable-hash' WHERE client_id=$1 AND comment='dynamic client registration secret'").bind(row.database_client_id).execute(pool).await?;
    let next = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.configuration_versions(id,environment_id,version_number,configuration_hash,status,configuration_document) SELECT $1,environment_id,3,'credential-provenance','DRAFT',configuration_document FROM aegaeon.configuration_versions WHERE id=$2").bind(next).bind(row.configuration_version_id).execute(pool).await?;
    sqlx::query("UPDATE aegaeon.client_secrets SET configuration_version_id=$1 WHERE client_id=$2")
        .bind(next)
        .bind(row.database_client_id)
        .execute(pool)
        .await?;
    update(
        pool,
        &row,
        "active-overlap-secret",
        "accepted-overlap-token",
    )
    .await?;
    let fresh=stored(pool,env,&json!({"client_id":"eligible-client","registration_access_token":"accepted-overlap-token"})).await?;
    sqlx::query("UPDATE aegaeon.client_secrets SET status='REVOKED',revoked_at=statement_timestamp() WHERE client_id=$1").bind(row.database_client_id).execute(pool).await?;
    assert!(matches!(
        update(pool, &fresh, "active-overlap-secret", "refused-token").await,
        Err(DcrDatabaseError::ConcurrentModification)
    ));
    // Exact bytes, including whitespace, belong to a credential assertion.
    issue(pool, &fresh, " padded-issued-secret ").await?;
    assert!(matches!(
        update(pool, &fresh, "padded-issued-secret", "refused-token").await,
        Err(DcrDatabaseError::ClientSecretMismatch)
    ));
    update(pool, &fresh, " padded-issued-secret ", "exact-bytes-token").await?;
    cleanup_test_dcr_environment(pool, &other_env).await?;
    Ok(())
}

async fn same_token(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let row = fixture(pool, env, "single-winner").await?;
    let mut tx = pool.begin().await?;
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE")
        .bind(env.environment_id)
        .execute(&mut *tx)
        .await?;
    let mut tasks = Vec::new();
    for token in ["winner-a", "winner-b"] {
        let pool = pool.clone();
        let row = row.clone();
        tasks.push(tokio::spawn(async move {
            update(&pool, &row, "issued-original-secret", token).await
        }));
    }
    wait_for_lock(pool, blocker).await?;
    tx.commit().await?;
    let mut wins = 0;
    let mut stale = 0;
    for task in tasks {
        match task.await? {
            Ok(()) => wins += 1,
            Err(DcrDatabaseError::ConcurrentModification) => stale += 1,
            Err(error) => return Err(error.into()),
        }
    }
    assert_eq!((wins, stale), (1, 1));
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; production persistence and observed DB lock barriers"]
async fn owner_put_credentials_recheck_after_lock_wait_and_single_winner() -> TestResult {
    let db = Database::create(false).await?;
    let result = async {
        let env = setup_test_dcr_environment(&db.pool).await?;
        let control = fixture(&db.pool, &env, "positive-control").await?;
        update(
            &db.pool,
            &control,
            "issued-original-secret",
            "control-new-token",
        )
        .await?;
        for kind in ["revocation", "expiry", "configuration"] {
            barrier(&db.pool, &env, kind).await?;
        }
        eligible_sets(&db.pool, &env).await?;
        same_token(&db.pool, &env).await
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
