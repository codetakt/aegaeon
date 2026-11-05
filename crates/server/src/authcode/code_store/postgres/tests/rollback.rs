use super::*;

async fn counts(pool: &PgPool) -> anyhow::Result<(i64, i64, i64, i64)> {
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.runtime_par_requests),(SELECT count(*) FROM aegaeon.runtime_authorization_codes),(SELECT count(*) FROM aegaeon.runtime_request_object_jtis),(SELECT count(*) FROM aegaeon.runtime_authorization_observations)").fetch_one(pool).await?)
}

async fn explicit_rollback(
    fixture: &Fixture,
    inputs: &AuthorizationCodeOneTimeInputCommit,
) -> anyhow::Result<()> {
    let Some(ParAuthorizationCodeCommit::Postgres {
        request_digest,
        expected_continuation,
        ..
    }) = &inputs.par
    else {
        anyhow::bail!("PAR context missing")
    };
    let Some(RequestObjectJtiAuthorizationCodeCommit::Postgres { digest, ttl_ms, .. }) =
        &inputs.request_object_jti
    else {
        anyhow::bail!("JAR context missing")
    };
    let code = code();
    let mut tx = fixture.pool.begin().await?;
    let outcome: i32 = sqlx::query_scalar(
        "SELECT aegaeon.issue_runtime_authorization_code($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(fixture.database.namespace.as_ref())
    .bind(sha256_digest(code.code.as_bytes()).as_slice())
    .bind(sha256_digest(code.client_id.as_bytes()).as_slice())
    .bind(serde_json::to_string(&code)?)
    .bind(expiry_micros(code.expires_at)?)
    .bind(sha256_digest(b"shared-state").as_slice())
    .bind(sha256_digest(b"shared-nonce").as_slice())
    .bind(300_000_i64)
    .bind(request_digest.as_slice())
    .bind(expected_continuation)
    .bind(digest.as_slice())
    .bind(ttl_ms)
    .fetch_one(&mut *tx)
    .await?;
    anyhow::ensure!(outcome == 0);
    tx.rollback().await?;
    anyhow::ensure!(counts(&fixture.pool).await? == (1, 0, 0, 0));
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; rollback and expiry after observation lock preserve PAR/JAR/code atomicity"]
async fn pg_code_transaction_rollback_and_expiry_after_lock() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let backend=fixture.backend()?;
        let inputs=AuthorizationCodeOneTimeInputCommit{par:Some(fixture.par().await?), request_object_jti:Some(fixture.jti("rollback-jti")?)};
        explicit_rollback(&fixture,&inputs).await?;
        backend.issue(code(),AuthorizationCodeOneTimeInputCommit::default()).await?;
        let mut lock=fixture.pool.begin().await?;
        sqlx::query("SELECT 1 FROM aegaeon.runtime_authorization_observations WHERE kind=0 FOR UPDATE").execute(&mut *lock).await?;
        let mut expiring=code(); expiring.expires_at=SystemTime::now()+Duration::from_millis(300);
        let deadline=expiring.expires_at;
        let worker=tokio::spawn(async move { backend.issue(expiring,inputs).await });
        tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE 'SELECT aegaeon.issue_runtime_authorization_code%')").bind(&fixture.name).fetch_one(&fixture.admin).await?;
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_,sqlx::Error>(())
        }).await??;
        tokio::time::timeout(Duration::from_secs(2),async {
            while SystemTime::now()<=deadline { tokio::time::sleep(Duration::from_millis(10)).await; }
        }).await?;
        lock.commit().await?;
        anyhow::ensure!(matches!(worker.await?,Err(StoreCodeError::Expired)));
        anyhow::ensure!(counts(&fixture.pool).await?==(1,1,0,2));
        let available:bool=sqlx::query_scalar("SELECT continuation IS NOT NULL FROM aegaeon.runtime_par_requests").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(available);
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}
