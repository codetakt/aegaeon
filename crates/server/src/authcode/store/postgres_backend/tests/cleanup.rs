use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL; bounded token cleanup with a locked remainder and live families"]
async fn pg_token_cleanup_batches_preserve_live_and_locked_rows() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let store=fixture.store();let(a,r,m)=grant(true);let(live,_)=store.store_issued_grant_async(a,r,m).await.map_err(anyhow::Error::msg)?;
        sqlx::query("INSERT INTO aegaeon.runtime_token_capabilities(namespace,token_digest,kind,payload,metadata,client_digest,subject_digest,subject_generation,expires_us) SELECT s.namespace,sha256(i::text::bytea),1,'{}','{}',sha256('client'::bytea),s.subject_digest,s.generation,1 FROM aegaeon.runtime_token_subjects s CROSS JOIN generate_series(1,8193) i").execute(&fixture.pool).await?;
        let mut tx=fixture.pool.begin().await?;
        let locked:Vec<u8>=sqlx::query_scalar("SELECT token_digest FROM aegaeon.runtime_token_capabilities WHERE expires_us=1 LIMIT 1 FOR UPDATE").fetch_one(&mut *tx).await?;
        store.cleanup_async().await.map_err(anyhow::Error::msg)?;
        let remaining:Vec<Vec<u8>>=sqlx::query_scalar("SELECT token_digest FROM aegaeon.runtime_token_capabilities WHERE expires_us=1").fetch_all(&fixture.pool).await?;
        anyhow::ensure!(remaining==[locked]);tx.rollback().await?;
        store.cleanup_async().await.map_err(anyhow::Error::msg)?;anyhow::ensure!(fixture.counts().await?==(2,1,0,0));
        anyhow::ensure!(store.try_verify_access_token_async(live).await.map_err(anyhow::Error::msg)?.is_some());
        // Parent cleanup never cascades through unexpired descendants.
        sqlx::query("UPDATE aegaeon.runtime_refresh_families SET expires_us=1").execute(&fixture.pool).await?;
        store.cleanup_async().await.map_err(anyhow::Error::msg)?;anyhow::ensure!(fixture.counts().await?==(2,1,0,0));
        sqlx::query("UPDATE aegaeon.runtime_token_capabilities SET expires_us=1").execute(&fixture.pool).await?;
        store.cleanup_async().await.map_err(anyhow::Error::msg)?;anyhow::ensure!(fixture.counts().await?==(0,0,0,0));Ok(())
    }.await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; diagnostic observations remain reusable and are counted asynchronously"]
async fn pg_code_observation_counts_are_reusable_and_expiring() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let codes=fixture.codes()?;anyhow::ensure!(codes.observation_counts_async().await.map_err(anyhow::Error::msg)?==(0,0));
        for _ in 0..3 {let mut input=AuthorizationCodeInput::new("client".into(),"subject".into(),None);input.state=Some("same-state".into());input.nonce=Some("same-nonce".into());codes.store_code_async(AuthorizationCode::new(input)).await.map_err(anyhow::Error::msg)?;}
        anyhow::ensure!(codes.observation_counts_async().await.map_err(anyhow::Error::msg)?==(1,1));
        sqlx::query("UPDATE aegaeon.runtime_authorization_observations SET expires_at=clock_timestamp()-interval '1 second' WHERE kind=0").execute(&fixture.pool).await?;
        anyhow::ensure!(codes.observation_counts_async().await.map_err(anyhow::Error::msg)?==(0,1));Ok(())
    }.await;
    fixture.finish().await?;
    result
}
