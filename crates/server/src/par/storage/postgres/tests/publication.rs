use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; PAR collision/replay rolls back coupled JAR publication"]
async fn pg_par_jar_collision_and_replay_publish_no_partial_request() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let database=grant_database(fixture.pool.clone());
        let backend=PostgresParRequestStore::new(database.clone());
        let jar=crate::request_object_store::RequestObjectJtiStore::from_postgres(300,database)?;
        let context=jar.authorization_code_commit_context_for("par-client","jar-once",Duration::from_secs(60))?.ok_or_else(||anyhow::anyhow!("JAR context missing"))?;
        let first=crate::par::ParStore::generate_request_uri();
        backend.insert(&first,stored()?).await?;
        anyhow::ensure!(backend.insert_with_jti(&first,stored()?,Some(context.clone())).await.is_err());
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_request_object_jtis").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(count==0);
        let mut wrong_client=stored()?;wrong_client.client_id="other-client".into();wrong_client.request.client_id="other-client".into();
        anyhow::ensure!(backend.insert_with_jti(&crate::par::ParStore::generate_request_uri(),wrong_client,Some(context.clone())).await.is_err());
        let second=crate::par::ParStore::generate_request_uri();
        backend.insert_with_jti(&second,stored()?,Some(context.clone())).await?;
        let replay=crate::par::ParStore::generate_request_uri();
        anyhow::ensure!(matches!(backend.insert_with_jti(&replay,stored()?,Some(context)).await,Err(ParStorageError::RequestObjectReplay)));
        anyhow::ensure!(backend.load(&replay).await?.is_none());
        let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM aegaeon.runtime_par_requests),(SELECT count(*) FROM aegaeon.runtime_request_object_jtis)").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(counts==(2,1));
        anyhow::ensure!(matches!(backend.reserve(&second,"par-client",&"a".repeat(43)).await?,Lookup::Found(_)));
        sqlx::query("UPDATE aegaeon.runtime_par_requests SET payload=payload||' ' WHERE token_digest=$1").bind(sha256_digest(second.as_bytes()).as_slice()).execute(&fixture.pool).await?;
        anyhow::ensure!(backend.load(&second).await.is_err());
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}
