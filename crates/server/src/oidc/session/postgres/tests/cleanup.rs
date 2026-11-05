use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL; bounded dependent cleanup, locked backlog and live records"]
async fn pg_oidc_cleanup_batches_and_locked_backlog() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let namespace=fixture.database.namespace.as_ref();
        sqlx::query("INSERT INTO aegaeon.runtime_oidc_sessions(namespace,sid,user_id,auth_digest,logout_jti,logged_out_at,expires_at) SELECT $1,gen_random_uuid(),'expired',sha256(i::text::bytea),gen_random_uuid(),1,clock_timestamp()-interval '1 second' FROM generate_series(1,8193) i").bind(namespace).execute(&fixture.pool).await?;
        sqlx::query("INSERT INTO aegaeon.runtime_oidc_auth_bindings SELECT namespace,auth_digest,sid FROM aegaeon.runtime_oidc_sessions").execute(&fixture.pool).await?;
        sqlx::query("INSERT INTO aegaeon.runtime_oidc_clients(namespace,sid,client_id) SELECT namespace,sid,'client' FROM aegaeon.runtime_oidc_sessions").execute(&fixture.pool).await?;
        let mut tx=fixture.pool.begin().await?;
        let locked:Uuid=sqlx::query_scalar("SELECT sid FROM aegaeon.runtime_oidc_auth_bindings LIMIT 1 FOR UPDATE").fetch_one(&mut *tx).await?;
        let backend=fixture.backend();
        let live=backend.get_or_create(OidcSessionContext { user_id:"live",auth_session_id:"live-browser" }).await.map_err(anyhow::Error::msg)?;
        backend.cleanup().await.map_err(anyhow::Error::msg)?;
        let remaining:Vec<Uuid>=sqlx::query_scalar("SELECT sid FROM aegaeon.runtime_oidc_sessions WHERE logout_jti IS NOT NULL").fetch_all(&fixture.pool).await?;
        anyhow::ensure!(remaining==[locked]);
        tx.rollback().await?;
        backend.cleanup().await.map_err(anyhow::Error::msg)?;
        let remaining:Vec<Uuid>=sqlx::query_scalar("SELECT sid FROM aegaeon.runtime_oidc_sessions").fetch_all(&fixture.pool).await?;
        anyhow::ensure!(remaining==[Uuid::parse_str(&live)?]);
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}
