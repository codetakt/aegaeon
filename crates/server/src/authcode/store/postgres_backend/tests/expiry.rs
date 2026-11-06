use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL; code expires during OIDC lock wait and every publication rolls back"]
async fn pg_token_code_expiry_during_oidc_binding() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let oidc = fixture.oidc()?;
        let context = OidcSessionContext {
            user_id: "subject",
            auth_session_id: "browser",
        };
        let sid = oidc
            .try_get_or_create_session_async(context)
            .await
            .map_err(anyhow::Error::msg)?;
        let prepared = oidc
            .prepare_authorization_code_grant_commit_async(context, "client")
            .await
            .map_err(anyhow::Error::msg)?;
        let mut input = AuthorizationCodeInput::new("client".into(), "subject".into(), None);
        input.auth_session_id = Some("browser".into());
        let code = AuthorizationCode::new_with_ttl(input, 2);
        fixture
            .codes()?
            .store_code_async(code.clone())
            .await
            .map_err(anyhow::Error::msg)?;
        let (_, payload) = fixture
            .codes()?
            .try_get_code_for_exchange_async(code.code.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("code missing"))?
            .into_parts();
        let mut tx = fixture.pool.begin().await?;
        sqlx::query("SELECT sid FROM aegaeon.runtime_oidc_sessions WHERE sid=$1 FOR UPDATE")
            .bind(Uuid::parse_str(&sid)?)
            .fetch_one(&mut *tx)
            .await?;
        let (a, r, m) = grant(true);
        let commit = AuthorizationCodeGrantCommit::new(
            fixture.codes()?,
            code.code,
            payload,
            a,
            r,
            m,
            Some(prepared),
        );
        let store = fixture.store();
        let job = tokio::spawn(async move {
            store
                .store_issued_authorization_code_grant_async(commit)
                .await
        });
        let mut waiting=false;
        for _ in 0..100 {
            waiting=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT aegaeon.bind_runtime_oidc_session%')").fetch_one(&fixture.pool).await?;
            if waiting {break;}
            sqlx::query("SELECT pg_sleep(0.005)").execute(&mut *tx).await?;
        }
        anyhow::ensure!(waiting,"grant must reach the actual OIDC row-lock wait");
        sqlx::query("SELECT pg_sleep(2.1)")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        anyhow::ensure!(job.await?.is_err());
        anyhow::ensure!(fixture.counts().await? == (0, 0, 1, 1));
        let clients: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_oidc_clients")
            .fetch_one(&fixture.pool)
            .await?;
        anyhow::ensure!(clients == 0);
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}
