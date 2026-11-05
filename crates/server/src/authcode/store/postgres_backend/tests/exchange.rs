use super::*;
use crate::authcode::store::RetainedRoot;
use crate::policy::token_exchange::TokenExchangePolicy;

fn policy() -> anyhow::Result<TokenExchangePolicy> {
    Ok(serde_json::from_value(
        serde_json::json!({"version":1,"targets":[{"audience":"api","resourceAliases":[]}],"rules":[{"clientId":"client","sourceAudience":"client","targetAudience":"api","scopes":[{"targetScope":"api.read","sourceScopes":["read"]}],"defaultScopes":["api.read"]}]}),
    )?)
}

async fn initial(fixture: &Fixture) -> anyhow::Result<(RefreshToken, BearerTokenMeta)> {
    let (mut a, r, mut m) = grant(true);
    let mut r = r.ok_or_else(|| anyhow::anyhow!("refresh missing"))?;
    r.exchange_grant = policy()?
        .capture(
            "issuer",
            "client",
            "subject",
            "client",
            &["read".into()],
            &["api.read".into()],
        )
        .map(|g| g.with_lineage_deadline(SystemTime::now() + Duration::from_secs(900)));
    a.exchange_root = r.exchange_grant.as_ref().and_then(|g| g.root()).cloned();
    m.exchange_grant = r.exchange_grant.clone();
    let store = fixture.store();
    let (access, refresh) = store
        .store_issued_grant_async(a, Some(r), m)
        .await
        .map_err(anyhow::Error::msg)?;
    let r = store
        .try_get_refresh_token_async(refresh.ok_or_else(|| anyhow::anyhow!("refresh missing"))?)
        .await
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("refresh absent"))?;
    let m = store
        .try_get_bearer_meta_async(access)
        .await
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("metadata absent"))?;
    Ok((r, m))
}

fn output(subject: &BearerTokenMeta) -> anyhow::Result<(AccessToken, BearerTokenMeta)> {
    let (scopes, selected) = policy()?
        .authorize(
            subject
                .exchange_grant
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("exchange grant missing"))?,
            "issuer",
            "client",
            "subject",
            "client",
            &subject.granted_scopes,
            "api",
            None,
        )
        .map_err(anyhow::Error::msg)?;
    let (mut a, _, mut m) = grant(false);
    a.scope = Some(scopes.join(" "));
    a.expires_in = 120;
    a.refresh_grant = subject.refresh_grant.clone();
    a.exchange_root = selected.root().cloned();
    m.refresh_grant = subject.refresh_grant.clone();
    m.refresh_parent = subject.refresh_parent.clone();
    m.audience = "api".into();
    m.granted_scopes = scopes;
    m.exchange_grant = Some(selected);
    m.expires_at = a.created_at + Duration::from_secs(120);
    Ok((a, m))
}

#[tokio::test]
#[ignore = "requires PostgreSQL; retained parent remint, exact subject snapshot and target restriction"]
async fn pg_token_exchange_and_remint_preserve_current_authority() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let (refresh, subject) = initial(&fixture).await?;
        let store = fixture.store();
        let (mut a, _, mut m) = grant(false);
        a.refresh_grant = refresh.refresh_grant.clone();
        a.exchange_root = refresh
            .exchange_grant
            .as_ref()
            .and_then(|g| g.root())
            .cloned();
        m.refresh_grant = refresh.refresh_grant.clone();
        m.refresh_parent = Some(refresh.token.clone());
        m.exchange_grant = refresh.exchange_grant.clone();
        let reminted = store
            .store_access_for_refresh_parent_async(a, m)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store
            .try_verify_access_token_async(reminted)
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        let (a, m) = output(&subject)?;
        let issued = store
            .store_exchanged_access_async(a, m, subject.clone())
            .await?;
        anyhow::ensure!(store
            .try_get_bearer_meta_async(issued.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_some_and(|m| m.audience == "api"));
        let (a, m) = output(&subject)?;
        let mut changed = subject.clone();
        changed.audience = "different".into();
        anyhow::ensure!(store
            .store_exchanged_access_async(a, m, changed)
            .await
            .is_err());
        let (a, mut m) = output(&subject)?;
        m.audience = "different".into();
        anyhow::ensure!(store
            .store_exchanged_access_async(a, m, subject.clone())
            .await
            .is_err());
        anyhow::ensure!(fixture.counts().await? == (4, 1, 0, 0));
        store
            .try_revoke_token_for_client_async(refresh.token, Some("client".into()))
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store
            .try_verify_access_token_async(issued)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        let (a, m) = output(&subject)?;
        anyhow::ensure!(store
            .store_exchanged_access_async(a, m, subject)
            .await
            .is_err());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; retained authority reuses one connection and fences concurrent revocation"]
async fn pg_token_retained_root_one_connection_and_missing_root() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let single = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(1))
        .connect_with(fixture.pool.connect_options().as_ref().clone())
        .await?;
    let result = async {
        let (refresh, subject) = initial(&fixture).await?;
        let retained = RetainedRoot {
            root: subject
                .exchange_grant
                .as_ref()
                .and_then(|g| g.root())
                .ok_or_else(|| anyhow::anyhow!("root missing"))?
                .clone(),
            refresh_grant: subject.refresh_grant.clone(),
            client: subject.client_id.clone(),
            subject: subject.user_id.clone(),
        };
        let mut database = fixture.database.clone();
        database.pool = single.clone();
        let store = TokenStore::from_postgres(database);
        let mut tx = single.begin().await?;
        anyhow::ensure!(store
            .retained_root_deadline_on_async(&mut tx, retained.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        let revoker = fixture.store();
        let token = refresh.token;
        let job = tokio::spawn(async move {
            revoker
                .try_revoke_token_for_client_async(token, Some("client".into()))
                .await
        });
        sqlx::query("SELECT pg_sleep(0.1)")
            .execute(&mut *tx)
            .await?;
        anyhow::ensure!(!job.is_finished());
        tx.commit().await?;
        job.await?.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store
            .retained_root_deadline_async(retained.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        let (_, fresh) = initial(&fixture).await?;
        let retained = RetainedRoot {
            root: fresh
                .exchange_grant
                .as_ref()
                .and_then(|g| g.root())
                .ok_or_else(|| anyhow::anyhow!("fresh root missing"))?
                .clone(),
            refresh_grant: fresh.refresh_grant,
            client: fresh.client_id,
            subject: fresh.user_id,
        };
        anyhow::ensure!(store
            .retained_root_deadline_async(retained.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        let mut tx = fixture.pool.begin().await?;
        sqlx::query("SET LOCAL session_replication_role='replica'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM aegaeon.runtime_exchange_roots")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        anyhow::ensure!(store
            .retained_root_deadline_async(retained)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        Ok(())
    }
    .await;
    single.close().await;
    fixture.finish().await?;
    result
}
