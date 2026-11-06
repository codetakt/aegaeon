use super::*;
use crate::authcode::store::RefreshRotationError;

fn successor(parent: &RefreshToken) -> (AccessToken, RefreshToken, BearerTokenMeta) {
    let next = parent.clone().rotate();
    let (mut a, _, mut m) = grant(false);
    a.refresh_grant = next.refresh_grant.clone();
    m.refresh_grant = next.refresh_grant.clone();
    m.refresh_parent = Some(next.token.clone());
    (a, next, m)
}

async fn initial(fixture: &Fixture) -> anyhow::Result<RefreshToken> {
    let store = fixture.store();
    let (a, r, m) = grant(true);
    let (_, refresh) = store
        .store_issued_grant_async(a, r, m)
        .await
        .map_err(anyhow::Error::msg)?;
    store
        .try_get_refresh_token_async(refresh.ok_or_else(|| anyhow::anyhow!("refresh missing"))?)
        .await
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("refresh absent"))
}

#[tokio::test]
#[ignore = "requires PostgreSQL; one successor and reuse denial covers every descendant"]
async fn pg_token_rotation_race_revokes_family() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let parent = initial(&fixture).await?;
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let (a, r, m) = successor(&parent);
            let store = fixture.store();
            let previous = parent.token.clone();
            jobs.spawn(async move { store.store_refreshed_grant_async(previous, a, r, m).await });
        }
        let mut success = Vec::new();
        let mut reused = 0;
        let mut invalid = 0;
        while let Some(result) = jobs.join_next().await {
            match result? {
                Ok(value) => success.push(value),
                Err(RefreshRotationError::Reused) => reused += 1,
                Err(RefreshRotationError::Invalid) => invalid += 1,
                Err(error) => anyhow::bail!("unexpected rotation error: {error:?}"),
            }
        }
        anyhow::ensure!(success.len() == 1 && reused == 1 && invalid == 30);
        anyhow::ensure!(fixture.counts().await? == (4, 1, 0, 0));
        let (access, refresh) = success.remove(0);
        let store = fixture.store();
        anyhow::ensure!(store
            .try_verify_access_token_async(access)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(store
            .try_is_refresh_revoked_async(refresh)
            .await
            .map_err(anyhow::Error::msg)?);
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; invalid successor and publication collision preserve active parent"]
async fn pg_token_rotation_collision_and_changed_binding() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let parent = initial(&fixture).await?;
        let store = fixture.store();
        let (a, mut r, m) = successor(&parent);
        r.auth_time_epoch_secs += 1;
        anyhow::ensure!(matches!(
            store
                .store_refreshed_grant_async(parent.token.clone(), a, r, m)
                .await,
            Err(RefreshRotationError::InconsistentGrant)
        ));
        let (mut a, r, mut m) = successor(&parent);
        a.token = parent.token.clone();
        m.token_id = a.token.clone();
        anyhow::ensure!(matches!(
            store
                .store_refreshed_grant_async(parent.token.clone(), a, r, m)
                .await,
            Err(RefreshRotationError::BackendUnavailable)
        ));
        anyhow::ensure!(fixture.counts().await? == (2, 1, 0, 0));
        let prepared = store
            .prepare_refresh_rotation_async(parent.token.clone())
            .await
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        anyhow::ensure!(!prepared.rotated);
        let (a, r, m) = successor(&parent);
        let (access, next) = store
            .store_refreshed_grant_async(parent.token.clone(), a, r, m)
            .await
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        anyhow::ensure!(store
            .try_verify_access_token_async(access.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        anyhow::ensure!(matches!(
            store.prepare_refresh_rotation_async(parent.token).await,
            Err(RefreshRotationError::Reused)
        ));
        anyhow::ensure!(store
            .try_verify_access_token_async(access)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(store
            .try_is_refresh_revoked_async(next)
            .await
            .map_err(anyhow::Error::msg)?);
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}
