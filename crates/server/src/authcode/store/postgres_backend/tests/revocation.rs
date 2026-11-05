use super::*;
use crate::authcode::store::ClientBoundRevocationOutcome as Outcome;

#[tokio::test]
#[ignore = "requires PostgreSQL; exact client/subject ownership and independent current generations"]
async fn pg_token_revocation_scope_and_subject_generation() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let store = fixture.store();
        let (a, r, m) = grant(true);
        let (first, refresh) = store
            .store_issued_grant_async(a, r, m)
            .await
            .map_err(anyhow::Error::msg)?;
        let (a, r, m) = grant(true);
        let (second, _) = store
            .store_issued_grant_async(a, r, m)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            store
                .try_revoke_token_for_client_async(first.clone(), Some("wrong-client".into()))
                .await
                .map_err(anyhow::Error::msg)?
                == Outcome::OwnerMismatch
        );
        anyhow::ensure!(
            store
                .try_revoke_token_for_client_async("unknown".into(), None)
                .await
                .map_err(anyhow::Error::msg)?
                == Outcome::Unknown
        );
        anyhow::ensure!(!store
            .try_revoke_access_token_for_subject_async("wrong-subject".into(), first.clone())
            .await
            .map_err(anyhow::Error::msg)?);
        anyhow::ensure!(store
            .try_revoke_access_token_for_subject_async("subject".into(), first.clone())
            .await
            .map_err(anyhow::Error::msg)?);
        anyhow::ensure!(store
            .try_verify_access_token_async(first)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(store
            .try_verify_access_token_async(second.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        let (mut a, r, mut m) = grant(false);
        a.user_id = "other".into();
        m.user_id = "other".into();
        let (other, _) = store
            .store_issued_grant_async(a, r, m)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            store
                .try_revoke_tokens_by_subject_async("subject".into())
                .await
                .map_err(anyhow::Error::msg)?
                == 3
        );
        anyhow::ensure!(store
            .try_verify_access_token_async(second)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(store
            .try_get_refresh_token_async(refresh.ok_or_else(|| anyhow::anyhow!("refresh missing"))?)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(store
            .try_verify_access_token_async(other)
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        let (a, r, m) = grant(false);
        let (new, _) = store
            .store_issued_grant_async(a, r, m)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store
            .try_verify_access_token_async(new)
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; missing subject authority and fresh publication after revoke-all"]
async fn pg_token_subject_generation_loss_and_waiting_publisher() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let store = fixture.store();
        let (a, r, m) = grant(false);
        let (old, _) = store
            .store_issued_grant_async(a, r, m)
            .await
            .map_err(anyhow::Error::msg)?;
        let mut tx = fixture.pool.begin().await?;
        sqlx::query("UPDATE aegaeon.runtime_token_subjects SET generation=gen_random_uuid()")
            .execute(&mut *tx)
            .await?;
        let child = store.clone();
        let (a, r, m) = grant(false);
        let job = tokio::spawn(async move { child.store_issued_grant_async(a, r, m).await });
        sqlx::query("SELECT pg_sleep(0.1)")
            .execute(&mut *tx)
            .await?;
        anyhow::ensure!(!job.is_finished());
        tx.commit().await?;
        let (new, _) = job.await?.map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store
            .try_verify_access_token_async(old.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(store
            .try_verify_access_token_async(new.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        let mut tx = fixture.pool.begin().await?;
        sqlx::query("SET LOCAL session_replication_role='replica'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM aegaeon.runtime_token_subjects")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        anyhow::ensure!(store
            .try_verify_access_token_async(new.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        let (a, r, m) = grant(false);
        let (fresh, _) = store
            .store_issued_grant_async(a, r, m)
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(store
            .try_verify_access_token_async(old)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(store
            .try_verify_access_token_async(new)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(store
            .try_verify_access_token_async(fresh)
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}
