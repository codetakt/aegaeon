use super::*;
#[tokio::test]
#[ignore = "requires PostgreSQL; 32 prepared device redemptions publish exactly one capability"]
async fn pg_device_redemption_concurrent_atomic_publication() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let (store, code) = f.create(60, None).await?;
        let commit = f.prepare(&store, &code).await?;
        anyhow::ensure!(
            f.count().await? == (1, 0),
            "preparation must retain approval"
        );
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let tokens = f.tokens();
            let receipt = commit.clone();
            jobs.spawn(async move {
                let (a, m) = grant();
                tokens.store_device_grant_async(a, m, Some(receipt)).await
            });
        }
        let mut success = 0;
        let mut refused = 0;
        while let Some(result) = jobs.join_next().await {
            match result? {
                Ok(token) => {
                    success += 1;
                    anyhow::ensure!(f
                        .tokens()
                        .try_verify_access_token_async(token)
                        .await
                        .map_err(anyhow::Error::msg)?
                        .is_some());
                }
                Err(_) => refused += 1,
            }
        }
        anyhow::ensure!(success == 1 && refused == 31 && f.count().await? == (0, 1));
        anyhow::ensure!(matches!(
            store
                .try_poll_async(code.device_code, "client".into(), None, None)
                .await
                .map_err(anyhow::Error::msg)?,
            DevicePollResult::ExpiredToken
        ));
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; failed token writes preserve approved device input, identity and audience binding"]
async fn pg_device_redemption_rollback_and_database_binding() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let (store, code) = f.create(60, None).await?;
        let commit = f.prepare(&store, &code).await?;
        let (a, m) = grant();
        let token = f
            .tokens()
            .store_issued_grant_async(a.clone(), None, m.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .0;
        anyhow::ensure!(f
            .tokens()
            .store_device_grant_async(a, m, Some(commit.clone()))
            .await
            .is_err());
        anyhow::ensure!(f.count().await? == (1, 1));
        let (a, mut m) = grant();
        m.audience = "changed".into();
        anyhow::ensure!(f
            .tokens()
            .store_device_grant_async(a, m, Some(commit.clone()))
            .await
            .is_err());
        let foreign = TokenStore::from_postgres(PostgresGrantDatabase::new(
            f.pool.clone(),
            &crate::config::RuntimeStateNamespace::from_environment_id(Uuid::new_v4()),
        ));
        let (a, m) = grant();
        anyhow::ensure!(foreign
            .store_device_grant_async(a, m, Some(commit.clone()))
            .await
            .is_err());
        let (a, m) = grant();
        f.tokens()
            .store_device_grant_async(a, m, Some(commit))
            .await
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(f.count().await? == (0, 2));
        anyhow::ensure!(f
            .tokens()
            .try_verify_access_token_async(token)
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; identity/resource failures do not change polling or approval state"]
async fn pg_device_polling_decisions_and_wrong_context() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let (store, code) = f.create(60, Some("https://api.example/")).await?;
        let inspect = || {
            sqlx::query_as::<_, (Option<i64>, i64, i16)>(
                "SELECT last_poll_us,interval_secs,status FROM aegaeon.runtime_device_codes",
            )
            .fetch_one(&f.pool)
        };
        let initial = inspect().await?;
        anyhow::ensure!(matches!(
            store
                .try_poll_async(code.device_code.clone(), "other".into(), None, None)
                .await
                .map_err(anyhow::Error::msg)?,
            DevicePollResult::InvalidGrant
        ));
        anyhow::ensure!(matches!(
            store
                .try_poll_async(
                    code.device_code.clone(),
                    "client".into(),
                    Some("wrong".into()),
                    None
                )
                .await
                .map_err(anyhow::Error::msg)?,
            DevicePollResult::ExpiredToken
        ));
        anyhow::ensure!(matches!(
            store
                .try_poll_async(
                    code.device_code.clone(),
                    "client".into(),
                    None,
                    Some("https://wrong.example/".into())
                )
                .await
                .map_err(anyhow::Error::msg)?,
            DevicePollResult::InvalidTarget
        ));
        anyhow::ensure!(inspect().await? == initial);
        anyhow::ensure!(store
            .try_lookup_by_user_code_async(code.user_code.clone())
            .await
            .map_err(anyhow::Error::msg)?
            .is_some());
        anyhow::ensure!(matches!(
            store
                .try_poll_async(code.device_code.clone(), "client".into(), None, None)
                .await
                .map_err(anyhow::Error::msg)?,
            DevicePollResult::AuthorizationPending
        ));
        anyhow::ensure!(matches!(
            store
                .try_poll_async(code.device_code.clone(), "client".into(), None, None)
                .await
                .map_err(anyhow::Error::msg)?,
            DevicePollResult::SlowDown
        ));
        anyhow::ensure!(inspect().await?.1 == 10);
        let mut jobs = tokio::task::JoinSet::new();
        for i in 0..32 {
            let store = store.clone();
            let user = code.user_code.clone();
            jobs.spawn(async move {
                if i % 2 == 0 {
                    store.try_approve_async(user, "subject".into()).await
                } else {
                    store.try_deny_async(user).await
                }
            });
        }
        let mut won = 0;
        while let Some(result) = jobs.join_next().await {
            if result?.map_err(anyhow::Error::msg)? {
                won += 1;
            }
        }
        anyhow::ensure!(won == 1);
        anyhow::ensure!(store
            .try_lookup_by_user_code_async(code.user_code)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(
            store
                .try_poll_for_token_async(
                    code.device_code,
                    "client".into(),
                    None,
                    None,
                    AccessTokenAudiencePolicy::new(false, None)
                )
                .await
                .is_err(),
            "SQL token consumption requires a commit context"
        );
        Ok(())
    }
    .await;
    f.cleanup(result).await
}
