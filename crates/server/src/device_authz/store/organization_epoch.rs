use super::*;
use crate::authcode::token::AccessTokenAudiencePolicy;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;

fn store(url: &str, prefix: &str) -> anyhow::Result<DeviceCodeStore> {
    Ok(DeviceCodeStore {
        backend: DeviceCodeStoreBackend::Redis(RedisDeviceCodeStoreBackend::new_with_prefix(
            url, prefix,
        )?),
        ttl: Duration::from_secs(60),
        default_interval_secs: 5,
    })
}

#[tokio::test]
#[ignore = "requires PostgreSQL witness and isolated Redis with multiple databases"]
async fn shared_redis_organizations_device_facades_refuse_foreign_database() -> anyhow::Result<()> {
    let id = uuid::Uuid::new_v4();
    let witness =
        CallerFixture::with_test_stores(id, std::env::var("AEGAEON_DATABASE_URL")?.parse()?)
            .await?;
    let selected = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let mut foreign = url::Url::parse(&selected)?;
    let db = redis::Client::open(selected.as_str())?
        .get_connection_info()
        .redis
        .db;
    foreign.set_path(if db == 0 { "/1" } else { "/0" });
    let prefix = format!("organization-device-epoch:{id}");
    let result = exercise(&witness, &selected, foreign.as_str(), &prefix).await;
    let cleanup = cleanup(&selected, foreign.as_str(), &prefix).await;
    let finish = witness.finish().await;
    result.and(cleanup).and(finish)
}

async fn exercise(
    witness: &CallerFixture,
    selected: &str,
    foreign: &str,
    prefix: &str,
) -> anyhow::Result<()> {
    exercise_selected(witness, &store(selected, prefix)?).await?;

    let foreign = store(foreign, prefix)?;
    for operation in 0..6 {
        // Seed outside the admitted scope: each facade must refuse this real,
        // usable store before reading or changing its live device grant.
        let code = foreign
            .try_create_with_resource_async(
                "client".into(),
                None,
                None,
                None,
                "https://issuer.example/verify".into(),
            )
            .await
            .ok_or_else(|| anyhow::anyhow!("foreign fixture allocation refused"))?;
        let work = witness.begin().await?;
        let closed = work.admission().closure_probe_for_test();
        let mut refused = false;
        let scoped = work
            .store_scope(async {
                refused = refused_operation(&foreign, &code, operation).await;
            })
            .await;
        let completion = work.complete().await;
        anyhow::ensure!(
            refused && closed.is_closed() && scoped.is_err() && completion.is_err(),
            "device facade must retain its observed owner"
        );
        anyhow::ensure!(witness.pending().await? == operation + 1);
        anyhow::ensure!(
            foreign
                .try_lookup_by_user_code_async(code.user_code)
                .await
                .map_err(anyhow::Error::msg)?
                .is_some(),
            "foreign grant must remain usable outside the refused scope"
        );
    }
    Ok(())
}

async fn cleanup(selected: &str, foreign: &str, prefix: &str) -> anyhow::Result<()> {
    for endpoint in [selected, foreign] {
        let client = redis::Client::open(endpoint)?;
        let pattern = format!("{prefix}:*");
        tokio::task::spawn_blocking(move || {
            let mut connection = crate::redis_io::connect(&client)?;
            let keys: Vec<String> = redis::cmd("KEYS").arg(pattern).query(&mut connection)?;
            if !keys.is_empty() {
                redis::cmd("DEL").arg(keys).query::<i64>(&mut connection)?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    }
    Ok(())
}

async fn exercise_selected(
    witness: &CallerFixture,
    ordinary: &DeviceCodeStore,
) -> anyhow::Result<()> {
    let normal = witness.begin().await?;
    normal
        .store_scope(async {
            let code = ordinary
                .try_create_with_resource_async(
                    "client".into(),
                    None,
                    None,
                    None,
                    "https://issuer.example/verify".into(),
                )
                .await
                .ok_or_else(|| anyhow::anyhow!("device allocation refused"))?;
            anyhow::ensure!(ordinary
                .try_lookup_by_user_code_async(code.user_code.clone())
                .await
                .map_err(anyhow::Error::msg)?
                .is_some());
            ordinary
                .try_poll_async(code.device_code.clone(), "client".into(), None, None)
                .await
                .map_err(anyhow::Error::msg)?;
            ordinary
                .try_poll_for_token_async(
                    code.device_code,
                    "client".into(),
                    None,
                    None,
                    AccessTokenAudiencePolicy::new(false, None),
                )
                .await
                .map_err(anyhow::Error::msg)?;
            anyhow::ensure!(ordinary
                .try_approve_async(code.user_code.clone(), "subject".into())
                .await
                .map_err(anyhow::Error::msg)?);
            ordinary
                .try_deny_async(code.user_code)
                .await
                .map_err(anyhow::Error::msg)?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    anyhow::ensure!(normal.complete().await?.pending == 0);

    Ok(())
}

async fn refused_operation(
    store: &DeviceCodeStore,
    code: &crate::device_authz::DeviceAuthorizationResponse,
    operation: u32,
) -> bool {
    match operation {
        0 => store
            .try_create_with_resource_async(
                "client".into(),
                None,
                None,
                None,
                "https://issuer.example/verify".into(),
            )
            .await
            .is_none(),
        1 => store
            .try_poll_async(code.device_code.clone(), "client".into(), None, None)
            .await
            .is_err(),
        2 => store
            .try_poll_for_token_async(
                code.device_code.clone(),
                "client".into(),
                None,
                None,
                AccessTokenAudiencePolicy::new(false, None),
            )
            .await
            .is_err(),
        3 => store
            .try_approve_async(code.user_code.clone(), "subject".into())
            .await
            .is_err(),
        4 => store.try_deny_async(code.user_code.clone()).await.is_err(),
        _ => store
            .try_lookup_by_user_code_async(code.user_code.clone())
            .await
            .is_err(),
    }
}
