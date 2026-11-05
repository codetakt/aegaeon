use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;

fn value() -> UpstreamLogoutRelayState {
    UpstreamLogoutRelayState {
        incident_id: None,
        downstream_redirect_uri: "https://client.example/logout".into(),
        downstream_state: None,
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL witness and isolated Redis with multiple databases"]
async fn shared_redis_organizations_logout_relay_refuses_foreign_database() -> anyhow::Result<()> {
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
    let prefix = format!("organization-relay-epoch:{id}");
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
    let ordinary =
        UpstreamLogoutRelayStore::redis_for_test(selected, prefix, Duration::from_secs(60))
            .map_err(anyhow::Error::msg)?;
    let normal = witness.begin().await?;
    normal
        .store_scope(async {
            ordinary
                .try_insert_async("ordinary".into(), value())
                .await
                .map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                ordinary
                    .try_take_async("ordinary".into())
                    .await
                    .map_err(anyhow::Error::msg)?
                    == Some(value())
            );
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    anyhow::ensure!(normal.complete().await?.pending == 0);

    let foreign =
        UpstreamLogoutRelayStore::redis_for_test(foreign, prefix, Duration::from_secs(60))
            .map_err(anyhow::Error::msg)?;
    for insert in [false, true] {
        foreign
            .try_insert_async("foreign".into(), value())
            .await
            .map_err(anyhow::Error::msg)?;
        let work = witness.begin().await?;
        let closed = work.admission().closure_probe_for_test();
        let mut refused = false;
        let scoped = work
            .store_scope(async {
                refused = if insert {
                    foreign
                        .try_insert_async("refused".into(), value())
                        .await
                        .is_err()
                } else {
                    foreign.try_take_async("foreign".into()).await.is_err()
                };
            })
            .await;
        let completion = work.complete().await;
        anyhow::ensure!(
            refused && closed.is_closed() && scoped.is_err() && completion.is_err(),
            "relay facade must observe its actual connection"
        );
        anyhow::ensure!(
            foreign
                .try_take_async("foreign".into())
                .await
                .map_err(anyhow::Error::msg)?
                == Some(value()),
            "foreign relay must not be consumed"
        );
        anyhow::ensure!(
            foreign
                .try_take_async("refused".into())
                .await
                .map_err(anyhow::Error::msg)?
                .is_none(),
            "foreign insertion must not occur"
        );
    }
    anyhow::ensure!(witness.pending().await? == 2);
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
