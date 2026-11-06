use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;

fn store(url: &str, prefix: &str) -> anyhow::Result<ManagementSessionStore> {
    Ok(ManagementSessionStore {
        backend: ManagementSessionBackend::Redis(RedisManagementSessionBackend::new_with_key(
            url,
            Arc::<str>::from(prefix),
        )?),
        session_ttl_secs: 60,
        max_sessions: 16,
    })
}

#[tokio::test]
#[ignore = "requires PostgreSQL witness and isolated Redis with multiple databases"]
async fn shared_redis_organizations_management_sessions_refuse_foreign_database(
) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
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
    let prefix = format!("organization-management-epoch:{id}");
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
    let administrator = Uuid::new_v4();
    let now = crate::util::now_unix_epoch_secs()?;
    let ordinary = store(selected, prefix)?;
    let normal = witness.begin().await?;
    normal
        .store_scope(async {
            let sid = ordinary
                .try_create_async(administrator, now)
                .await
                .map_err(anyhow::Error::msg)?
                .ok_or_else(|| anyhow::anyhow!("session allocation refused"))?;
            let current = ordinary
                .try_get_async(sid.clone(), now)
                .await
                .map_err(anyhow::Error::msg)?
                .ok_or_else(|| anyhow::anyhow!("live session absent"))?;
            anyhow::ensure!(
                current.administrator_id == administrator && current.is_human_session()
            );
            anyhow::ensure!(ordinary
                .try_delete_async(sid)
                .await
                .map_err(anyhow::Error::msg)?);
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    anyhow::ensure!(normal.complete().await?.pending == 0);

    let foreign = store(foreign, prefix)?;
    let sid = foreign
        .try_create_async(administrator, now)
        .await
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("foreign fixture allocation refused"))?;
    for operation in 0..3 {
        let work = witness.begin().await?;
        let closed = work.admission().closure_probe_for_test();
        let mut refused = false;
        let scoped = work
            .store_scope(async {
                refused = match operation {
                    0 => foreign.try_create_async(administrator, now).await.is_err(),
                    1 => foreign.try_get_async(sid.clone(), now).await.is_err(),
                    _ => foreign.try_delete_async(sid.clone()).await.is_err(),
                };
            })
            .await;
        let completion = work.complete().await;
        anyhow::ensure!(
            refused && closed.is_closed() && scoped.is_err() && completion.is_err(),
            "session facade must observe its actual connection"
        );
        anyhow::ensure!(witness.pending().await? == operation + 1);
        anyhow::ensure!(
            foreign
                .try_get_async(sid.clone(), now)
                .await
                .map_err(anyhow::Error::msg)?
                .is_some(),
            "foreign session must not be consumed or deleted"
        );
    }
    anyhow::ensure!(foreign
        .try_delete_async(sid)
        .await
        .map_err(anyhow::Error::msg)?);
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
