use super::*;
use crate::organizations::witness::work::Work;

async fn write(
    work: &Work,
    client: redis::Client,
    key: String,
    value: &'static str,
) -> anyhow::Result<redis::RedisResult<()>> {
    Ok(work
        .blocking(move || {
            let mut connection = crate::redis_io::connect(&client)?;
            redis::cmd("SET").arg(key).arg(value).query(&mut connection)
        })
        .await?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis ACL; attribution permission precedes authority writes"]
async fn shared_redis_organizations_store_label_acl_refuses_before_write() -> TestResult {
    let endpoint = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let admin = redis::Client::open(endpoint.as_str())?;
    let config = redis::AsyncConnectionConfig::new()
        .set_connection_timeout(Duration::from_secs(3))
        .set_response_timeout(Duration::from_secs(3));
    let mut connection = admin
        .get_multiplexed_async_connection_with_config(&config)
        .await?;
    let user = format!("label-permission-{}", Uuid::new_v4());
    let password = Uuid::new_v4().to_string();
    let key = format!("label-permission-{}", Uuid::new_v4());
    let mut url = url::Url::parse(&endpoint)?;
    url.set_username(&user)
        .map_err(|()| anyhow::anyhow!("fixture username"))?;
    url.set_password(Some(&password))
        .map_err(|()| anyhow::anyhow!("fixture password"))?;
    let restricted = redis::Client::open(url.as_str())?;
    let witness = CallerFixture::new(Uuid::new_v4()).await?;
    let result: TestResult = async {
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&user)
            .arg("on")
            .arg(format!(">{password}"))
            .arg(format!("~{key}"))
            .arg("+ping")
            .arg("+set")
            .arg("+client|setname")
            .query_async::<()>(&mut connection)
            .await?;
        let allowed = witness.begin().await?;
        write(&allowed, restricted.clone(), key.clone(), "before-denial").await??;
        anyhow::ensure!(
            allowed.complete().await?.pending == 0,
            "allowed work must complete"
        );
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&user)
            .arg("-client|setname")
            .query_async::<()>(&mut connection)
            .await?;
        let denied = witness.begin().await?;
        let outcome = write(&denied, restricted, key.clone(), "after-denial").await?;
        let probe = denied.admission().closure_probe_for_test();
        let completion = denied.complete().await;
        let value: String = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut connection)
            .await?;
        anyhow::ensure!(
            outcome.is_err() && value == "before-denial",
            "missing attribution permission must refuse before SET"
        );
        anyhow::ensure!(
            probe.is_closed() && completion.is_err() && witness.pending().await? == 1,
            "failed setup must retain pending work"
        );
        Ok(())
    }
    .await;
    let remove_user = redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&user)
        .query_async::<u64>(&mut connection)
        .await;
    let remove_key = redis::cmd("DEL")
        .arg(&key)
        .query_async::<u64>(&mut connection)
        .await;
    drop(connection);
    let cleanup = witness.finish().await;
    result?;
    remove_user?;
    remove_key?;
    cleanup
}
