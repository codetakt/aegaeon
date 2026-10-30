use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; real AS replay commit with lost acknowledgement"]
async fn shared_redis_organizations_as_proof_loss_retains_witness_admission() -> TestResult {
    let fixture = Fixture::with_identifier(IDENTIFIER).await?;
    let state = fixture::state(&fixture).await?;
    let witness = CallerFixture::new(state.environment_id).await?;
    let result = exercise(&fixture, &state, &witness).await;
    let witness_cleanup = witness.finish().await;
    let state_cleanup = fixture::finish(&state).await;
    let result = result.map_err(|error| -> Box<dyn std::error::Error> { error.into() });
    let cleanup = witness_cleanup.map_err(|error| -> Box<dyn std::error::Error> { error.into() });
    fixture
        .cleanup(result.and(cleanup).and(state_cleanup))
        .await
}

async fn exercise(
    fixture: &Fixture,
    state: &AppState,
    witness: &CallerFixture,
) -> anyhow::Result<()> {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let first = witness.begin().await?;
    let parent = first
        .store_scope(async {
            fixture::parent(fixture, state, &key)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
        })
        .await??;
    anyhow::ensure!(first.complete().await?.pending == 0);
    let source = parent["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("parent"))?;
    let ordinary = witness.begin().await?;
    let selected = ordinary
        .store_scope(async {
            select(state, source, &key, IDENTIFIER)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
        })
        .await??;
    anyhow::ensure!(selected.0 == StatusCode::OK, "normal AS issuance");
    anyhow::ensure!(ordinary.complete().await?.pending == 0);

    let upstream = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = format!("redis://{}/", listener.local_addr()?);
    let proxy_client = upstream.clone();
    let peer = std::thread::spawn(move || super::replay_completion::proxy(listener, &proxy_client));
    let mut failed = state.clone();
    failed.dpop = Arc::new(
        crate::middleware::DpopMiddleware::new(
            state.environment_id.to_string(),
            state.issuer.as_str(),
            Arc::new(crate::middleware::replay_store::RedisReplayStore::new_for_tests(&url)?),
            Duration::from_secs(360),
        )
        .with_native_verifier_for_tests(),
    );
    let work = witness.begin().await?;
    let closed = work.admission().closure_probe_for_test();
    let mut response = None;
    let scoped = work
        .store_scope(async {
            response = Some(
                select(&failed, source, &key, IDENTIFIER)
                    .await
                    .map_err(|e| e.to_string()),
            );
        })
        .await;
    let completion = work.complete().await;
    let (replay_key, mutations) = tokio::task::spawn_blocking(move || {
        peer.join()
            .map_err(|_| anyhow::anyhow!("replay proxy panic"))?
    })
    .await??;
    let value = tokio::task::spawn_blocking(move || -> redis::RedisResult<Option<String>> {
        let mut connection = crate::redis_io::connect(&upstream)?;
        let value = redis::cmd("GET").arg(&replay_key).query(&mut connection)?;
        redis::cmd("DEL")
            .arg(&replay_key)
            .query::<i64>(&mut connection)?;
        Ok(value)
    })
    .await??;
    let response = response
        .ok_or_else(|| anyhow::anyhow!("no HTTP response"))?
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        value.as_deref() == Some("1") && mutations == 1,
        "actual one replay mutation"
    );
    anyhow::ensure!(
        response.0 == StatusCode::SERVICE_UNAVAILABLE,
        "AS loss must refuse"
    );
    anyhow::ensure!(
        closed.is_closed(),
        "AS proof worker must close its actual witness owner"
    );
    anyhow::ensure!(
        scoped.is_err() && completion.is_err(),
        "uncertain work cannot complete"
    );
    anyhow::ensure!(
        witness.pending().await? == 1,
        "durable admission remains pending"
    );
    Ok(())
}
