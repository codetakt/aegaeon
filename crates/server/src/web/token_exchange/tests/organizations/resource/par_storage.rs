use super::*;
use std::time::{Duration, Instant};

fn fields(state: &AppState) -> Vec<(String, String)> {
    vec![
        ("client_id".into(), OWNER.into()),
        ("state".into(), "store-worker-state".into()),
        ("iss".into(), state.issuer.as_str().into()),
        ("response_type".into(), "code".into()),
        ("redirect_uri".into(), "https://example.test/cb".into()),
        ("scope".into(), "read".into()),
        (
            "code_challenge".into(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
        ),
        ("code_challenge_method".into(), "S256".into()),
    ]
}

fn proof(state: &AppState, key: &aegaeon_crypto::signing::Ed25519KeyData) -> TestResult<String> {
    crate::web::test_support::native_dpop::proof(
        state,
        key,
        json!({"htu":format!("{}/par", state.issuer)}),
    )
}

fn failed_store(state: &AppState, url: &str) -> TestResult<AppState> {
    let mut failed = state.clone();
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let store = Arc::new(crate::par::ParStore::redis_for_tests(url, 90, &namespace)?);
    let metrics = aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?;
    failed.protocol.par_endpoint = Arc::new(crate::par::ParEndpoint::new(
        Arc::new(crate::metrics_integration::MetricsIntegration::new(
            Arc::new(metrics),
        )),
        store.clone(),
    ));
    failed.protocol.par_store = store;
    Ok(failed)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_par_storage_capacity_cancel_failure_and_recovery() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let capacity = crate::web::par_endpoint::reserve_for_test()?;
        assert_eq!(
            proof_workers::post_form(&state, "/par", &fields(&state), &proof(&state, &key)?)
                .await?,
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(capacity);
        for cancel in [false, true] {
            let (url, received, peer) = store_fault::stalled_peer()?;
            let failed = failed_store(&state, &url)?;
            let signed = proof(&state, &key)?;
            let started = Instant::now();
            let request = tokio::spawn(async move {
                proof_workers::post_form(&failed, "/par", &fields(&failed), &signed)
                    .await
                    .map_err(|error| error.to_string())
            });
            tokio::time::timeout(Duration::from_secs(3), received).await??;
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "PAR store blocked executor"
            );
            assert!(crate::web::par_endpoint::reserve_for_test().is_err());
            if cancel {
                request.abort();
                assert!(request.await.unwrap_err().is_cancelled());
                assert!(crate::web::par_endpoint::reserve_for_test().is_err());
            } else {
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(8), request).await???,
                    StatusCode::INTERNAL_SERVER_ERROR
                );
            }
            tokio::task::spawn_blocking(move || peer.join().unwrap()).await?;
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Ok(all) = crate::web::par_endpoint::reserve_for_test() {
                    drop(all);
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "PAR worker did not release its slot"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                proof_workers::post_form(&state, "/par", &fields(&state), &proof(&state, &key)?)
                    .await?,
                StatusCode::CREATED
            );
        }
        Ok(())
    }
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
