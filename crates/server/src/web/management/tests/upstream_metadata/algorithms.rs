use super::*;

async fn check_algorithms(refresh: bool) -> ManagementTestResult {
    for (algorithms, permitted) in [
        (json!(["rs256"]), false),
        (json!(["Rs256"]), false),
        (json!([" RS256"]), false),
        (json!(["RS256 "]), false),
        (json!(["RS384"]), false),
        (json!(["RS256"]), true),
        (json!(["rs256", "RS256"]), true),
    ] {
        let f = Fixture::new(0).await?;
        let policy = json!({"openid_provider":{"id_token_signing_alg_values_supported":{"value":algorithms}}});
        let chain = f.chain(f.metadata(), &[Some(policy)], None);
        f.configure(&chain).await?;
        let acquisitions = AtomicUsize::new(0);
        // First acquire a signed chain; the second operation must use its cached raw evidence.
        for cached in [false, true] {
            let acquire = |_, _| {
                assert!(!cached, "unexpected acquisition on cached path");
                acquisitions.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(chain.clone()))
            };
            let result = if refresh {
                let link = f.refresh_link();
                let exchange = perform_upstream_refresh_exchange_with(
                    &f.state,
                    "https://local.example",
                    &link,
                    &f.profile,
                    acquire,
                )
                .await
                .map_err(response_error)?;
                assert_eq!(
                    exchange
                        .metadata
                        .discovery
                        .id_token_signing_alg_values_supported,
                    serde_json::from_value::<Vec<String>>(algorithms.clone())?
                );
                validate_upstream_refresh_exchange(
                    &f.state,
                    "https://local.example",
                    &link,
                    &exchange,
                )
                .await
            } else {
                perform_upstream_callback_exchange_with(
                    &f.state,
                    &f.request,
                    "code",
                    "https://local.example",
                    acquire,
                )
                .await
                .map(|exchange| assert_eq!(exchange.id_token.signing_alg, "RS256"))
            };
            assert_eq!(
                result.is_ok(),
                permitted,
                "selected algorithms {algorithms}, cached={cached}, refresh={refresh}"
            );
            if let Err(response) = result {
                assert_eq!(response.status(), http::StatusCode::BAD_GATEWAY);
                let body = axum::body::to_bytes(response.into_body(), 16384).await?;
                let body = std::str::from_utf8(&body)?;
                assert!(body.contains("alg not supported"), "{body}");
            }
            assert_eq!(f.calls.load(Ordering::SeqCst), if cached { 2 } else { 1 });
            assert_eq!(acquisitions.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}

#[test]
fn federation_effective_callback_algorithm_identifiers_are_exact() -> ManagementTestResult {
    run(check_algorithms(false))
}

#[test]
fn federation_effective_refresh_algorithm_identifiers_are_exact() -> ManagementTestResult {
    run(check_algorithms(true))
}
