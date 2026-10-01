use super::*;

#[test]
fn federation_effective_refresh_validates_before_credentials_and_without_id_token(
) -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        let link = f.refresh_link();
        f.respond(None)?;
        let baseline = f.chain(f.metadata(), &[], None);
        f.configure(&baseline).await?;
        for policy in [
            json!({"grant_types_supported":{"value":["authorization_code"]}}),
            json!({"grant_types_supported":{"value":null}}),
            // Retained local provider guard: refresh-only is not admitted.
            json!({"grant_types_supported":{"value":["refresh_token"]}}),
            json!({"token_endpoint_auth_methods_supported":{"value":["client_secret_basic"]}}),
            json!({"code_challenge_methods_supported":{"value":null}}),
            json!({"authorization_response_iss_parameter_supported":{"value":null}}),
        ] {
            let chain = f.chain(
                f.metadata(),
                &[Some(json!({"openid_provider":policy}))],
                None,
            );
            f.reset_discovery()?;
            cache(&f.state, &chain).await?;
            assert!(
                perform_upstream_refresh_exchange_with(
                    &f.state,
                    "https://local.example",
                    &link,
                    &f.profile,
                    fail_acquisition
                )
                .await
                .is_err(),
                "{policy}"
            );
            assert_eq!(f.calls.load(Ordering::SeqCst), 0);
        }
        f.reset_discovery()?;
        cache(&f.state, &baseline).await?;
        let exchange = perform_upstream_refresh_exchange_with(
            &f.state,
            "https://local.example",
            &link,
            &f.profile,
            fail_acquisition,
        )
        .await
        .map_err(response_error)?;
        assert!(exchange.token_response.id_token.is_none());
        validate_upstream_refresh_exchange(&f.state, "https://local.example", &link, &exchange)
            .await
            .map_err(response_error)?;
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        assert!(f.forms.lock().unwrap()[0].contains("refresh_token=refresh-secret"));
        assert!(!f.forms.lock().unwrap()[0].contains("scope="));
        Ok(())
    })
}

#[test]
fn federation_effective_refresh_algorithms_and_inline_keys_are_bound_once() -> ManagementTestResult
{
    run(async {
        let f = Fixture::new(1).await?;
        let link = f.refresh_link();
        let policy = json!({"openid_provider":{"id_token_signing_alg_values_supported":{"subset_of":["RS256"]}}});
        let baseline = f.chain(f.metadata(), &[Some(policy)], None);
        f.configure(&baseline).await?;
        let calls = AtomicUsize::new(0);
        let exchange = perform_upstream_refresh_exchange_with(
            &f.state,
            "https://local.example",
            &link,
            &f.profile,
            |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(baseline.clone()))
            },
        )
        .await
        .map_err(response_error)?;
        validate_upstream_refresh_exchange(&f.state, "https://local.example", &link, &exchange)
            .await
            .map_err(response_error)?;
        f.respond(Some(jsonwebtoken::Algorithm::RS384))?;
        let exchange = perform_upstream_refresh_exchange_with(
            &f.state,
            "https://local.example",
            &link,
            &f.profile,
            fail_acquisition,
        )
        .await
        .map_err(response_error)?;
        assert!(validate_upstream_refresh_exchange(
            &f.state,
            "https://local.example",
            &link,
            &exchange
        )
        .await
        .is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
        f.respond(Some(jsonwebtoken::Algorithm::RS256))?;
        let mut metadata = f.metadata();
        metadata["jwks"] =
            json!({"keys":[InMemoryKeyManager::new().federation_public_jwk().unwrap()]});
        let replacement = f.chain(metadata, &[Some(json!({"openid_provider":{"grant_types_supported":{"value":["authorization_code"]}}}))], None);
        f.mutate_during_exchange(replacement);
        let exchange = perform_upstream_refresh_exchange_with(
            &f.state,
            "https://local.example",
            &link,
            &f.profile,
            fail_acquisition,
        )
        .await
        .map_err(response_error)?;
        validate_upstream_refresh_exchange(&f.state, "https://local.example", &link, &exchange)
            .await
            .map_err(response_error)?;
        assert!(perform_upstream_refresh_exchange_with(
            &f.state,
            "https://local.example",
            &link,
            &f.profile,
            fail_acquisition
        )
        .await
        .is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 3);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        Ok(())
    })
}
