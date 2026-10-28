use super::*;

#[test]
fn federation_effective_callback_algorithms_and_bound_single_context() -> ManagementTestResult {
    run(async {
        let mut f = Fixture::new(1).await?;
        f.discovery
            .id_token_signing_alg_values_supported
            .push("RS512".into());
        f.reset_discovery()?;
        let policy = json!({"openid_provider":{"id_token_signing_alg_values_supported":{"subset_of":["RS256"]}}});
        let chain = f.chain(f.metadata(), &[None, Some(policy)], None);
        f.configure(&chain).await?;
        let acquisitions = AtomicUsize::new(0);
        let exchange = perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            |_, _| {
                acquisitions.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(chain.clone()))
            },
        )
        .await
        .map_err(response_error)?;
        assert_eq!(exchange.id_token.signing_alg, "RS256");
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        f.respond(Some(jsonwebtoken::Algorithm::RS384))?;
        assert!(perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            fail_acquisition
        )
        .await
        .is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
        let invalid = f.chain(f.metadata(), &[Some(json!({"openid_provider":{"id_token_signing_alg_values_supported":{"value":["RS384"]}}}))], None);
        cache(&f.state, &invalid).await?;
        let response = match perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            fail_acquisition,
        )
        .await
        {
            Err(response) => response,
            Ok(_) => panic!("RS384-only metadata accepted"),
        };
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body: Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body["error"], "server_error");
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
        // Narrow the broader valid list while retaining mandatory RS256.
        let permit = f.chain(f.metadata(), &[Some(json!({"openid_provider":{"id_token_signing_alg_values_supported":{"subset_of":["RS256","RS384"]}}}))], None);
        cache(&f.state, &permit).await?;
        let exchange = perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            fail_acquisition,
        )
        .await
        .map_err(response_error)?;
        assert_eq!(exchange.id_token.signing_alg, "RS384");
        // A valid signed successor changes both grant and inline keys during
        // the token call. The in-progress operation must retain its prior context.
        let mut replacement = f.metadata();
        replacement["jwks"] =
            json!({"keys":[InMemoryKeyManager::new().federation_public_jwk().unwrap()]});
        let replacement = f.chain(
            replacement,
            &[Some(
                json!({"openid_provider":{"grant_types_supported":{"value":["refresh_token"]}}}),
            )],
            None,
        );
        f.mutate_during_exchange(replacement);
        assert!(perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            fail_acquisition
        )
        .await
        .is_ok());
        assert_eq!(f.calls.load(Ordering::SeqCst), 4);
        assert!(perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            fail_acquisition
        )
        .await
        .is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 4);
        assert_eq!(acquisitions.load(Ordering::SeqCst), 1);
        assert!(f
            .forms
            .lock()
            .unwrap()
            .iter()
            .all(|form| form.contains("code=code")
                && form.contains("client_secret=test-client-secret")));
        Ok(())
    })
}

#[test]
fn federation_effective_callback_current_policy_and_pin_refuse_before_credentials(
) -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        let baseline = f.chain(f.metadata(), &[], None);
        f.configure(&baseline).await?;
        for policy in [
            json!({"grant_types_supported":{"value":["refresh_token"]}}),
            json!({"response_types_supported":{"value":["id_token"]}}),
            json!({"token_endpoint_auth_methods_supported":{"value":["client_secret_basic"]}}),
            json!({"token_endpoint_auth_methods_supported":{"value":null}}),
            json!({"code_challenge_methods_supported":{"value":null}}),
            json!({"authorization_response_iss_parameter_supported":{"value":null}}),
            json!({"acr_values_supported":{"value":["low"]}}),
        ] {
            let changed = f.chain(
                f.metadata(),
                &[Some(json!({"openid_provider":policy}))],
                None,
            );
            cache(&f.state, &changed).await?;
            assert!(
                perform_upstream_callback_exchange_with(
                    &f.state,
                    &f.request,
                    "code",
                    "https://local.example",
                    fail_acquisition
                )
                .await
                .is_err(),
                "{policy}"
            );
            assert_eq!(f.calls.load(Ordering::SeqCst), 0);
        }
        cache(&f.state, &baseline).await?;
        assert!(perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            fail_acquisition
        )
        .await
        .is_ok());
        let anchor = &baseline.trust_chain.anchor;
        let pin = json!({"openid_provider":{"grant_types_supported":{"essential":true}}});
        f.state
            .federation
            .trust_anchors
            .upsert(
                f.state.environment_id,
                &anchor.entity_id,
                baseline
                    .trust_chain
                    .chain
                    .last()
                    .unwrap()
                    .jwks
                    .as_ref()
                    .unwrap(),
                Some(&pin),
            )
            .await?;
        assert!(perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            fail_acquisition
        )
        .await
        .is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        Ok(())
    })
}

#[test]
fn federation_effective_callback_logout_and_inline_keys_use_selected_metadata(
) -> ManagementTestResult {
    run(async {
        let f = Fixture::new(0).await?;
        let policy = crate::upstream::UpstreamLogoutPolicy {
            back_channel: false,
            session_hint_claim: None,
            recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
        };
        for endpoint in [json!("https://logout.example/session"), Value::Null] {
            let chain = f.chain(
                f.metadata(),
                &[Some(
                    json!({"openid_provider":{"end_session_endpoint":{"value":endpoint}}}),
                )],
                None,
            );
            f.configure(&chain).await?;
            cache(&f.state, &chain).await?;
            let exchange = perform_upstream_callback_exchange_with(
                &f.state,
                &f.request,
                "code",
                "https://local.example",
                fail_acquisition,
            )
            .await
            .map_err(response_error)?;
            let session = crate::web::upstream_logout_sessions::build_upstream_logout_session(
                Some(&policy),
                ISSUER,
                &exchange.discovery,
                &exchange.id_token,
                &f.request,
                &[],
            )
            .unwrap();
            assert_eq!(session.end_session_endpoint.as_deref(), endpoint.as_str());
        }
        let mut changed_keys = f.metadata();
        changed_keys["jwks"] =
            json!({"keys":[InMemoryKeyManager::new().federation_public_jwk().unwrap()]});
        let chain = f.chain(changed_keys, &[], None);
        cache(&f.state, &chain).await?;
        assert!(perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            fail_acquisition
        )
        .await
        .is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 3);
        Ok(())
    })
}

#[test]
fn federation_effective_callback_unsafe_selected_endpoint_refuses_before_send(
) -> ManagementTestResult {
    run(async {
        let mut f = Fixture::new(0).await?;
        // Discovery, signed metadata and the captured transaction agree; only
        // the outbound safety guard can reject this selected destination.
        f.discovery.token_endpoint = "https://127.0.0.1/token".into();
        f.request.token_endpoint = f.discovery.token_endpoint.clone();
        f.state
            .upstream
            .discovery_cache
            .try_insert(ISSUER, f.discovery.clone())?;
        let chain = f.chain(f.metadata(), &[], None);
        f.configure(&chain).await?;
        let result = perform_upstream_callback_exchange_with(
            &f.state,
            &f.request,
            "code",
            "https://local.example",
            |_, _| std::future::ready(Ok(chain.clone())),
        )
        .await;
        let response = match result {
            Err(response) => response,
            Ok(_) => panic!("unsafe selected endpoint accepted"),
        };
        let body = axum::body::to_bytes(response.into_body(), 65536).await?;
        assert!(String::from_utf8(body.to_vec())?.contains("SSRF policy"));
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
        Ok(())
    })
}

#[test]
fn federation_effective_callback_captured_endpoints_refuse_current_drift() -> ManagementTestResult {
    run(async {
        let mut f = Fixture::new(0).await?;
        let original = f.discovery.clone();
        for change_token in [true, false] {
            f.discovery = original.clone();
            if change_token {
                f.discovery.token_endpoint = "https://upstream.example/new-token".into();
            } else {
                f.discovery.jwks_uri = "https://upstream.example/new-jwks".into();
            }
            // Independently fetched Discovery agrees with the signed current
            // metadata, but the captured authorization transaction does not.
            f.state
                .upstream
                .discovery_cache
                .try_insert(ISSUER, f.discovery.clone())?;
            let chain = f.chain(f.metadata(), &[], None);
            f.configure(&chain).await?;
            cache(&f.state, &chain).await?;
            let result = perform_upstream_callback_exchange_with(
                &f.state,
                &f.request,
                "code",
                "https://local.example",
                fail_acquisition,
            )
            .await;
            let response = match result {
                Err(response) => response,
                Ok(_) => panic!("changed captured endpoint accepted"),
            };
            let body = axum::body::to_bytes(response.into_body(), 65536).await?;
            assert!(String::from_utf8(body.to_vec())?.contains("upstream metadata changed"));
            assert_eq!(f.calls.load(Ordering::SeqCst), 0);
        }
        Ok(())
    })
}
