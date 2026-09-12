use super::*;

#[tokio::test]
async fn token_exchange_authority_requires_an_issued_refresh_parent() -> TestResult {
    for asynchronous in [false, true] {
        for (scope, issue_refresh, has_parent) in [
            ("read", true, false),
            ("read offline_access", false, false),
            ("read offline_access", true, true),
        ] {
            let policy = must_ok!(
                serde_json::from_value(serde_json::json!({
                    "version": 1, "targets": [{"audience": "api", "resourceAliases": []}],
                    "rules": [{"clientId": "test_client", "sourceAudience": "test_client",
                        "targetAudience": "api", "scopes": [{"targetScope": "api.read",
                            "sourceScopes": ["read"]}], "defaultScopes": ["api.read"]}]
                })),
                "exchange policy"
            );
            let issuer = TokenIssuer::new_process_local_with_ttls_for_tests(
                Arc::new(InMemoryKeyManager::new()),
                60,
                120,
                60,
            )
            .with_token_exchange_policy(policy)
            .with_issuer("https://issuer.example".into());
            let (code, _) = issuer
                .issue_authorization_code(authorization_request(scope, None), "user123".into())?;
            let stored = must_some!(issuer.code_store.try_get_code(&code)?, "code exists");
            let captured = must_some!(stored.exchange_grant, "code captures eligible authority");
            let request = token_request_for_code(code, None);
            let response = if asynchronous {
                issuer
                    .exchange_code_for_tokens_bound_with_grant_policy_async(
                        request,
                        None,
                        None,
                        true,
                        issue_refresh,
                    )
                    .await?
            } else {
                issuer.exchange_code_for_tokens_bound_with_grant_policy(
                    request,
                    None,
                    None,
                    true,
                    issue_refresh,
                )?
            };
            let TokenResponse::Success {
                access_token,
                refresh_token,
                ..
            } = response
            else {
                fail_test!("expected code redemption: {response:?}");
            };
            let access = must_some!(
                issuer.token_store.try_verify_access_token(&access_token)?,
                "access exists"
            );
            let meta = must_some!(
                issuer.token_store.try_get_bearer_meta(&access_token)?,
                "metadata exists"
            );
            assert_eq!(refresh_token.is_some(), has_parent);
            assert_eq!(meta.refresh_parent, refresh_token);
            assert_eq!(meta.exchange_grant.is_some(), has_parent);
            assert_eq!(access.exchange_root.is_some(), has_parent);
            if let Some(parent) = refresh_token {
                let parent = must_some!(
                    issuer.token_store.try_get_refresh_token(&parent)?,
                    "parent exists"
                );
                assert_eq!(parent.exchange_grant.as_ref(), Some(&captured));
                assert_eq!(access.exchange_root.as_ref(), captured.root());
                assert_eq!(
                    meta.exchange_grant.as_ref().and_then(|grant| grant.root()),
                    captured.root()
                );
            }
        }
    }
    Ok(())
}
