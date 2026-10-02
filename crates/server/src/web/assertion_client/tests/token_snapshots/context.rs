use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn token_snapshot_all_six_contexts_keep_credentials_and_registered_metadata() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL required; no silent skip")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = all_grants_fixture(&pool, &env).await?;
        let original = state.clients.try_get(BASIC)?.ok_or("client")?;
        let original_fingerprint = state.clients.try_runtime_snapshot_fingerprint()?;
        let invalid = format!("Basic {}", STANDARD.encode(format!("{BASIC}:wrong-secret")));
        let mut captured = Vec::new();
        for grant in crate::policy::SUPPORTED_GRANT_TYPES {
            let response = context(&state, grant, &invalid)
                .await
                .err()
                .ok_or("invalid credential accepted")?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{grant}");
            let (ctx, selected) = context(&state, grant, &basic())
                .await
                .map_err(|r| format!("{grant}: {}", r.status()))?;
            assert_eq!(ctx.client_id, BASIC);
            assert!(!Arc::ptr_eq(&state.clients, &selected.clients), "{grant}");
            assert!(
                selected.clients.try_get(CLIENT)?.is_none(),
                "unrelated identity copied"
            );
            captured.push((grant, selected));
        }
        assert_eq!(captured.len(), 6);
        replace_client(&state).await?;
        assert_ne!(
            state.clients.try_runtime_snapshot_fingerprint()?,
            original_fingerprint
        );
        for (grant, selected) in captured {
            let client = selected.clients.try_get(BASIC)?.ok_or("captured client")?;
            assert_eq!(
                client.token_endpoint_auth_method, original.token_endpoint_auth_method,
                "{grant}"
            );
            assert_eq!(
                client.allowed_grant_types, original.allowed_grant_types,
                "{grant}"
            );
            assert_eq!(client.allowed_scopes, original.allowed_scopes, "{grant}");
            assert_eq!(client.jwks_uri, original.jwks_uri, "{grant}");
            assert_eq!(
                client.inline_jwks.as_ref().map(|keys| keys.as_value()),
                original.inline_jwks.as_ref().map(|keys| keys.as_value()),
                "{grant}"
            );
            assert_eq!(
                selected.clients.try_runtime_snapshot_fingerprint()?,
                original_fingerprint
            );
            assert!(
                selected
                    .clients
                    .try_validate_basic_auth(&basic())?
                    .is_some(),
                "{grant}"
            );
            assert!(
                selected
                    .clients
                    .try_validate_basic_auth(&invalid)?
                    .is_none(),
                "{grant}"
            );
            let replacement = format!(
                "Basic {}",
                STANDARD.encode(format!("{BASIC}:{NEXT_SECRET}"))
            );
            assert!(
                selected
                    .clients
                    .try_validate_basic_auth(&replacement)?
                    .is_none(),
                "{grant}"
            );
        }
        let current = state.clients.try_get(BASIC)?.ok_or("current client")?;
        assert_eq!(current.token_endpoint_auth_method, "client_secret_post");
        assert_eq!(current.allowed_scopes, ["other.read"]);
        assert_eq!(
            current.jwks_uri.as_deref(),
            Some("https://keys.example/new.json")
        );
        assert!(current.inline_jwks.is_none());
        assert!(state.clients.try_validate_basic_auth(&basic())?.is_none());
        assert!(state
            .clients
            .try_validate_client_secret_post(Some(BASIC), Some(NEXT_SECRET))?
            .is_some());
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn token_snapshot_requests_share_assertion_replay_state() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL required; no silent skip")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = all_grants_fixture(&pool, &env).await?;
        let jwt = sign(&claims(&state, "/token")?)?;
        let params: Vec<_> = fields("/token", &jwt)
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let headers = HeaderMap::new();
        let uri = "/token".parse()?;
        let first = build_token_context(
            &state,
            &uri,
            &headers,
            params.clone(),
            state.issuer.as_str(),
            "first".into(),
        )
        .await;
        assert!(first.is_ok());
        let second = build_token_context(
            &state,
            &uri,
            &headers,
            params,
            state.issuer.as_str(),
            "second".into(),
        )
        .await;
        assert_eq!(
            second.err().ok_or("replay accepted")?.status(),
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
