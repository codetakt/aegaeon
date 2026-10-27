//! Consent must keep its selected client after rebuilding the request context.
use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn consent_denial_uses_selected_redirect_after_shared_registry_changes() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL required; no silent skip")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, sid) = fixture(&pool, &env).await?;
        update_test_policy(&mut state, |policy| policy.strict_authorize_redirect = true).await?;
        let (status, html) = send(
            &state,
            &sid,
            &authorize_uri(&state, Some("consent"))?,
            None,
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{html}");
        let token = transaction(&html)?;
        let barriers = crate::runtime_authority::AuthorizationReadBarriers {
            observed: Arc::new(tokio::sync::Barrier::new(2)),
            resume: Arc::new(tokio::sync::Barrier::new(2)),
        };
        state.runtime_authority.authorization_context_barriers = Some(barriers.clone());
        let registry = state.clients.clone();
        let mut changed = registry.try_get(CLIENT)?.ok_or("client missing")?;
        changed.redirect_uris = vec!["https://changed.example/callback".into()];
        let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
            SocketAddr::from(([127, 0, 0, 1], 12345)),
        )));
        let request = Request::post("/auth/consent")
            .header(header::COOKIE, format!("aegaeon_auth_session={sid}"))
            .header(header::ORIGIN, state.issuer.as_str())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(serde_urlencoded::to_string([
                ("transaction", token),
                ("decision", "deny"),
            ])?))?;
        let mutate = async {
            barriers.observed.wait().await;
            let changed = registry.try_update(changed);
            barriers.resume.wait().await;
            changed
        };
        let (response, changed) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(app.oneshot(request), mutate)
        })
        .await?;
        assert!(changed?);
        let response = response?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(!response.headers().contains_key(header::LOCATION));
        let body = String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await?.to_vec())?;
        let redirect = url::Url::parse(&continuation_destination(&body)?)?;
        assert_eq!(
            redirect.origin().ascii_serialization(),
            "https://client.example.com"
        );
        assert_eq!(redirect.path(), "/callback");
        assert!(redirect
            .query_pairs()
            .any(|(name, value)| name == "error" && value == "access_denied"));
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
