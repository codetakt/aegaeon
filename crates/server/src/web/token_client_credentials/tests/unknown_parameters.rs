use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn client_credentials_unknown_parameters_preserve_target_scope_and_authentication(
) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env, true, false).await?;
        for extra in [
            vec![],
            vec![
                ("organization_id", ""),
                ("organizationId", "organization_other"),
                ("organizationId", "ignored"),
                ("unknown", "a"),
                ("unknown", "b"),
            ],
        ] {
            let mut fields = vec![
                ("grant_type", "client_credentials"),
                ("audience", TARGET),
                ("scope", "api.read"),
            ];
            fields.extend(extra);
            let (status, body) = request(&state, "/token", CALLER, SECRET, &fields).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["scope"], "api.read");
            let token = body["access_token"].as_str().ok_or("token")?;
            let meta = state
                .tokens
                .store
                .try_get_bearer_meta(token)?
                .ok_or("metadata")?;
            assert_eq!(meta.audience, TARGET);
            assert!(meta.application_grant.is_none());
            assert!(body.get("refresh_token").is_none());
            let (status, denied) = request(&state, "/token", CALLER, "wrong", &fields).await?;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(denied["error"], "invalid_client");
            assert!(denied.get("access_token").is_none());
        }
        let (status, denied) = request(
            &state,
            "/token",
            CALLER,
            SECRET,
            &[
                ("grant_type", "client_credentials"),
                ("audience", TARGET),
                ("organization_id", "organization_other"),
            ],
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(denied["error"], "invalid_request");
        assert!(denied.get("access_token").is_none());
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
