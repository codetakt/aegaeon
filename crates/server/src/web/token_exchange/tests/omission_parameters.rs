use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn token_empty_extensions_preserve_scope_defaults_and_raw_uri_admission() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        let initial = grant(&state).await?;
        let source = initial["access_token"].as_str().ok_or("source")?;
        let base = [
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", source),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", "internal-api"),
        ];
        let mut params = base.to_vec();
        params.extend([
            ("grant_type", ""),
            ("subject_token", ""),
            ("subject_token_type", ""),
            ("requested_token_type", ""),
            ("actor_token", ""),
            ("actor_token_type", ""),
            ("client_id", ""),
            ("audience", ""),
            ("resource", ""),
            ("scope", ""),
        ]);
        let (status, body) = request(&state, &params, true).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["scope"], "api.read");
        assert_eq!(jwt(&body)?["aud"], "internal-api");
        params.push(("subject_token", source));
        let (status, body) = request(&state, &params, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");
        assert!(body.get("access_token").is_none());

        // Empty values still count toward the unchanged raw URI admission limit.
        let query = std::iter::repeat_n("unknown=", 65)
            .collect::<Vec<_>>()
            .join("&");
        let response = Router::new()
            .route("/token", post(crate::web::token_endpoint::token))
            .layer(Extension(ConnectInfo(SocketAddr::from((
                [127, 0, 0, 1],
                12453,
            )))))
            .with_state(state.clone())
            .oneshot(
                Request::post(format!("/token?{query}"))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(
                        header::AUTHORIZATION,
                        format!("Basic {}", STANDARD.encode(format!("{CLIENT}:{SECRET}"))),
                    )
                    .body(Body::from(serde_urlencoded::to_string(base)?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let denied: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
        assert_eq!(denied["error"], "invalid_request");
        assert_eq!(
            denied["error_description"],
            "too many request query parameters"
        );
        assert!(denied.get("access_token").is_none());
        let (status, recovered) = request(&state, &base, true).await?;
        assert_eq!(status, StatusCode::OK, "{recovered}");
        assert_eq!(recovered["scope"], "api.read");
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
