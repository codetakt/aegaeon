use super::*;

async fn request(
    state: &AppState,
    pairs: &[(String, String)],
) -> TestResult<axum::response::Response> {
    let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    Ok(app
        .oneshot(
            Request::get(format!(
                "/authorize?{}",
                serde_urlencoded::to_string(pairs)?
            ))
            .body(Body::empty())?,
        )
        .await?)
}

async fn rejected(
    state: &AppState,
    mode: &str,
    signed_request: bool,
    challenge: &str,
    method: &str,
    trusted: bool,
) -> TestResult {
    let mut pairs = authorization_pairs(state, Some(challenge), Some(method));
    for (key, value) in &mut pairs {
        if key == "state" {
            *value = "selected-pkce-state".into();
        }
        if key == "redirect_uri" && !trusted {
            *value = "https://unregistered.example/callback".into();
        }
    }
    pairs.push(("response_mode".into(), mode.into()));
    if signed_request {
        let jwt = signed(state, &pairs)?;
        pairs = vec![("client_id".into(), BASIC.into()), ("request".into(), jwt)];
    }
    let response = request(state, &pairs).await?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    if trusted && mode == "query" {
        assert!(response.status().is_redirection());
        let location = url::Url::parse(response.headers()[header::LOCATION].to_str()?)?;
        assert_eq!(location.as_str().split('?').next(), Some(REDIRECT));
        let params: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(params["error"], "invalid_request");
        assert_eq!(params["state"], "selected-pkce-state");
        assert_eq!(params["iss"], state.issuer.as_str());
        assert!(!params.contains_key("code"));
    } else if trusted {
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::LOCATION));
        let body = String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?;
        assert!(body.contains(&format!("action=\"{REDIRECT}\"")));
        for (name, value) in [
            ("error", "invalid_request"),
            ("state", "selected-pkce-state"),
            ("iss", state.issuer.as_str()),
        ] {
            assert!(body.contains(&format!("name=\"{name}\" value=\"{value}\"")));
        }
        assert!(!body.contains("name=\"code\""));
    } else {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(header::LOCATION));
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "invalid_redirect_uri");
    }
    assert!(state.tokens.issuer.code_store.snapshot().codes.is_empty());
    assert_eq!(par_count(state)?, 0);
    let logins: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.authorization_logins WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_one(&state.db_pool)
    .await?;
    assert_eq!(logins, 0, "PKCE rejection must precede login retention");
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn shared_redis_pkce_errors_use_trusted_selected_query_and_form_post_before_login(
) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        update_test_policy(&mut state, |policy| policy.strict_authorize_redirect = true).await?;
        for signed_request in [false, true] {
            for mode in ["query", "form_post"] {
                for (challenge, method) in [
                    ("short", "S256"),
                    (CHALLENGE, "plain"),
                    ("invalid=challenge", "S256"),
                ] {
                    rejected(&state, mode, signed_request, challenge, method, true).await?;
                }
                rejected(&state, mode, signed_request, "short", "S256", false).await?;
            }
        }
        // The same registered client with valid PKCE still begins login.
        let pairs = authorization_pairs(&state, Some(CHALLENGE), Some("S256"));
        let response = request(&state, &pairs).await?;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert!(response.headers()[header::LOCATION]
            .to_str()?
            .starts_with("/auth/login?"));
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
