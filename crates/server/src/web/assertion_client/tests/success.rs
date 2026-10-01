use super::*;

pub(super) async fn authenticated_lifecycle(state: &AppState, token: &str) -> TestResult {
    for (path, active) in [
        ("/introspect", true),
        ("/revoke", false),
        ("/introspect", false),
    ] {
        let jwt = sign(&claims(state, path)?)?;
        let pairs = [
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", jwt.as_str()),
            ("token", token),
        ];
        let (status, body) = send(state, path, &pairs, None).await?;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        if path == "/introspect" {
            assert_eq!(body["active"], active, "{body}");
        }
    }
    Ok(())
}
async fn exercise(state: &AppState) -> TestResult {
    let jwt = sign(&claims(state, "/token")?)?;
    reject(state, "/token", &fields("/token", &jwt), Some(&basic())).await?;
    let (status, body) = send(state, "/token", &fields("/token", &jwt), None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().ok_or("access token")?;
    reject(state, "/token", &fields("/token", &jwt), None).await?;
    // A bad revocation assertion cannot change a live token's state.
    let mut revoke_claims = claims(state, "/revoke")?;
    revoke_claims["iss"] = json!("wrong-issuer");
    let bad = sign(&revoke_claims)?;
    reject(
        state,
        "/revoke",
        &[
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &bad),
            ("token", token),
        ],
        None,
    )
    .await?;
    authenticated_lifecycle(state, token).await?;

    let req: crate::authcode::types::AuthorizationRequest = serde_json::from_value(json!({
        "response_type":"code","client_id":CLIENT,"redirect_uri":REDIRECT,"scope":"api.read",
        "code_challenge":CHALLENGE,"code_challenge_method":"S256"
    }))?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code(req, "assertion-user".into())?;
    let jwt = sign(&claims(state, "/token")?)?;
    let pairs = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", jwt.as_str()),
    ];
    let mut invalid = pairs.to_vec();
    invalid[5].1 = "invalid";
    reject(state, "/token", &invalid, None).await?;
    let (status, body) = send(state, "/token", &pairs, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());
    // The code has actually been consumed by the authenticated handler.
    let jwt = sign(&claims(state, "/token")?)?;
    let mut replay = pairs.to_vec();
    replay[5].1 = &jwt;
    let (status, body) = send(state, "/token", &replay, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");

    let jwt = sign(&claims(state, "/device_authorization")?)?;
    let (status, body) = send(
        state,
        "/device_authorization",
        &fields("/device_authorization", &jwt),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["device_code"].is_string());
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn assertion_subject_authenticates_token_code_device_and_lifecycle_routes() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async { exercise(&fixture(&pool, &env).await?).await }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn assertion_subject_does_not_supply_anonymous_public_client_identity() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        for path in ["/token", "/device_authorization", "/revoke", "/par"] {
            let mut f = fields(path, "");
            f.retain(|(k, _)| !k.starts_with("client_assertion") && *k != "client_id");
            if path == "/revoke" {
                reject(&state, path, &f, None).await?;
            } else {
                reject_request(&state, path, &f, None).await?;
            }
        }
        let (status, body) = send(
            &state,
            "/device_authorization",
            &[("client_id", PUBLIC), ("scope", "api.read")],
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["device_code"].is_string());
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
