use super::*;

fn metadata(jwks: Value) -> Value {
    json!({"redirect_uris":["https://example.com/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code"],"response_types":["code"],"scope":"openid","pkce_required":true,"jwks":jwks})
}
fn no_cache(response: &Response) {
    assert!(response.headers()[header::CACHE_CONTROL]
        .to_str()
        .unwrap()
        .contains("no-store"));
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
}
async fn safe_json(response: Response) -> TestResult<Value> {
    no_cache(&response);
    let value = response_json(response).await?;
    assert!(!value.to_string().contains("private-sentinel"));
    Ok(value)
}

pub(super) async fn before_upgrade(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    // Startup projection loads both legacy rows; actual router guard stays mounted.
    let state = test_app_state(pool.clone(), env).await?;
    let (_, signer) = material(Algorithm::RS256);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = json!({"iss":"owner","aud":env.issuer_url,"exp":now+60,"iat":now,"jti":"legacy-public-signature","client_id":"owner","response_type":"code"});
    let token = crate::test_utils::jwk_usage::sign(Algorithm::RS256, &signer, &claims);
    assert!(state
        .clients
        .verify_request_object(
            "owner",
            &token,
            &env.issuer_url,
            aegaeon_jose::algorithms::CryptoProfile::Compat
        )
        .is_ok());
    let app = crate::web::router::build_router(state);
    let before = stored_state(pool).await?;
    let response = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            "owner",
            Some("owner-token"),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let read = safe_json(response).await?;
    assert!(read["jwks"] == public_set());
    assert!(
        stored_state(pool).await? == before,
        "GET must not mutate stored data or RAT"
    );
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut value = public_set();
        value["keys"][0][field] = json!("private-sentinel");
        let mut update = metadata(value.clone());
        update["client_id"] = json!("owner");
        let response = app
            .clone()
            .oneshot(registration_request(
                Method::PUT,
                "owner",
                Some("owner-token"),
                Some(&update),
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            safe_json(response).await?["error"],
            "invalid_client_metadata"
        );
        let request = Request::builder()
            .method(Method::POST)
            .uri("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(metadata(value).to_string()))?;
        let response = app.clone().oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            safe_json(response).await?["error"],
            "invalid_client_metadata"
        );
        assert!(
            stored_state(pool).await? == before,
            "rejected input must not mutate registrations, secrets or audit"
        );
    }
    for token in [None, Some("wrong-token")] {
        let response = app
            .clone()
            .oneshot(registration_request(Method::GET, "owner", token, None)?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    // Another client's valid RAT is not the owner's RAT.
    let response = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            "owner",
            Some("other-token"),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let mut replacement = metadata(public_set());
    replacement["client_id"] = json!("owner");
    let response = app
        .clone()
        .oneshot(registration_request(
            Method::PUT,
            "owner",
            Some("owner-token"),
            Some(&replacement),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let updated = safe_json(response).await?;
    assert!(updated["jwks"] == public_set());
    let token = updated["registration_access_token"]
        .as_str()
        .ok_or_else(|| io::Error::other("missing rotated RAT"))?;
    assert!(token != "owner-token");
    let response = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            "owner",
            Some(token),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    safe_json(response).await?;
    let response = app
        .clone()
        .oneshot(registration_request(
            Method::PUT,
            "owner",
            Some("owner-token"),
            Some(&replacement),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(metadata(public_set()).to_string()))?;
    let response = app.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(safe_json(response).await?["jwks"] == public_set());
    Ok(())
}
