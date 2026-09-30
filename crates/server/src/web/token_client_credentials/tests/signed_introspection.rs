use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

async fn signed_response(state: &AppState, token: &str) -> TestResult<String> {
    let app = Router::new()
        .route("/introspect", post(crate::web::token_lifecycle::introspect))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::web::runtime_authority_guard::runtime_authority_guard_middleware,
        ))
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            12456,
        )))))
        .with_state(state.clone());
    let response = app
        .oneshot(
            Request::post("/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ACCEPT, "application/token-introspection+jwt")
                .header(
                    header::AUTHORIZATION,
                    format!("Basic {}", STANDARD.encode(format!("{RS}:{RS_SECRET}"))),
                )
                .body(Body::from(serde_urlencoded::to_string([("token", token)])?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/token-introspection+jwt"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    Ok(String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await?
            .to_vec(),
    )?)
}

fn verified_response(state: &AppState, compact: &str) -> TestResult<Value> {
    let parts: Vec<_> = compact.split('.').collect();
    assert_eq!(parts.len(), 3);
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
    let key = state.keys.jwt_introspection.as_ref().ok_or("signing key missing")?;
    let public = key.jwt_signing_public_jwk().ok_or("public JWK missing")?;
    assert_eq!(public["kty"], "OKP");
    assert_eq!(public["crv"], "Ed25519");
    let public_key = URL_SAFE_NO_PAD.decode(public["x"].as_str().ok_or("public key missing")?)?;
    aegaeon_crypto::signature::verify_ed25519(&public_key, signing_input.as_bytes(), &signature)?;
    let mut changed_input = signing_input.as_bytes().to_vec();
    changed_input[0] ^= 1;
    assert!(aegaeon_crypto::signature::verify_ed25519(&public_key, &changed_input, &signature).is_err());
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    assert_eq!(header["typ"], "token-introspection+jwt");
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["kid"], key.key_id());
    let payload: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    assert_eq!(payload["iss"], state.issuer.as_str());
    assert_eq!(payload["aud"], RS, "outer audience binds the authenticated introspector");
    assert!(payload["jti"].as_str().is_some_and(|value| !value.is_empty()));
    assert!(payload["exp"].as_u64().ok_or("expiry missing")? > payload["iat"].as_u64().ok_or("issued time missing")?);
    Ok(payload)
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn client_credentials_signed_introspection_binds_resource_and_requester() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("AEGAEON_DATABASE_URL is required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env, false, true).await?;
        state.keys.jwt_introspection = Some(Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?));
        let mut document = policy(false)?;
        document.jwt_introspection_enabled = true;
        install_policy(&pool, &env, &document).await?;
        let state = reload(&state, &env).await?;
        let (status, issued) = request(
            &state, "/token", CALLER, SECRET,
            &[("grant_type", "client_credentials"), ("audience", TARGET)],
        ).await?;
        assert_eq!(status, StatusCode::OK, "{issued}");
        let token = issued["access_token"].as_str().ok_or("token missing")?;
        let active = verified_response(&state, &signed_response(&state, token).await?)?;
        assert_eq!(active["token_introspection"]["active"], true);
        assert_eq!(active["token_introspection"]["aud"], TARGET, "nested audience retains the canonical resource target");
        assert_eq!(active["token_introspection"]["client_id"], CALLER);
        assert_eq!(active["token_introspection"]["sub"], CALLER);
        assert_ne!(active["aud"], active["token_introspection"]["aud"]);
        document.client_credentials.resource_servers[0].introspection_clients.clear();
        install_policy(&pool, &env, &document).await?;
        let state = reload(&state, &env).await?;
        let inactive = verified_response(&state, &signed_response(&state, token).await?)?;
        assert_eq!(inactive["token_introspection"], json!({"active": false}), "inactive signed responses disclose no token attributes");
        assert_ne!(active["jti"], inactive["jti"]);
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
