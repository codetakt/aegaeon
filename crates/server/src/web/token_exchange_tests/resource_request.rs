use super::*;

fn block_on_resource_request<T>(future: impl std::future::Future<Output = T>) -> Result<T, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("test runtime should initialize: {err}"))?;
    Ok(runtime.block_on(future))
}

fn issue_resource_request_token(
    token_issuer: &TokenIssuer,
    requested_resource: Option<String>,
) -> Result<String, String> {
    let redirect_uri = "https://client.example/callback";
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let (code, _) = token_issuer
        .issue_authorization_code(
            AuthzReq {
                response_type: "code".to_string(),
                client_id: "client".to_string(),
                iss: None,
                redirect_uri: Some(redirect_uri.to_string()),
                resource: None,
                authorization_details: None,
                scope: Some("read".to_string()),
                state: Some("state".to_string()),
                nonce: None,
                code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
                code_challenge_method: Some("S256".to_string()),
                request_uri: None,
                request_object: None,
                request_object_claims: None,
                acr_values: None,
                max_age: None,
            },
            "user-1".to_string(),
        )
        .map_err(|err| format!("authorization code should be issued: {err}"))?;
    let token_response = token_issuer
        .exchange_code_for_tokens(
            IssuerTokenReq {
                grant_type: "authorization_code".to_string(),
                code: Some(code),
                redirect_uri: Some(redirect_uri.to_string()),
                client_id: "client".to_string(),
                client_secret: None,
                refresh_token: None,
                code_verifier: Some(code_verifier.to_string()),
                resource: requested_resource,
                request_object_claims: None,
            },
            None,
        )
        .map_err(|err| format!("token exchange should complete: {err}"))?;
    match token_response {
        IssuerTokenResp::Success { access_token, .. } => Ok(access_token),
        IssuerTokenResp::Error { error, .. } => {
            Err(format!("token exchange should not fail: {error}"))
        }
    }
}

fn resource_audience_test_validator(
    token_issuer: &TokenIssuer,
    key_manager: Arc<dyn KeyManager>,
) -> TokenValidator {
    TokenValidator::with_policy(
        token_issuer.token_store.clone(),
        key_manager,
        crate::policy::SecurityPolicy::default().with_sender_binding_enforcement(false),
    )
}

#[test]
fn resource_request_rejects_token_without_resource_audience() -> Result<(), String> {
    let issuer_base = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(crate::kms::InMemoryKeyManager::new());
    let token_issuer = TokenIssuer::new_process_local_for_tests(Arc::clone(&key_manager));
    let access_token = issue_resource_request_token(&token_issuer, None)?;
    let validator = resource_audience_test_validator(&token_issuer, key_manager);

    let outcome = block_on_resource_request(process_resource_request(
        &validator,
        Some(format!("Bearer {access_token}")),
        None,
        None,
        issuer_base,
    ))?;

    assert!(!outcome.success);
    assert_eq!(outcome.response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(outcome.reason.as_deref(), Some("invalid_audience"));
    Ok(())
}

#[test]
fn resource_request_accepts_token_with_protected_resource_audience() -> Result<(), String> {
    let issuer_base = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(crate::kms::InMemoryKeyManager::new());
    let token_issuer = TokenIssuer::new_process_local_for_tests(Arc::clone(&key_manager));
    let access_token = issue_resource_request_token(
        &token_issuer,
        Some(crate::resource_audience::protected_resource(issuer_base)),
    )?;
    let validator = resource_audience_test_validator(&token_issuer, key_manager);

    let outcome = block_on_resource_request(process_resource_request(
        &validator,
        Some(format!("Bearer {access_token}")),
        None,
        None,
        issuer_base,
    ))?;

    assert!(outcome.success);
    assert_eq!(outcome.response.status(), StatusCode::OK);
    Ok(())
}

#[test]
fn resource_request_maps_jwt_access_token_backend_policy_to_internal_error() -> Result<(), String> {
    let issuer_base = "https://auth.example.com";
    let redirect_uri = "https://client.example/callback";
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let key_manager: Arc<dyn KeyManager> = Arc::new(
        crate::kms::InMemoryPublicJwtKeyManager::new()
            .map_err(|err| format!("public JWT key manager should initialize: {err}"))?,
    );
    let token_issuer = TokenIssuer::new_process_local_for_tests(Arc::clone(&key_manager))
        .with_issuer(issuer_base.to_string())
        .with_jwt_access_tokens_enabled(true);

    let (code, _) = token_issuer
        .issue_authorization_code(
            AuthzReq {
                response_type: "code".to_string(),
                client_id: "client".to_string(),
                iss: None,
                redirect_uri: Some(redirect_uri.to_string()),
                resource: None,
                authorization_details: None,
                scope: Some("read".to_string()),
                state: Some("state".to_string()),
                nonce: None,
                code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
                code_challenge_method: Some("S256".to_string()),
                request_uri: None,
                request_object: None,
                request_object_claims: None,
                acr_values: None,
                max_age: None,
            },
            "user-1".to_string(),
        )
        .map_err(|err| format!("authorization code should be issued: {err}"))?;
    let token_response = token_issuer
        .exchange_code_for_tokens(
            IssuerTokenReq {
                grant_type: "authorization_code".to_string(),
                code: Some(code),
                redirect_uri: Some(redirect_uri.to_string()),
                client_id: "client".to_string(),
                client_secret: None,
                refresh_token: None,
                code_verifier: Some(code_verifier.to_string()),
                resource: None,
                request_object_claims: None,
            },
            None,
        )
        .map_err(|err| format!("token exchange should complete: {err}"))?;
    let access_token = match token_response {
        IssuerTokenResp::Success { access_token, .. } => access_token,
        IssuerTokenResp::Error { error, .. } => {
            return Err(format!("token exchange should not fail: {error}"));
        }
    };
    let backend_key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        aegaeon_jose::raw_json::RawJsonSurface::JwtAccessTokenHeader,
    );
    let _raw_json_guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw JSON environment guard should be available".to_string())?;
    let _backend_override = EnvVarGuard::new(backend_key, Some("future"));
    let validator = TokenValidator::new(token_issuer.token_store.clone(), key_manager)
        .with_jwt_access_tokens_enabled(true)
        .with_issuer(Some(issuer_base.to_string()));

    let outcome = block_on_resource_request(process_resource_request(
        &validator,
        Some(format!("Bearer {access_token}")),
        None,
        None,
        issuer_base,
    ))?;

    assert!(!outcome.success);
    assert_eq!(outcome.response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        outcome.reason.as_deref(),
        Some("access token validation failed")
    );
    Ok(())
}
