use super::*;

fn issue(
    issuer: &TokenIssuer,
    challenge: Option<&str>,
    method: Option<&str>,
    required: bool,
) -> Result<String, String> {
    let mut request = authorization_request("read", None);
    request.state = None;
    request.nonce = None;
    request.code_challenge = challenge.map(str::to_owned);
    request.code_challenge_method = method.map(str::to_owned);
    issuer
        .issue_authorization_code_with_pkce_required(request, "user".into(), required, 0, None)
        .map(|pair| pair.0)
}

#[test]
fn pkce_admission_public_issuer_validates_even_when_optional() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    for required in [false, true] {
        for challenge in [
            String::new(),
            "A".repeat(42),
            "A".repeat(129),
            format!("{}é", "A".repeat(42)),
            format!("{}=", "A".repeat(42)),
            format!("{}\n", "A".repeat(42)),
        ] {
            let before = issuer.code_store.snapshot();
            assert!(issue(&issuer, Some(&challenge), Some("S256"), required).is_err());
            assert_eq!(issuer.code_store.snapshot().codes.len(), before.codes.len());
        }
        for (challenge, method) in [
            (Some("A".repeat(43)), None),
            (None, Some("S256")),
            (Some("A".repeat(43)), Some("plain")),
        ] {
            assert!(issue(&issuer, challenge.as_deref(), method, required).is_err());
        }
        for length in [43, 128] {
            let challenge = format!("{}.~_-", "A".repeat(length - 4));
            let code = issue(&issuer, Some(&challenge), Some("S256"), required)?;
            assert_eq!(
                issuer
                    .code_store
                    .try_get_code(&code)
                    .map_err(|e| e.to_string())?
                    .ok_or("stored code")?
                    .code_challenge
                    .as_deref(),
                Some(challenge.as_str())
            );
        }
    }
    Ok(())
}

fn invalid_exchange(issuer: &TokenIssuer, request: TokenRequest) -> TestResult {
    let code = request.code.clone().ok_or("code")?;
    assert!(
        matches!(issuer.exchange_code_for_tokens(request, None)?, TokenResponse::Error { error, .. } if error == "invalid_grant")
    );
    assert!(issuer
        .code_store
        .try_get_code(&code)
        .map_err(|e| e.to_string())?
        .is_some());
    Ok(())
}

fn retained_binding(issuer: &TokenIssuer) -> TestResult {
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let code = issue(issuer, Some(challenge), Some("S256"), true)?;
    for verifier in [
        None,
        Some("A".repeat(43)),
        Some("short".into()),
        Some(format!("{}=", "A".repeat(42))),
    ] {
        let mut request = token_request_for_code(code.clone(), None);
        request.code_verifier = verifier;
        invalid_exchange(issuer, request)?;
    }
    assert!(matches!(
        issuer.exchange_code_for_tokens(token_request_for_code(code.clone(), None), None)?,
        TokenResponse::Success { .. }
    ));
    assert!(issuer
        .exchange_code_for_tokens(token_request_for_code(code, None), None)
        .is_err());
    let optional = issue(issuer, None, None, false)?;
    invalid_exchange(issuer, token_request_for_code(optional.clone(), None))?;
    let mut request = token_request_for_code(optional, None);
    request.code_verifier = None;
    assert!(matches!(
        issuer.exchange_code_for_tokens(request, None)?,
        TokenResponse::Success { .. }
    ));
    // Deliberately malformed legacy retained records bypass the public issuer.
    for (challenge, method) in [
        (None, Some("S256")),
        (Some("short".into()), Some("S256")),
        (Some("A".repeat(43)), Some("S256")),
        (Some(challenge.into()), None),
        (Some(challenge.into()), Some("plain")),
    ] {
        let code = issue(issuer, None, None, false)?;
        let mut retained = issuer
            .code_store
            .try_get_code(&code)
            .map_err(|e| e.to_string())?
            .ok_or("stored code")?;
        retained.code = uuid::Uuid::new_v4().to_string();
        retained.code_challenge = challenge;
        retained.code_challenge_method = method.map(str::to_owned);
        let code = issuer
            .code_store
            .store_code(retained)
            .map_err(|e| e.to_string())?;
        invalid_exchange(issuer, token_request_for_code(code.clone(), None))?;
        let mut missing_verifier = token_request_for_code(code.clone(), None);
        missing_verifier.code_verifier = None;
        invalid_exchange(issuer, missing_verifier)?;
        assert!(issuer
            .code_store
            .try_get_code(&code)
            .map_err(|e| e.to_string())?
            .is_some());
    }
    Ok(())
}

#[test]
fn pkce_admission_retained_binding_process_local() -> TestResult {
    retained_binding(&TokenIssuer::new_process_local_for_tests(Arc::new(
        InMemoryKeyManager::new(),
    )))
}

#[test]
#[ignore = "requires Redis"]
fn pkce_admission_retained_binding_shared_redis() -> TestResult {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(uuid::Uuid::new_v4());
    let issuer = TokenIssuer::try_from_shared_store_env_with_ttls(
        Arc::new(InMemoryKeyManager::new()),
        300,
        3600,
        120,
        &namespace,
    )
    .map_err(|e| e.to_string())?;
    retained_binding(&issuer)
}
