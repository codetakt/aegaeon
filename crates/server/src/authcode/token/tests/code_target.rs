// Issuer-boundary fixtures represent approved grants. Resource syntax or a
// token request itself is not evidence of user consent or resource approval.
fn code_target_fixture(
    scope: &str,
    granted: Option<&str>,
) -> Result<(TokenIssuer, String), String> {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()))
        .with_oidc(Some(enabled_oidc_config()?));
    let (code, _) =
        issuer.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
            auth_session_id: Some("code-target-fixture".to_string()),
            ..AuthorizationCodeIssueInput::new(
                authorization_request(scope, granted),
                "user123".to_string(),
                true,
                0,
            )
        })?;
    Ok((issuer, code))
}

fn assert_code_target_rejected(response: TokenResponse) -> TestResult {
    match response {
        TokenResponse::Error { error, .. } if error == "invalid_target" => Ok(()),
        other => Err(format!("ungranted target must be rejected: {other:?}")),
    }
}

fn check_code_target_success(
    issuer: &TokenIssuer,
    response: TokenResponse,
    target: &str,
) -> TestResult {
    let TokenResponse::Success {
        access_token,
        refresh_token: Some(refresh),
        ..
    } = response
    else {
        return Err(format!(
            "valid target must issue the granted tokens: {response:?}"
        ));
    };
    let meta = get_bearer_meta(&issuer.token_store, &access_token)?
        .ok_or_else(|| "bearer metadata missing".to_string())?;
    assert_eq!(meta.audience, target);
    let saved = issuer
        .token_store
        .try_get_refresh_token(&refresh)?
        .ok_or_else(|| "refresh record missing".to_string())?;
    assert_eq!(
        saved.target_context.as_ref().map(|c| c.audience.as_str()),
        Some(target)
    );
    Ok(())
}

#[test]
fn code_target_rejects_unrecorded_resource_without_consuming_code() -> TestResult {
    for scope in ["read offline_access", "openid offline_access"] {
        let (issuer, code) = code_target_fixture(scope, None)?;
        let response = issuer.exchange_code_for_tokens(
            token_request_for_code(code.clone(), Some("https://ungranted.example/api")),
            None,
        )?;
        assert_code_target_rejected(response)?;
        assert!(issuer
            .code_store
            .try_get_code_for_exchange(&code)?
            .is_some());
        let response = issuer.exchange_code_for_tokens(token_request_for_code(code, None), None)?;
        let target = if scope.starts_with("openid") {
            "https://auth.example.com/userinfo"
        } else {
            "test_client"
        };
        check_code_target_success(&issuer, response, target)?;
    }
    Ok(())
}

#[tokio::test]
async fn code_target_async_rejects_unrecorded_resource_without_consuming_code() -> TestResult {
    let (issuer, code) = code_target_fixture("openid offline_access", None)?;
    let response = issuer
        .exchange_code_for_tokens_bound_with_grant_policy_async(
            token_request_for_code(code.clone(), Some("https://ungranted.example/api")),
            None,
            None,
            true,
            true,
        )
        .await?;
    assert_code_target_rejected(response)?;
    assert!(issuer
        .code_store
        .try_get_code_for_exchange(&code)?
        .is_some());
    let response = issuer
        .exchange_code_for_tokens_bound_with_grant_policy_async(
            token_request_for_code(code, None),
            None,
            None,
            true,
            true,
        )
        .await?;
    check_code_target_success(&issuer, response, "https://auth.example.com/userinfo")
}

#[test]
fn code_target_recorded_resource_can_be_omitted_or_repeated() -> TestResult {
    let target = "https://granted.example/api";
    for request in [None, Some(target)] {
        let (issuer, code) = code_target_fixture("openid offline_access", Some(target))?;
        let response =
            issuer.exchange_code_for_tokens(token_request_for_code(code, request), None)?;
        check_code_target_success(&issuer, response, target)?;
    }
    Ok(())
}

#[test]
fn code_target_default_can_still_be_omitted() -> TestResult {
    let (issuer, code) = code_target_fixture("openid offline_access", None)?;
    let response = issuer.exchange_code_for_tokens(token_request_for_code(code, None), None)?;
    check_code_target_success(&issuer, response, "https://auth.example.com/userinfo")
}

#[test]
fn code_target_rejects_changed_or_malformed_resource_without_consuming_code() -> TestResult {
    let target = "https://granted.example/api";
    for requested in [
        "https://other.example/api",
        "/relative",
        "https://granted.example/api#fragment",
    ] {
        let (issuer, code) = code_target_fixture("openid offline_access", Some(target))?;
        let response = issuer.exchange_code_for_tokens(
            token_request_for_code(code.clone(), Some(requested)),
            None,
        )?;
        assert_code_target_rejected(response)?;
        assert!(issuer
            .code_store
            .try_get_code_for_exchange(&code)?
            .is_some());
        let response = issuer.exchange_code_for_tokens(token_request_for_code(code, None), None)?;
        check_code_target_success(&issuer, response, target)?;
    }
    Ok(())
}
