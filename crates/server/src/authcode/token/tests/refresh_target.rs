// These tests start at the issuer boundary with an already-granted scope.
// They check token/store target consistency, not authorization UI or consent.
fn oidc_offline_grant_retains_target(scope: &str) -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()))
        .with_oidc(Some(enabled_oidc_config()?));
    let (code, _) =
        issuer.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
            auth_session_id: Some("offline-grant-fixture".to_string()),
            ..AuthorizationCodeIssueInput::new(
                authorization_request(scope, None),
                "user123".to_string(),
                true,
                0,
            )
        })?;
    let response = issuer.exchange_code_for_tokens(token_request_for_code(code, None), None)?;
    let TokenResponse::Success {
        access_token,
        refresh_token: Some(refresh),
        ..
    } = response
    else {
        return Err(format!(
            "an approved offline grant must issue consistent tokens: {response:?}"
        ));
    };
    let target = "https://auth.example.com/userinfo";
    let initial = get_bearer_meta(&issuer.token_store, &access_token)?
        .ok_or_else(|| "initial bearer metadata missing".to_string())?;
    assert_eq!(initial.audience, target);
    let response = issuer.refresh_access_token(&refresh, None, None)?;
    let TokenResponse::Success { access_token, .. } = response else {
        return Err(format!(
            "refresh must preserve the initial target: {response:?}"
        ));
    };
    let refreshed = get_bearer_meta(&issuer.token_store, &access_token)?
        .ok_or_else(|| "refreshed bearer metadata missing".to_string())?;
    assert_eq!(refreshed.audience, target);
    Ok(())
}

#[test]
fn oidc_offline_grant_target_with_minimal_scope() -> TestResult {
    oidc_offline_grant_retains_target("openid offline_access")
}

#[test]
fn oidc_offline_grant_target_with_profile_and_email() -> TestResult {
    oidc_offline_grant_retains_target("openid profile email offline_access")
}

fn offline_target_fixture() -> Result<(TokenIssuer, String), String> {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()))
        .with_issuer("https://issuer-a.example".to_string());
    let (code, _) = issuer.issue_authorization_code(
        authorization_request("read offline_access", None),
        "user123".to_string(),
    )?;
    let response = issuer.exchange_code_for_tokens(token_request_for_code(code, None), None)?;
    match response {
        TokenResponse::Success {
            refresh_token: Some(refresh),
            ..
        } => Ok((issuer, refresh)),
        other => Err(format!("offline fixture issuance failed: {other:?}")),
    }
}

#[test]
fn refresh_target_rejects_changed_issuer() -> TestResult {
    let (issuer, refresh) = offline_target_fixture()?;
    let changed = issuer.with_issuer("https://issuer-b.example".to_string());
    assert!(
        matches!(changed.refresh_access_token(&refresh, None, None)?,
        TokenResponse::Error { error, .. } if error == "invalid_grant")
    );
    Ok(())
}

#[test]
fn refresh_target_requires_original_context_for_legacy_record() -> TestResult {
    let (issuer, refresh) = offline_target_fixture()?;
    let stored = issuer
        .token_store
        .try_get_refresh_token(&refresh)?
        .ok_or_else(|| "stored refresh missing".to_string())?;
    let mut legacy = serde_json::to_value(&stored).map_err(|err| err.to_string())?;
    legacy
        .as_object_mut()
        .ok_or_else(|| "refresh JSON object missing".to_string())?
        .remove("target_context");
    let legacy = serde_json::from_value(legacy).map_err(|err| err.to_string())?;
    issuer
        .token_store
        .try_replace_refresh_token_record(legacy)?;
    assert!(matches!(issuer.refresh_access_token(&refresh, None, None)?,
        TokenResponse::Error { error, .. } if error == "invalid_grant"));
    Ok(())
}

#[test]
fn refresh_target_rejects_late_resource_without_grant_authority() -> TestResult {
    let (issuer, refresh) = offline_target_fixture()?;
    assert!(
        matches!(issuer.refresh_access_token(&refresh, Some("https://other.example/resource"), None)?,
        TokenResponse::Error { error, .. } if error == "invalid_target")
    );
    Ok(())
}
