use super::*;

fn configuration(enabled: bool) -> Result<crate::oidc::OidcConfig, String> {
    let mut config = enabled_oidc_config()?;
    config.userinfo_enabled = enabled;
    Ok(config)
}

fn openid_code(issuer: &TokenIssuer, resource: Option<&str>) -> Result<String, String> {
    let (code, _) =
        issuer.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
            auth_session_id: Some("approved-session".into()),
            ..AuthorizationCodeIssueInput::new(
                authorization_request("openid offline_access", resource),
                "subject".into(),
                true,
                0,
            )
        })?;
    Ok(code)
}

#[test]
fn disabled_userinfo_rejects_jwt_default_but_preserves_explicit_and_opaque_resources() -> TestResult
{
    let issuer = issuer(true)?.with_oidc(Some(configuration(false)?));
    assert!(must_err!(
        openid_code(&issuer, None),
        "disabled UserInfo must reject JWT default"
    )
    .starts_with("invalid_target:"));
    let target = "https://resource.example/api";
    let code = openid_code(&issuer, Some(target))?;
    let (token, _) =
        tokens(issuer.exchange_code_for_tokens(token_request_for_code(code, None), None)?)?;
    assert_eq!(claims(&token)?["aud"], target);
    let opaque = issuer.with_jwt_access_tokens_enabled(false);
    let code = openid_code(&opaque, None)?;
    let (token, _) =
        tokens(opaque.exchange_code_for_tokens(token_request_for_code(code, None), None)?)?;
    assert!(!token.contains('.'));
    assert_eq!(
        get_bearer_meta(&opaque.token_store, &token)?
            .ok_or("metadata missing")?
            .audience,
        "https://auth.example.com/userinfo"
    );
    Ok(())
}

#[tokio::test]
async fn disabling_userinfo_preserves_code_for_retry_after_reenable() -> TestResult {
    let enabled = issuer(true)?.with_oidc(Some(configuration(true)?));
    let code = openid_code(&enabled, None)?;
    let disabled = enabled.with_oidc(Some(configuration(false)?));
    invalid_target(
        disabled
            .exchange_code_for_tokens_bound_with_grant_policy_async(
                token_request_for_code(code.clone(), None),
                None,
                None,
                true,
                true,
            )
            .await?,
    )?;
    assert!(disabled
        .code_store
        .try_get_code_for_exchange(&code)?
        .is_some());
    let enabled = disabled.with_oidc(Some(configuration(true)?));
    let (token, _) =
        tokens(enabled.exchange_code_for_tokens(token_request_for_code(code, None), None)?)?;
    assert_eq!(claims(&token)?["aud"], "https://auth.example.com/userinfo");
    Ok(())
}

#[tokio::test]
async fn disabling_userinfo_preserves_refresh_for_retry_after_reenable() -> TestResult {
    let enabled = issuer(true)?.with_oidc(Some(configuration(true)?));
    let code = openid_code(&enabled, None)?;
    let (_, refresh) =
        tokens(enabled.exchange_code_for_tokens(token_request_for_code(code, None), None)?)?;
    let refresh = refresh.ok_or("refresh missing")?;
    let disabled = enabled.with_oidc(Some(configuration(false)?));
    invalid_target(
        disabled
            .refresh_access_token_bound_async(refresh.clone(), None, None, None)
            .await?,
    )?;
    assert!(disabled
        .token_store
        .try_get_refresh_token(&refresh)?
        .is_some());
    let enabled = disabled.with_oidc(Some(configuration(true)?));
    let (token, _) = tokens(enabled.refresh_access_token(&refresh, None, None)?)?;
    assert_eq!(claims(&token)?["aud"], "https://auth.example.com/userinfo");
    Ok(())
}

#[test]
fn device_policy_preserves_opaque_openid_default_and_explicit_resource() -> TestResult {
    for enabled in [false, true] {
        let issuer = issuer(false)?.with_oidc(Some(configuration(enabled)?));
        let policy = issuer.device_access_token_audience_policy();
        assert_eq!(policy.resolve("client", Some("openid"), None)?, "client");
        let target = "https://resource.example/api";
        assert_eq!(
            policy.resolve("client", Some("openid"), Some(target))?,
            target
        );
        let jwt = issuer.with_jwt_access_tokens_enabled(true);
        let default =
            jwt.device_access_token_audience_policy()
                .resolve("client", Some("openid"), None);
        if enabled {
            assert_eq!(default?, "https://auth.example.com/userinfo");
        } else {
            assert!(default.is_err());
        }
    }
    Ok(())
}
