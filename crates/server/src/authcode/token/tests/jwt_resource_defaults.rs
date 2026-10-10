use super::*;

fn issuer(jwt: bool) -> Result<TokenIssuer, String> {
    Ok(
        TokenIssuer::new_process_local_for_tests(public_jwt_key_manager()?)
            .with_issuer("https://auth.example.com".into())
            .with_jwt_access_tokens_enabled(jwt),
    )
}

fn invalid_target(response: TokenResponse) -> TestResult {
    match response {
        TokenResponse::Error { error, .. } if error == "invalid_target" => Ok(()),
        other => Err(format!("expected no-resource rejection, got {other:?}")),
    }
}

fn tokens(response: TokenResponse) -> Result<(String, Option<String>), String> {
    match response {
        TokenResponse::Success {
            access_token,
            refresh_token,
            ..
        } => Ok((access_token, refresh_token)),
        other => Err(format!("expected authorized token issuance, got {other:?}")),
    }
}

fn claims(token: &str) -> Result<Value, String> {
    decode_jwt_part(token.split('.').nth(1).ok_or("JWT payload missing")?)
}

#[test]
fn jwt_bearer_sync_entrypoints_reject_missing_default() -> TestResult {
    let issuer = issuer(true)?.with_oidc(Some(enabled_oidc_config()?));
    for resource in [None, Some(""), Some(" ")] {
        invalid_target(issuer.issue_jwt_bearer_token(
            "client",
            "subject",
            Some("read".into()),
            resource,
            None,
        )?)?;
        invalid_target(issuer.issue_jwt_bearer_token_bound(
            "client",
            "subject",
            Some("read".into()),
            resource,
            None,
            None,
        )?)?;
    }
    assert!(matches!(
        issuer.issue_jwt_bearer_token("client", "subject", Some("openid".into()), None, None)?,
        TokenResponse::Error { error, .. } if error == "invalid_scope"
    ));
    Ok(())
}

#[tokio::test]
async fn jwt_bearer_async_rejects_default_and_preserves_explicit_target_binding() -> TestResult {
    use crate::authcode::types::{CnfClaim, SenderBinding};
    let issuer = issuer(true)?;
    invalid_target(
        issuer
            .issue_jwt_bearer_token_bound_async(
                "client".into(),
                "subject".into(),
                Some("read".into()),
                None,
                None,
                None,
            )
            .await?,
    )?;
    let target = "https://resource.example/api";
    let cnf = CnfClaim::Jkt("test-thumbprint".into());
    let binding = SenderBinding::DPoP {
        jkt: "test-thumbprint".into(),
    };
    let response = issuer
        .issue_jwt_bearer_token_bound_async(
            "client".into(),
            "subject".into(),
            Some("read".into()),
            Some(target.into()),
            Some(cnf),
            Some(binding.clone()),
        )
        .await?;
    assert!(matches!(&response, TokenResponse::Success { token_type, .. } if token_type == "DPoP"));
    let (token, _) = tokens(response)?;
    let payload = claims(&token)?;
    assert_eq!(payload["aud"], target);
    assert_eq!(payload["sub"], "subject");
    assert_eq!(payload["client_id"], "client");
    assert_eq!(payload["cnf"]["jkt"], "test-thumbprint");
    let meta = get_bearer_meta(&issuer.token_store, &token)?.ok_or("metadata missing")?;
    assert_eq!(meta.audience, target);
    assert_eq!(meta.sender_binding, Some(binding));
    Ok(())
}

#[test]
fn jwt_bearer_explicit_resource_and_opaque_default_remain_available() -> TestResult {
    let target = "https://resource.example/api";
    let jwt = issuer(true)?;
    let (token, _) = tokens(jwt.issue_jwt_bearer_token(
        "client",
        "subject",
        Some("read".into()),
        Some(target),
        None,
    )?)?;
    assert_eq!(claims(&token)?["aud"], target);
    let opaque = issuer(false)?;
    let (token, _) = tokens(opaque.issue_jwt_bearer_token(
        "client",
        "subject",
        Some("read".into()),
        None,
        None,
    )?)?;
    assert!(!token.contains('.'));
    assert_eq!(
        get_bearer_meta(&opaque.token_store, &token)?
            .ok_or("metadata")?
            .audience,
        "client"
    );
    Ok(())
}

#[test]
fn jwt_authorization_code_requires_an_approved_default_before_storage() -> TestResult {
    let issuer = issuer(true)?;
    let error = must_err!(
        issuer.issue_authorization_code(authorization_request("read", None), "subject".into()),
        "missing resource must reject authorization-code issuance",
    );
    assert!(error.starts_with("invalid_target:"));
    let target = "https://resource.example/api";
    let (code, _) = issuer.issue_authorization_code(
        authorization_request("read", Some(target)),
        "subject".into(),
    )?;
    let (token, _) =
        tokens(issuer.exchange_code_for_tokens(token_request_for_code(code, None), None)?)?;
    assert_eq!(claims(&token)?["aud"], target);
    Ok(())
}

#[tokio::test]
async fn enabling_jwt_does_not_consume_a_legacy_code_without_resource() -> TestResult {
    let opaque = issuer(false)?;
    let (code, _) =
        opaque.issue_authorization_code(authorization_request("read", None), "subject".into())?;
    let jwt = opaque.with_jwt_access_tokens_enabled(true);
    invalid_target(
        jwt.exchange_code_for_tokens_bound_with_grant_policy_async(
            token_request_for_code(code.clone(), None),
            None,
            None,
            true,
            true,
        )
        .await?,
    )?;
    assert!(jwt.code_store.try_get_code_for_exchange(&code)?.is_some());
    let opaque = jwt.with_jwt_access_tokens_enabled(false);
    tokens(opaque.exchange_code_for_tokens(token_request_for_code(code, None), None)?)?;
    Ok(())
}

#[tokio::test]
async fn enabling_jwt_does_not_rotate_a_legacy_client_default_refresh() -> TestResult {
    let opaque = issuer(false)?;
    let (code, _) = opaque.issue_authorization_code(
        authorization_request("read offline_access", None),
        "subject".into(),
    )?;
    let (_, refresh) =
        tokens(opaque.exchange_code_for_tokens(token_request_for_code(code, None), None)?)?;
    let refresh = refresh.ok_or("refresh missing")?;
    let jwt = opaque.with_jwt_access_tokens_enabled(true);
    invalid_target(jwt.refresh_access_token(&refresh, None, None)?)?;
    invalid_target(
        jwt.refresh_access_token_bound_async(refresh.clone(), None, None, None)
            .await?,
    )?;
    assert!(jwt.token_store.try_get_refresh_token(&refresh)?.is_some());
    let opaque = jwt.with_jwt_access_tokens_enabled(false);
    tokens(opaque.refresh_access_token(&refresh, None, None)?)?;
    Ok(())
}

#[test]
fn openid_default_and_client_credentials_permit_select_resource_audiences() -> TestResult {
    let issuer = issuer(true)?.with_oidc(Some(enabled_oidc_config()?));
    let (code, _) =
        issuer.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
            auth_session_id: Some("approved-session".into()),
            ..AuthorizationCodeIssueInput::new(
                authorization_request("openid offline_access", None),
                "subject".into(),
                true,
                0,
            )
        })?;
    let (token, refresh) =
        tokens(issuer.exchange_code_for_tokens(token_request_for_code(code, None), None)?)?;
    let target = "https://auth.example.com/userinfo";
    assert_eq!(claims(&token)?["aud"], target);
    let (token, _) =
        tokens(issuer.refresh_access_token(&refresh.ok_or("refresh missing")?, None, None)?)?;
    assert_eq!(claims(&token)?["aud"], target);
    let target = "https://resource.example/api";
    let (token, _) = tokens(issuer.issue_client_credentials_token(
        issuer.client_credentials_permit_for_tests("client", &["read".into()], target),
        None,
    )?)?;
    assert_eq!(claims(&token)?["aud"], target);
    Ok(())
}

#[test]
fn explicit_resource_equal_to_client_identifier_is_still_an_approved_target() -> TestResult {
    let client = "https://resource.example/api";
    let issuer = issuer(true)?;
    let mut request = authorization_request("read offline_access", Some(client));
    request.client_id = client.into();
    let (code, _) = issuer.issue_authorization_code(request, "subject".into())?;
    let mut redemption = token_request_for_code(code, None);
    redemption.client_id = client.into();
    let (_, refresh) = tokens(issuer.exchange_code_for_tokens(redemption, None)?)?;
    let (token, _) =
        tokens(issuer.refresh_access_token(&refresh.ok_or("refresh missing")?, None, None)?)?;
    assert_eq!(claims(&token)?["aud"], client);
    Ok(())
}

#[test]
fn client_identifier_equal_to_userinfo_does_not_create_a_default() -> TestResult {
    let target = "https://auth.example.com/userinfo";
    for scope in ["read offline_access", "openid offline_access"] {
        let opaque = issuer(false)?.with_oidc(Some(enabled_oidc_config()?));
        let mut request = authorization_request(scope, None);
        request.client_id = target.into();
        let (code, _) =
            opaque.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
                auth_session_id: Some("approved-session".into()),
                ..AuthorizationCodeIssueInput::new(request, "subject".into(), true, 0)
            })?;
        let mut redemption = token_request_for_code(code, None);
        redemption.client_id = target.into();
        let (_, refresh) = tokens(opaque.exchange_code_for_tokens(redemption, None)?)?;
        let refresh = refresh.ok_or("refresh missing")?;
        let jwt = opaque.with_jwt_access_tokens_enabled(true);
        let response = jwt.refresh_access_token(&refresh, None, None)?;
        if scope.starts_with("openid ") {
            let (token, _) = tokens(response)?;
            assert_eq!(claims(&token)?["aud"], target);
        } else {
            invalid_target(response)?;
            assert!(jwt.token_store.try_get_refresh_token(&refresh)?.is_some());
        }
    }
    Ok(())
}

#[tokio::test]
async fn refresh_scope_narrowing_keeps_original_openid_resource_default() -> TestResult {
    let issuer = issuer(true)?.with_oidc(Some(enabled_oidc_config()?));
    let (code, _) =
        issuer.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
            auth_session_id: Some("approved-session".into()),
            ..AuthorizationCodeIssueInput::new(
                authorization_request("openid read offline_access", None),
                "subject".into(),
                true,
                0,
            )
        })?;
    let (_, refresh) =
        tokens(issuer.exchange_code_for_tokens(token_request_for_code(code, None), None)?)?;
    let refresh = refresh.ok_or("refresh missing")?;
    let stored = issuer
        .token_store
        .try_get_refresh_token(&refresh)?
        .ok_or("stored refresh missing")?;
    let response = issuer
        .refresh_prepared_access_token_bound_async(
            refresh,
            stored,
            None,
            Some("read".into()),
            None,
            None,
        )
        .await?;
    assert!(
        matches!(&response, TokenResponse::Success { scope: Some(scope), .. } if scope == "read")
    );
    let (token, _) = tokens(response)?;
    assert_eq!(claims(&token)?["aud"], "https://auth.example.com/userinfo");
    Ok(())
}
