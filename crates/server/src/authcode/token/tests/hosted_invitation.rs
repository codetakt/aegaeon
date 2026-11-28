use super::*;

#[test]
fn hosted_invitation_bounds_code_refresh_parent_and_keeps_concurrent_root_independent() -> TestResult
{
    let issuer_url = "https://issuer.example";
    let scope = "organization.invitation.accept";
    let target = format!("{issuer_url}/organization-invitations");
    let source = format!("{issuer_url}/userinfo");
    let policy=serde_json::from_value(serde_json::json!({"version":1,"targets":[{"audience":target,"resourceAliases":[]}],"rules":[{
        "clientId":"test_client","sourceAudience":source,"targetAudience":target,
        "scopes":[{"sourceScopes":["read"],"targetScope":scope}],"defaultScopes":[scope]}]})).map_err(|e|e.to_string())?;
    let issuer = TokenIssuer::new_process_local_with_ttls_for_tests(
        Arc::new(InMemoryKeyManager::new()),
        600,
        3600,
        120,
    )
    .with_issuer(issuer_url.into())
    .with_token_exchange_policy(policy);
    let deadline = SystemTime::now() + Duration::from_secs(43);
    let issue = |deadline| -> Result<_, String> {
        let req = authorization_request("read offline_access", Some(&source));
        let input = AuthorizationCodeIssueInput {
            hosted_invitation_deadline: deadline,
            exchange_scope_ceiling: vec![scope.into()],
            ..AuthorizationCodeIssueInput::new(req, "recipient".into(), true, 0)
        };
        let (code, _) = issuer.issue_authorization_code_with_local_profile(input)?;
        let stored = issuer
            .code_store
            .try_get_code(&code)?
            .ok_or("missing code")?;
        let grant = stored.exchange_grant.ok_or("missing root authority")?;
        let root = grant.root().ok_or("missing root")?.clone();
        assert_eq!(grant.is_hosted_invitation(), deadline.is_some());
        let response =
            issuer.exchange_code_for_tokens(token_request_for_code(code, Some(&source)), None)?;
        let TokenResponse::Success {
            access_token,
            expires_in,
            refresh_token: Some(refresh),
            ..
        } = response
        else {
            return Err("missing family".into());
        };
        let family = issuer
            .token_store
            .try_get_refresh_token(&refresh)?
            .ok_or("missing refresh")?;
        if let Some(cutoff) = deadline {
            assert_eq!(stored.expires_at, cutoff);
            assert_eq!(root.expires_at, cutoff);
            assert!(expires_in <= 43);
            assert!(family.expires_at <= cutoff);
        } else {
            assert!(expires_in > 43);
            assert!(family.expires_at > SystemTime::now() + Duration::from_secs(44));
        }
        Ok((root.id, access_token, refresh))
    };
    let (one, first, refresh) = issue(Some(deadline))?;
    let (two, concurrent, _) = issue(Some(deadline))?;
    let (_, ordinary, _) = issue(None)?;
    assert_ne!(one, two);
    issuer.token_store.try_revoke_token(&refresh)?;
    assert!(issuer
        .token_store
        .try_verify_access_token(&first)?
        .is_none());
    assert!(issuer
        .token_store
        .try_verify_access_token(&concurrent)?
        .is_some());
    assert!(issuer
        .token_store
        .try_verify_access_token(&ordinary)?
        .is_some());
    assert!(issue(Some(SystemTime::now())).is_err());
    Ok(())
}
