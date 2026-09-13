//! Issuer-level integration of application projection and actual refresh lineage.
//! Projection authority is seeded directly; HTTP authority checks are separate.
use super::*;
use crate::application_authorization::inorii::{Grant, CLAIM_NAME};

fn projection() -> Result<Grant, String> {
    serde_json::from_value(serde_json::json!({
        "version":1, "environment_id":uuid::Uuid::new_v4(),
        "issuer":"https://issuer.example", "client_id":"test_client", "subject":"user123",
        "revision":7, "audiences":["test_client"], "selected_organization":null,
        "claims":{"roles":["USER"], "organization_roles":[]}
    }))
    .map_err(|e| e.to_string())
}

#[tokio::test]
async fn application_exchange_lineage_retains_projection_with_and_without_refresh() -> TestResult {
    for asynchronous in [false, true] {
        for issue_refresh in [false, true] {
            let projection = projection()?;
            let policy = must_ok!(
                serde_json::from_value(serde_json::json!({
                    "version":1, "targets":[{"audience":"api", "resourceAliases":[]}],
                    "rules":[{"clientId":"test_client", "sourceAudience":"test_client",
                        "targetAudience":"api", "scopes":[{"targetScope":"api.read", "sourceScopes":["read"]}],
                        "defaultScopes":["api.read"]}]
                })),
                "policy"
            );
            let issuer = TokenIssuer::new_process_local_for_tests(public_jwt_key_manager()?)
                .with_token_exchange_policy(policy)
                .with_issuer("https://issuer.example".into())
                .with_jwt_access_tokens_enabled(true);
            let mut input = crate::authcode::token::AuthorizationCodeIssueInput::new(
                authorization_request("read offline_access", None),
                "user123".into(),
                true,
                1,
            );
            input.application_grant = Some(projection.clone());
            input.exchange_scope_ceiling = vec!["api.read".into()];
            let (code, _) = must_ok!(
                issuer.issue_authorization_code_with_local_profile(input),
                "code"
            );
            let request = token_request_for_code(code, None);
            let response = if asynchronous {
                issuer
                    .exchange_code_for_tokens_bound_with_grant_policy_async(
                        request,
                        None,
                        None,
                        true,
                        issue_refresh,
                    )
                    .await?
            } else {
                issuer.exchange_code_for_tokens_bound_with_grant_policy(
                    request,
                    None,
                    None,
                    true,
                    issue_refresh,
                )?
            };
            let TokenResponse::Success {
                access_token,
                refresh_token,
                ..
            } = response
            else {
                fail_test!("expected issuance: {response:?}");
            };
            let part = must_some!(access_token.split('.').nth(1), "JWT payload");
            let payload = decode_jwt_part(part)?;
            assert_eq!(
                payload[CLAIM_NAME],
                must_ok!(serde_json::to_value(&projection.claims), "claims")
            );
            let meta = must_some!(
                issuer.token_store.try_get_bearer_meta(&access_token)?,
                "metadata"
            );
            assert_eq!(meta.application_grant.as_ref(), Some(&projection));
            assert_eq!(meta.exchange_grant.is_some(), issue_refresh);
            assert_eq!(refresh_token.is_some(), issue_refresh);
            let access = must_some!(
                issuer.token_store.try_verify_access_token(&access_token)?,
                "access"
            );
            assert_eq!(access.exchange_root.is_some(), issue_refresh);
            if let Some(refresh_token) = refresh_token {
                let parent = must_some!(
                    issuer.token_store.try_get_refresh_token(&refresh_token)?,
                    "parent"
                );
                assert_eq!(parent.application_grant.as_ref(), Some(&projection));
                assert_eq!(parent.exchange_grant, meta.exchange_grant);
                assert!(parent.exchange_grant.is_some());
            }
        }
    }
    Ok(())
}
