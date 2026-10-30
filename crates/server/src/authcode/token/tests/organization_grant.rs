//! Actual issuer/store component; database and browser consent have separate fixtures.
use super::*;
use crate::authcode::types::{CnfClaim, DpopKeyThumbprint, SenderBinding};
use crate::organizations::{
    consent::{Consent, GrantRequest, GRANT_TYPE},
    MembershipCeiling, Scope,
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

fn input() -> Result<AuthorizationCodeIssueInput, String> {
    let details = serde_json::json!([{"type":GRANT_TYPE,"locations":["api"],
        "organizations":[{"identifier":"学校-É","privileges":["documents.read"]}]}]);
    let request = GrantRequest::parse(&details).map_err(|e| e.to_string())?;
    let now = crate::util::now_unix_epoch_secs().map_err(|e| e.to_string())? as i64;
    let mut approval = Consent {
        support: BTreeMap::new(),
        original_authentication: None,
        version: 1,
        request,
        scope: Scope {
            environment_id: Uuid::new_v4(),
            domain_id: Uuid::new_v4(),
        },
        issuer: "https://issuer.example".into(),
        client_id: "test_client".into(),
        client_registration_id: Uuid::new_v4(),
        client_binding_id: Uuid::new_v4(),
        client_binding_revision: 1,
        domain_revision: 1,
        identity_revision: 1,
        subject: "user123".into(),
        user_id: Uuid::new_v4(),
        dpop_jkt: URL_SAFE_NO_PAD.encode([71_u8; 32]),
        auth_time: 100,
        captured_at: now,
        memberships: BTreeMap::from([(
            Uuid::new_v4(),
            MembershipCeiling {
                organization_generation: 1,
                incarnation: Uuid::new_v4(),
                grant_generation: 1,
                role_versions: BTreeMap::from([("reader".into(), 1)]),
                privileges: BTreeSet::from(["documents.read".into()]),
            },
        )]),
    };
    approval.original_authentication = Some(
        crate::organizations::authentication::OriginalAuthentication::fixture(
            approval.scope.environment_id,
            approval.user_id,
            &approval.subject,
            approval.auth_time,
            approval.captured_at,
        ),
    );
    let mut req = authorization_request("read offline_access", Some("https://parent.example/api"));
    req.dpop_jkt = Some(DpopKeyThumbprint::parse(&approval.dpop_jkt)?);
    req.authorization_details = Some(details);
    let mut input = AuthorizationCodeIssueInput::new(req, "user123".into(), true, 100);
    input.exchange_scope_ceiling = vec!["api.read".into()];
    input.organization_approval = Some(approval);
    Ok(input)
}

fn issuer() -> Result<TokenIssuer, String> {
    let policy = serde_json::from_value(serde_json::json!({
        "version":1,"targets":[{"audience":"api","resourceAliases":[]}],
        "rules":[{"clientId":"test_client","sourceAudience":"https://parent.example/api","targetAudience":"api",
            "scopes":[{"targetScope":"api.read","sourceScopes":["read"]}],"defaultScopes":["api.read"]}]
    })).map_err(|e|e.to_string())?;
    Ok(
        TokenIssuer::new_process_local_for_tests(public_jwt_key_manager()?)
            .with_token_exchange_policy(policy)
            .with_issuer("https://issuer.example".into())
            .with_jwt_access_tokens_enabled(true),
    )
}

#[tokio::test]
async fn organizations_original_issuer_requires_approval_dpop_and_refresh_root() -> TestResult {
    let issuer = issuer()?;
    let mut missing = input()?;
    missing.organization_approval = None;
    assert!(issuer
        .issue_authorization_code_with_local_profile(missing)
        .is_err());
    let mut mismatch = input()?;
    mismatch.auth_time_epoch_secs = 200;
    assert!(issuer
        .issue_authorization_code_with_local_profile(mismatch)
        .is_err());
    let input = input()?;
    let details = input.req.authorization_details.clone();
    let key = input
        .req
        .dpop_jkt
        .as_ref()
        .ok_or("key")?
        .as_str()
        .to_string();
    let (code, _) = issuer.issue_authorization_code_with_local_profile(input)?;
    let stored = issuer
        .code_store
        .try_get_code(&code)?
        .ok_or("stored code")?;
    let original = stored.exchange_grant.ok_or("original grant")?;
    let request = token_request_for_code(code.clone(), None);
    assert!(
        matches!(issuer.exchange_code_for_tokens_bound_with_grant_policy_async(request.clone(),None,None,true,true).await?,TokenResponse::Error{ref error,..} if error=="invalid_dpop_proof")
    );
    let cnf = CnfClaim::Jkt(key.clone());
    let sender = SenderBinding::DPoP { jkt: key };
    assert!(
        matches!(issuer.exchange_code_for_tokens_bound_with_grant_policy_async(request.clone(),Some(&cnf),Some(&sender),true,false).await?,TokenResponse::Error{ref error,..} if error=="invalid_grant")
    );
    assert!(issuer.code_store.try_get_code(&code)?.is_some());
    let response = issuer
        .exchange_code_for_tokens_bound_with_grant_policy_async(
            request,
            Some(&cnf),
            Some(&sender),
            true,
            true,
        )
        .await?;
    let TokenResponse::Success {
        access_token,
        refresh_token: Some(refresh),
        authorization_details,
        token_type,
        ..
    } = response
    else {
        fail_test!("issued parent expected")
    };
    assert_eq!(token_type, "DPoP");
    assert_eq!(authorization_details, details);
    let claims = decode_jwt_part(access_token.split('.').nth(1).ok_or("JWT")?)?;
    assert_eq!(
        claims["authorization_details"],
        details.clone().ok_or("details")?
    );
    assert!(claims.get("organization").is_none());
    assert!(claims.get("original_authentication").is_none());
    assert!(claims.get("upstream_subject_hash").is_none());
    let metadata = issuer
        .token_store
        .try_get_bearer_meta(&access_token)?
        .ok_or("metadata")?;
    assert_eq!(metadata.exchange_grant.as_ref(), Some(&original));
    signed_correspondence(&issuer, &access_token, &metadata)?;
    let parent = issuer
        .token_store
        .try_get_refresh_token(&refresh)?
        .ok_or("parent")?;
    assert_eq!(parent.exchange_grant.as_ref(), Some(&original));
    let renewed = issuer
        .refresh_access_token_bound_async(refresh, None, Some(cnf), Some(sender))
        .await?;
    let TokenResponse::Success {
        access_token,
        refresh_token: Some(refresh),
        authorization_details,
        ..
    } = renewed
    else {
        fail_test!("renewed parent expected")
    };
    assert_eq!(authorization_details, details);
    let metadata = issuer
        .token_store
        .try_get_bearer_meta(&access_token)?
        .ok_or("renewed metadata")?;
    assert_eq!(metadata.exchange_grant.as_ref(), Some(&original));
    signed_correspondence(&issuer, &access_token, &metadata)?;
    let parent = issuer
        .token_store
        .try_get_refresh_token(&refresh)?
        .ok_or("renewed parent")?;
    assert_eq!(parent.exchange_grant, Some(original));
    assert_eq!(parent.auth_time_epoch_secs, 100);
    Ok(())
}

fn signed_correspondence(
    issuer: &TokenIssuer,
    token: &str,
    meta: &crate::authcode::types::BearerTokenMeta,
) -> TestResult {
    let validator = TokenValidator::new(issuer.token_store.clone(), issuer.key_manager.clone())
        .with_issuer(Some("https://issuer.example".into()));
    let access = issuer
        .token_store
        .try_verify_access_token(token)?
        .ok_or("access")?;
    validator
        .validate_stored_access_token_jwt(&access, Some(meta))
        .map_err(|e| e.to_string())?;
    for field in [
        "client",
        "subject",
        "details",
        "key",
        "authentication",
        "context",
        "issued",
        "expiry",
    ] {
        let mut changed = meta.clone();
        match field {
            "client" => changed.client_id = "different-client".into(),
            "subject" => changed.user_id = "different-subject".into(),
            "details" => {
                changed.authorization_details.as_mut().ok_or("details")?[0]["organizations"][0]
                    ["identifier"] = serde_json::json!("different organization")
            }
            "key" => {
                changed.sender_binding = Some(SenderBinding::DPoP {
                    jkt: URL_SAFE_NO_PAD.encode([72_u8; 32]),
                })
            }
            "authentication" => changed.auth_time_epoch_secs = Some(101),
            "context" => changed.acr = Some("changed-acr".into()),
            "issued" => changed.issued_at += std::time::Duration::from_secs(1),
            "expiry" => changed.expires_at += std::time::Duration::from_secs(1),
            _ => unreachable!(),
        }
        assert!(
            validator
                .validate_stored_access_token_jwt(&access, Some(&changed))
                .is_err(),
            "signed {field} must match stored authority"
        );
    }
    let mut claims = decode_jwt_part(token.split('.').nth(1).ok_or("payload")?)?;
    claims["authorization_details"][0]["organizations"][0]["privileges"] =
        serde_json::json!(["documents.write"]);
    let signing = format!(
        "{}.{}",
        token.split('.').next().ok_or("header")?,
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).map_err(|e| e.to_string())?)
    );
    let mut changed = access;
    changed.token = format!(
        "{signing}.{}",
        URL_SAFE_NO_PAD.encode(
            issuer
                .key_manager
                .sign(signing.as_bytes())
                .map_err(|e| e.to_string())?
        )
    );
    assert!(
        validator
            .validate_stored_access_token_jwt(&changed, Some(meta))
            .is_err(),
        "valid signature cannot substitute another authorization detail"
    );
    Ok(())
}
