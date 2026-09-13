#[test]
fn test_access_tokens_default_to_opaque() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let response = must_ok!(
        issuer.issue_client_credentials_token("client", Some("read".to_string()), None, None),
        "client credentials token",
    );

    let access_token = match response {
        TokenResponse::Success { access_token, .. } => access_token,
        other => fail_test!("expected success response, got {other:?}"),
    };

    assert!(
        !access_token.contains('.'),
        "opaque access tokens must not be JWT-like by default"
    );
    Ok(())
}

#[test]
fn test_jwt_access_token_claims_when_enabled() -> TestResult {
    let issuer = "https://auth.example.com";
    let token_issuer = TokenIssuer::new_process_local_for_tests(public_jwt_key_manager()?)
        .with_issuer(issuer.to_string())
        .with_jwt_access_tokens_enabled(true);

    let response = must_ok!(
        token_issuer.issue_client_credentials_token("client", Some("read".to_string()), None, None),
        "client credentials token",
    );

    let access_token = match response {
        TokenResponse::Success { access_token, .. } => access_token,
        other => fail_test!("expected success response, got {other:?}"),
    };

    let parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(parts.len(), 3, "jwt access token must be JWS compact");

    let header = decode_jwt_part(parts[0])?;
    assert_eq!(header.get("typ").and_then(|v| v.as_str()), Some("at+jwt"));

    let payload = decode_jwt_part(parts[1])?;
    assert_eq!(payload.get("iss").and_then(|v| v.as_str()), Some(issuer));
    assert_eq!(payload.get("sub").and_then(|v| v.as_str()), Some("client"));
    assert_eq!(
        payload.get("client_id").and_then(|v| v.as_str()),
        Some("client")
    );
    assert_eq!(payload.get("aud").and_then(|v| v.as_str()), Some("client"));
    assert!(payload.get("iat").and_then(Value::as_u64).is_some());
    assert!(payload.get("exp").and_then(Value::as_u64).is_some());
    assert!(payload.get("jti").and_then(|v| v.as_str()).is_some());
    Ok(())
}

#[test]
fn test_jwt_access_token_issuance_requires_public_verification_material() -> TestResult {
    let token_issuer =
        TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()))
            .with_issuer("https://auth.example.com".to_string())
            .with_jwt_access_tokens_enabled(true);

    let response = must_ok!(
        token_issuer.issue_client_credentials_token("client", Some("read".to_string()), None, None),
        "client credentials token",
    );

    let TokenResponse::Error {
        error,
        error_description,
    } = response
    else {
        fail_test!("expected fail-closed JWT access token response");
    };
    assert_eq!(error, "server_error");
    assert_eq!(
        error_description.as_deref(),
        Some("JWT access token signing requires public verification material")
    );
    Ok(())
}

#[tokio::test]
async fn application_service_claim_release_and_dpop_type_follow_actual_grant() -> TestResult {
    use crate::application_authorization::inorii::{Claims, Grant, CLAIM_NAME};
    use crate::authcode::types::{CnfClaim, SenderBinding};
    let issuer = "https://auth.example.com";
    let token_issuer = TokenIssuer::new_process_local_for_tests(public_jwt_key_manager()?)
        .with_issuer(issuer.to_string())
        .with_jwt_access_tokens_enabled(true);
    let grant = Grant {
        version: 1,
        environment_id: uuid::Uuid::new_v4(),
        issuer: issuer.into(),
        client_id: "service-client".into(),
        subject: "service-client".into(),
        revision: 1,
        audiences: vec!["https://api.example/service".into()],
        selected_organization: None,
        claims: Claims {
            roles: vec![],
            organization_roles: vec![],
        },
    };
    let jkt = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_owned();
    let cnf = CnfClaim::Jkt(jkt.clone());
    let binding = SenderBinding::DPoP { jkt: jkt.clone() };
    for audience in [
        "https://api.example/service",
        "https://other.example/service",
    ] {
        let response = token_issuer
            .issue_client_credentials_application_token_async(
                "service-client",
                Some("read".into()),
                Some(audience),
                Some(&cnf),
                Some(&binding),
                Some(&grant),
            )
            .await?;
        let TokenResponse::Success {
            access_token,
            token_type,
            refresh_token,
            ..
        } = response
        else {
            fail_test!("client credentials issuance failed");
        };
        assert_eq!(token_type, "DPoP");
        assert!(refresh_token.is_none());
        let payload = decode_jwt_part(access_token.split('.').nth(1).ok_or("JWT payload")?)?;
        assert_eq!(payload["cnf"]["jkt"], jkt);
        if audience == grant.audiences[0] {
            assert_eq!(
                payload[CLAIM_NAME],
                serde_json::json!({"roles":[],"organization_roles":[]})
            );
        } else {
            assert!(payload.get(CLAIM_NAME).is_none());
        }
        let meta = token_issuer
            .token_store
            .try_get_bearer_meta(&access_token)?
            .ok_or("stored meta")?;
        assert_eq!(meta.application_grant, Some(grant.clone()));
        assert_eq!(meta.sender_binding, Some(binding.clone()));
    }
    Ok(())
}

#[test]
fn exchange_minter_preserves_only_authorized_application_claims() -> TestResult {
    use crate::application_authorization::inorii::{Claims, GlobalRole, Grant, CLAIM_NAME};
    use crate::authcode::BearerAccessTokenMint;
    let issuer = "https://auth.example.com";
    let token_issuer = TokenIssuer::new_process_local_for_tests(public_jwt_key_manager()?)
        .with_issuer(issuer.to_string())
        .with_jwt_access_tokens_enabled(true);
    let grant = Grant {
        version: 1,
        environment_id: uuid::Uuid::new_v4(),
        issuer: issuer.into(),
        client_id: "bff".into(),
        subject: "human-subject".into(),
        revision: 1,
        audiences: vec!["service-a".into()],
        selected_organization: None,
        claims: Claims {
            roles: vec![GlobalRole::User],
            organization_roles: vec![],
        },
    };
    let mint = BearerAccessTokenMint {
        application_grant: Some(&grant),
        client_id: "bff",
        subject: "human-subject",
        scope: Some("read"),
        audience: "service-a",
        issued_at: std::time::SystemTime::now(),
        expires_in: 60,
        auth_time_epoch_secs: None,
        acr: None,
        cnf: None,
    };
    for audience in ["service-a", "service-b"] {
        let token =
            token_issuer.mint_bearer_access_token(BearerAccessTokenMint { audience, ..mint })?;
        let payload = decode_jwt_part(token.split('.').nth(1).ok_or("JWT payload")?)?;
        if audience == "service-a" {
            assert_eq!(
                payload[CLAIM_NAME],
                serde_json::to_value(&grant.claims).map_err(|error| error.to_string())?
            );
        } else {
            assert!(payload.get(CLAIM_NAME).is_none());
        }
    }
    assert!(token_issuer
        .mint_bearer_access_token(BearerAccessTokenMint {
            subject: "another-human",
            ..mint
        })
        .is_err());
    Ok(())
}
