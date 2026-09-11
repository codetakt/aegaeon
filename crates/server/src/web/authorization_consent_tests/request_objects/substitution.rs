use super::*;

fn check_assertion_substitution(bearer: bool) -> TestResult {
    let registry = crate::client_registry::ClientRegistry::new_process_local_for_tests();
    let mut client = sample_registered_client(CLIENT);
    client.token_endpoint_auth_method = "private_key_jwt".to_string();
    client.jwks_pem =
        Some(include_str!("../../../../tests/fixtures/rsa2048-public.pem").to_string());
    assert!(registry.try_register(client)?);
    let issuer = "https://issuer.example";
    let token_endpoint = "https://issuer.example/token";
    let profile = crate::config::ServerConfig::default().crypto_profile;
    let key = EncodingKey::from_rsa_pem(include_bytes!(
        "../../../../tests/fixtures/rsa2048-private.pk8.pem"
    ))?;
    for (typ, response_type, expected) in [
        (None, false, true),
        (Some("JWT"), false, true),
        (Some("oauth-authz-req+jwt"), false, false),
        (Some("application/oauth-authz-req+jwt"), false, false),
        (None, true, false),
        (Some("JWT"), true, false),
        (Some("oauth-authz-req+jwt"), true, false),
    ] {
        let now = crate::util::now_unix_epoch_secs()?;
        let mut claims = json!({"iss": CLIENT, "sub": CLIENT, "client_id": CLIENT,
            "aud": if bearer {issuer} else {token_endpoint}, "iat": now, "exp": now + 30,
            "jti": Uuid::new_v4().to_string()});
        if response_type {
            claims["response_type"] = json!("code");
            claims["redirect_uri"] = json!("https://client.example.com/callback");
        }
        let mut header = Header::new(Algorithm::RS256);
        header.typ = typ.map(str::to_string);
        let assertion = jsonwebtoken::encode(&header, &claims, &key)?;
        let admitted = if bearer {
            // The optional client-subject profile overlaps the canonical AS
            // audience, so audience alone cannot establish JWT kind separation.
            registry
                .try_validate_jwt_bearer_grant_assertion(
                    CLIENT,
                    &assertion,
                    token_endpoint,
                    issuer,
                    true,
                    profile,
                )
                .map_err(|error| format!("bearer validation failed: {error:?}"))?
        } else {
            registry
                .try_validate_private_key_jwt(CLIENT, &assertion, token_endpoint, profile)
                .map_err(|error| format!("client assertion validation failed: {error:?}"))?
        };
        assert_eq!(
            admitted.is_some(),
            expected,
            "bearer={bearer} typ={typ:?} response_type={response_type}"
        );
    }
    Ok(())
}

#[test]
fn jwt_kind_separation_private_key_jwt_rejects_request_objects() -> TestResult {
    check_assertion_substitution(false)
}

#[test]
fn jwt_kind_separation_bearer_client_subject_rejects_request_objects() -> TestResult {
    check_assertion_substitution(true)
}
