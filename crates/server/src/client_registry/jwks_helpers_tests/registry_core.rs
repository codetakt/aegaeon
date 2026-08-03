use super::*;

struct BackendUnavailableReplayStore;

impl ReplayStore for BackendUnavailableReplayStore {
    fn check_and_store(
        &self,
        _entry: crate::middleware::ReplayEntry<'_>,
    ) -> Result<(), ReplayStoreError> {
        Err(ReplayStoreError::BackendUnavailable("down".to_string()))
    }
}

fn registration_client(
    client_id: &str,
    registration_access_token: Option<&str>,
) -> RegisteredClient {
    RegisteredClient {
        client_id: client_id.to_string(),
        client_secret: None,
        redirect_uris: vec!["https://example.com/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: "private_key_jwt".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: vec!["read".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        registration_access_token: registration_access_token.map(ToString::to_string),
        client_id_issued_at: None,
    }
}

#[test]
fn redirect_uri_validation_is_exact_only() {
    let registry = ClientRegistry::new_process_local_for_tests();
    registry.register(RegisteredClient {
        client_id: "redirect-client".to_string(),
        client_secret: None,
        redirect_uris: vec!["https://example.com/callback/*".to_string()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: "none".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: vec!["openid".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        registration_access_token: None,
        client_id_issued_at: None,
    });

    assert!(registry.validate_redirect_uri("redirect-client", "https://example.com/callback/*"));
    assert!(!registry.validate_redirect_uri("redirect-client", "https://example.com/callback/foo"));
}

#[test]
fn jwt_replay_store_is_namespace_and_client_scoped() {
    let store = std::sync::Arc::new(InMemoryReplayStore::new()) as std::sync::Arc<dyn ReplayStore>;

    assert!(record_jwt_replay(
        &store,
        PRIVATE_KEY_JWT_REPLAY_NAMESPACE,
        "client-a",
        "jti-1",
        300,
    )
    .is_ok());
    assert!(matches!(
        record_jwt_replay(
            &store,
            PRIVATE_KEY_JWT_REPLAY_NAMESPACE,
            "client-a",
            "jti-1",
            300,
        ),
        Err(ReplayStoreError::Replay)
    ));
    assert!(record_jwt_replay(
        &store,
        PRIVATE_KEY_JWT_REPLAY_NAMESPACE,
        "client-b",
        "jti-1",
        300,
    )
    .is_ok());
    assert!(record_jwt_replay(
        &store,
        JWT_BEARER_REPLAY_NAMESPACE,
        "client-a",
        "jti-1",
        300,
    )
    .is_ok());
}

#[test]
fn jwt_replay_store_backend_errors_are_preserved() {
    let store =
        std::sync::Arc::new(BackendUnavailableReplayStore) as std::sync::Arc<dyn ReplayStore>;

    let result = record_jwt_replay(
        &store,
        PRIVATE_KEY_JWT_REPLAY_NAMESPACE,
        "client-a",
        "jti-1",
        300,
    );

    assert!(matches!(
        result,
        Err(ReplayStoreError::BackendUnavailable(message)) if message == "down"
    ));
}

#[test]
fn jwt_replay_material_is_length_delimited() {
    assert_ne!(
        jwt_replay_material("client\0jti", "suffix"),
        jwt_replay_material("client", "jti\0suffix")
    );
}

#[test]
fn registration_token_lookup_scans_all_candidates() -> TestResult {
    let clients = vec![
        registration_client("client-a", Some("rat-a")),
        registration_client("client-without-rat", None),
        registration_client("client-b", Some("rat-b")),
    ];
    let mut visited = 0;
    let selected = test_some(
        select_registration_token_match(clients.iter().inspect(|_| visited += 1), "rat-b"),
        "matching registration token",
    )?;

    assert_eq!(
        visited,
        clients.len(),
        "registration token selection must not stop at the first mismatch or match"
    );
    assert_eq!(selected.client_id, "client-b");

    let registry = ClientRegistry::new_process_local_for_tests();
    clients
        .into_iter()
        .for_each(|client| assert!(registry.register(client)));
    assert_eq!(
        registry
            .get_by_registration_token("rat-b")
            .map(|client| client.client_id),
        Some("client-b".to_string())
    );
    assert!(registry.get_by_registration_token("rat-missing").is_none());
    Ok(())
}

#[test]
fn replace_all_clients_removes_stale_clients_and_credentials() {
    let registry = ClientRegistry::new_process_local_for_tests();
    let mut stale = registration_client("stale-client", None);
    stale.token_endpoint_auth_method = "client_secret_basic".to_string();
    assert!(registry.register(stale));
    registry.register_client_secret_credentials(
        "stale-client",
        vec![ClientSecretCredential::new("stale-hash".to_string(), 10)],
    );

    let mut active = registration_client("active-client", None);
    active.token_endpoint_auth_method = "client_secret_basic".to_string();
    let active_credential = ClientSecretCredential::new("active-hash".to_string(), 20);

    registry.replace_all_clients(
        HashMap::from([(active.client_id.clone(), active)]),
        HashMap::from([
            ("active-client".to_string(), vec![active_credential.clone()]),
            (
                "orphan-client".to_string(),
                vec![ClientSecretCredential::new("orphan-hash".to_string(), 30)],
            ),
        ]),
    );

    assert!(!registry.is_registered_client("stale-client"));
    assert!(registry
        .client_secret_credentials("stale-client")
        .is_empty());
    assert_eq!(
        registry.client_secret_credentials("active-client"),
        vec![active_credential]
    );
    assert!(registry
        .client_secret_credentials("orphan-client")
        .is_empty());
    assert_eq!(registry.runtime_snapshot_fingerprint(), None);
}

#[test]
fn replace_all_clients_can_record_runtime_snapshot_fingerprint() {
    let registry = ClientRegistry::new_process_local_for_tests();
    let active = registration_client("active-client", None);

    registry.replace_all_clients_with_fingerprint(
        HashMap::from([(active.client_id.clone(), active)]),
        HashMap::new(),
        Some("runtime-fingerprint".to_string()),
    );

    assert_eq!(
        registry.runtime_snapshot_fingerprint().as_deref(),
        Some("runtime-fingerprint")
    );
}

#[test]
fn confidential_client_requires_valid_credentials() -> TestResult {
    let _lock = env_lock()?;
    let _client_assertion_redis = EnvVarGuard::new(
        "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
        Some("redis://127.0.0.1/0"),
    );
    let _jwks_redis = EnvVarGuard::new(JWKS_REDIS_URL_ENV, Some("redis://127.0.0.1/1"));
    let registry = test_context(
        ClientRegistry::try_with_test_clients_with_runtime_policy(
            ClientAssertionRuntimePolicy::default(),
            JwksRuntimePolicy::default(),
            &crate::config::RuntimeStateNamespace::for_tests("client-registry-core-test"),
        ),
        "test clients",
    )?;
    assert!(registry.is_confidential("test-client"));
    let header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("test-client:test-secret")
    );
    assert_eq!(
        registry.validate_basic_auth(&header).map(|(id, _)| id),
        Some("test-client".to_string())
    );
    let bad_header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("test-client:wrong-secret")
    );
    assert!(registry.validate_basic_auth(&bad_header).is_none());
    assert!(registry
        .validate_client_secret_post(Some("test-client"), Some("test-secret"))
        .is_none());
    assert!(registry
        .validate_client_secret_post(Some("test-client-post"), Some("test-secret-post"))
        .is_some());
    assert!(registry
        .validate_client_secret_post(Some("test-client-post"), Some("wrong-secret"))
        .is_none());
    Ok(())
}

#[test]
fn public_client_auth_method_comparison_is_canonical() {
    let registry = ClientRegistry::new_process_local_for_tests();
    registry.register(RegisteredClient {
        client_id: "public-client".to_string(),
        client_secret: None,
        redirect_uris: vec!["https://example.com/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: " None ".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: vec!["read".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        registration_access_token: None,
        client_id_issued_at: None,
    });

    assert!(
        !registry.is_confidential("public-client"),
        "public clients must remain public after trim/case normalization"
    );
}

#[test]
fn client_jwt_allowed_algorithms_reject_unknown_values() {
    assert!(std::panic::catch_unwind(|| {
        ClientAssertionRuntimePolicy::try_new(
            ["RS256".to_string(), "HS256".to_string()],
            false,
            60,
            aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
            300,
            300,
        )
    })
    .is_ok_and(|result| result.is_err()));
}

fn promoted_rsa_test_client(
    client_id: &str,
    jwk_alg: &str,
    token_endpoint_auth_method: &str,
) -> Result<RegisteredClient, String> {
    let (modulus, exponent) = test_some(
        rsa_public_components_from_public_pem(TEST_RSA_PUBLIC_KEY_PEM),
        "rsa public components",
    )?;
    let inline_jwks = RegisteredClientJwks::from_value(
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": "promoted-rsa-test-key",
                "alg": jwk_alg,
                "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(modulus),
                "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(exponent)
            }]
        }),
        true,
    )?;
    Ok(RegisteredClient {
        client_id: client_id.to_string(),
        client_secret: None,
        redirect_uris: vec!["https://client.example/cb".to_string()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: token_endpoint_auth_method.to_string(),
        jwks_pem: None,
        inline_jwks: Some(inline_jwks),
        jwks_uri: None,
        token_endpoint_auth_signing_alg: (token_endpoint_auth_method == "private_key_jwt")
            .then(|| jwk_alg.to_string()),
        allowed_scopes: vec!["read".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        registration_access_token: None,
        client_id_issued_at: None,
    })
}

fn sign_promoted_rsa_test_jwt(
    algorithm: jsonwebtoken::Algorithm,
    claims: serde_json::Value,
) -> Result<String, String> {
    let header = serde_json::json!({
        "alg": match algorithm {
            jsonwebtoken::Algorithm::PS256 => "PS256",
            jsonwebtoken::Algorithm::PS384 => "PS384",
            _ => return Err("unsupported promoted RSA test algorithm".to_string()),
        },
        "kid": "promoted-rsa-test-key",
        "typ": "JWT"
    });
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|err| err.to_string())?);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&claims).map_err(|err| err.to_string())?);
    let signing_input = format!("{header}.{payload}");
    let private_key = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)
        .map_err(|err| err.to_string())?
        .into_contents();
    let signer = aegaeon_crypto::signing::RsaPssSigner::from_pkcs8(&private_key)
        .map_err(|err| err.to_string())?;
    let signature = match algorithm {
        jsonwebtoken::Algorithm::PS256 => signer.sign_pss256(signing_input.as_bytes()),
        jsonwebtoken::Algorithm::PS384 => signer.sign_pss384(signing_input.as_bytes()),
        _ => unreachable!("algorithm checked above"),
    }
    .map_err(|err| err.to_string())?;
    Ok(format!(
        "{signing_input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn current_test_epoch() -> Result<i64, String> {
    test_some(unix_epoch_now_i64("promoted RSA test clock"), "test clock")
}

fn ps256_client_assertion_policy() -> Result<ClientAssertionRuntimePolicy, String> {
    ClientAssertionRuntimePolicy::try_new(
        ["PS256".to_string()],
        false,
        60,
        aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
        300,
        300,
    )
    .map_err(|err| err.to_string())
}

#[test]
fn verified_profile_routes_ps256_request_objects_through_promoted_verifier() -> TestResult {
    let client_id = "ps256-jar-client";
    let registry = ClientRegistry::new_process_local_for_tests();
    assert!(registry.register(promoted_rsa_test_client(client_id, "PS256", "none")?));
    let now = current_test_epoch()?;
    let assertion = sign_promoted_rsa_test_jwt(
        jsonwebtoken::Algorithm::PS256,
        serde_json::json!({
            "iss": client_id,
            "aud": ["https://issuer.example"],
            "exp": now + 300,
            "nbf": now - 5,
            "client_id": client_id,
            "jti": "jar-ps256"
        }),
    )?;

    let verified = registry
        .verify_request_object(
            client_id,
            &assertion,
            "https://issuer.example",
            aegaeon_jose::algorithms::CryptoProfile::Verified,
        )
        .map_err(|err| err.to_string())?;
    assert_eq!(verified.algorithm, jsonwebtoken::Algorithm::PS256);
    Ok(())
}

#[test]
fn verified_profile_keeps_ps384_request_objects_rejected() -> TestResult {
    let client_id = "ps384-jar-client";
    let registry = ClientRegistry::new_process_local_for_tests();
    assert!(registry.register(promoted_rsa_test_client(client_id, "PS384", "none")?));
    let now = current_test_epoch()?;
    let assertion = sign_promoted_rsa_test_jwt(
        jsonwebtoken::Algorithm::PS384,
        serde_json::json!({
            "iss": client_id,
            "aud": ["https://issuer.example"],
            "exp": now + 300,
            "client_id": client_id
        }),
    )?;

    assert!(matches!(
        registry.verify_request_object(
            client_id,
            &assertion,
            "https://issuer.example",
            aegaeon_jose::algorithms::CryptoProfile::Verified,
        ),
        Err(RequestObjectValidationError::Jose(
            RequestObjectError::UnsupportedAlgorithm(_)
        ))
    ));
    Ok(())
}

#[test]
fn ps256_request_object_rejects_rs256_labeled_jwk() -> TestResult {
    let client_id = "ps256-jwk-mismatch-client";
    let registry = ClientRegistry::new_process_local_for_tests();
    assert!(registry.register(promoted_rsa_test_client(client_id, "RS256", "none")?));
    let now = current_test_epoch()?;
    let assertion = sign_promoted_rsa_test_jwt(
        jsonwebtoken::Algorithm::PS256,
        serde_json::json!({
            "iss": client_id,
            "aud": ["https://issuer.example"],
            "exp": now + 300,
            "client_id": client_id
        }),
    )?;

    assert!(matches!(
        registry.verify_request_object(
            client_id,
            &assertion,
            "https://issuer.example",
            aegaeon_jose::algorithms::CryptoProfile::Verified,
        ),
        Err(RequestObjectValidationError::VerificationKeyMissing(id)) if id == client_id
    ));
    Ok(())
}

#[test]
fn private_key_jwt_ps256_requires_explicit_policy_and_uses_promoted_verifier() -> TestResult {
    let client_id = "ps256-private-key-jwt-client";
    let expected_aud = "https://issuer.example/token";
    let client = promoted_rsa_test_client(client_id, "PS256", "private_key_jwt")?;
    let now = current_test_epoch()?;
    let assertion = sign_promoted_rsa_test_jwt(
        jsonwebtoken::Algorithm::PS256,
        serde_json::json!({
            "iss": client_id,
            "sub": client_id,
            "aud": expected_aud,
            "exp": now + 300,
            "iat": now,
            "jti": "pkjwt-ps256"
        }),
    )?;

    let allowed = ClientRegistry::new_process_local_with_runtime_policy_for_tests(
        ps256_client_assertion_policy()?,
        JwksRuntimePolicy::default(),
    );
    assert!(allowed.register(client.clone()));
    assert_eq!(
        allowed
            .try_validate_private_key_jwt(
                client_id,
                &assertion,
                expected_aud,
                aegaeon_jose::algorithms::CryptoProfile::Verified,
            )
            .map_err(|err| format!("{err:?}"))?,
        Some(client_id.to_string())
    );

    let default_policy = ClientRegistry::new_process_local_for_tests();
    assert!(default_policy.register(client));
    assert_eq!(
        default_policy
            .try_validate_private_key_jwt(
                client_id,
                &assertion,
                expected_aud,
                aegaeon_jose::algorithms::CryptoProfile::Verified,
            )
            .map_err(|err| format!("{err:?}"))?,
        None
    );
    Ok(())
}

#[test]
fn jwt_bearer_ps256_requires_explicit_policy_and_uses_promoted_verifier() -> TestResult {
    let client_id = "ps256-jwt-bearer-client";
    let token_aud = "https://issuer.example/token";
    let client = promoted_rsa_test_client(client_id, "PS256", "client_secret_basic")?;
    let now = current_test_epoch()?;
    let assertion = sign_promoted_rsa_test_jwt(
        jsonwebtoken::Algorithm::PS256,
        serde_json::json!({
            "iss": client_id,
            "sub": "resource-owner",
            "aud": token_aud,
            "exp": now + 300,
            "iat": now,
            "jti": "jwt-bearer-ps256"
        }),
    )?;

    let allowed = ClientRegistry::new_process_local_with_runtime_policy_for_tests(
        ps256_client_assertion_policy()?,
        JwksRuntimePolicy::default(),
    );
    assert!(allowed.register(client.clone()));
    assert_eq!(
        allowed
            .try_validate_jwt_bearer_grant_assertion(
                client_id,
                &assertion,
                token_aud,
                "https://issuer.example",
                false,
                aegaeon_jose::algorithms::CryptoProfile::Verified,
            )
            .map_err(|err| format!("{err:?}"))?,
        Some("resource-owner".to_string())
    );

    let default_policy = ClientRegistry::new_process_local_for_tests();
    assert!(default_policy.register(client));
    assert_eq!(
        default_policy
            .try_validate_jwt_bearer_grant_assertion(
                client_id,
                &assertion,
                token_aud,
                "https://issuer.example",
                false,
                aegaeon_jose::algorithms::CryptoProfile::Verified,
            )
            .map_err(|err| format!("{err:?}"))?,
        None
    );
    Ok(())
}

#[test]
fn client_secret_hash_authenticates_without_plaintext_secret() -> TestResult {
    let registry = ClientRegistry::new_process_local_for_tests();
    registry.register(RegisteredClient {
        client_id: "db-client".to_string(),
        client_secret: None,
        redirect_uris: vec!["https://example.com/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: vec!["read".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        registration_access_token: None,
        client_id_issued_at: None,
    });
    registry.register(RegisteredClient {
        client_id: "db-post-client".to_string(),
        client_secret: None,
        redirect_uris: vec!["https://example.com/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: "client_secret_post".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: vec!["read".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        registration_access_token: None,
        client_id_issued_at: None,
    });
    let secret_hash = test_context(
        crate::local_credentials::hash_password("db-secret"),
        "hash client secret",
    )?;
    let expired_secret_hash = test_context(
        crate::local_credentials::hash_password("expired-secret"),
        "hash expired client secret",
    )?;
    let now_epoch_secs = test_some(
        unix_epoch_now_i64("client secret test clock"),
        "test clock should be valid",
    )?;
    registry.register_client_secret_credentials(
        "db-client",
        vec![
            ClientSecretCredential::new(secret_hash, now_epoch_secs + 60),
            ClientSecretCredential::new(expired_secret_hash, now_epoch_secs - 1),
        ],
    );
    let post_secret_hash = test_context(
        crate::local_credentials::hash_password("db-post-secret"),
        "hash post client secret",
    )?;
    registry.register_client_secret_credentials(
        "db-post-client",
        vec![ClientSecretCredential::new(
            post_secret_hash,
            now_epoch_secs + 60,
        )],
    );

    let header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("db-client:db-secret")
    );
    assert!(registry.validate_basic_auth(&header).is_some());
    assert!(registry
        .validate_client_secret_post(Some("db-client"), Some("db-secret"))
        .is_none());
    assert!(registry
        .validate_client_secret_post(Some("db-post-client"), Some("db-post-secret"))
        .is_some());
    assert!(registry
        .validate_client_secret_post(Some("db-post-client"), Some("wrong"))
        .is_none());
    assert!(registry
        .validate_client_secret_post(Some("db-client"), Some("expired-secret"))
        .is_none());
    Ok(())
}
