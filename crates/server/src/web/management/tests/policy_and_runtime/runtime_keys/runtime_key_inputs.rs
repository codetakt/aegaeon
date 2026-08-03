
fn runtime_key_create_request(usage: &str) -> CreateRuntimeKeyRequest {
    CreateRuntimeKeyRequest {
        base_configuration_version_id: Uuid::new_v4().to_string(),
        usage: usage.to_string(),
        algorithm: None,
        provider: "databaseEncrypted".to_string(),
        kid: Some("runtime-key-1".to_string()),
        provider_configuration: None,
        private_key_pem: Some(TEST_RSA_PRIVATE_KEY_PEM.to_string()),
        activate: true,
        comment: Some("initial import".to_string()),
    }
}

fn runtime_key_input_environment_id() -> Uuid {
    Uuid::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0001)
}

fn runtime_key_input_context(input: &RuntimeKeyCreateInput) -> KeyHandleEncryptionContext<'_> {
    KeyHandleEncryptionContext::new(
        runtime_key_input_environment_id(),
        input.usage.as_db_str(),
        &input.provider,
        &input.algorithm,
        &input.kid,
    )
}

fn pkcs8_private_key_pem(pkcs8: Vec<u8>) -> String {
    pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8))
}

#[test]
fn prepare_runtime_key_create_input_accepts_oidc_signing_database_encrypted_pkcs8() -> TestResult {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key encryption key env guard".to_string())?;
    let kek = [0x51u8; 32];
    let _env = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode(kek));

    let req = runtime_key_create_request("OIDC_ID_TOKEN_SIGNING");
    let input = prepare_runtime_key_create_input(&req, runtime_key_input_environment_id(), "req-1")
        .map_err(|_| io::Error::other("runtime key request should validate"))?;
    let parsed = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)?;
    let decrypted = decrypt_key_handle(
        &input.encrypted_key_handle,
        &kek,
        runtime_key_input_context(&input),
    )?;

    assert_eq!(input.usage, RuntimeKeyUsageInput::OidcIdTokenSigning);
    assert_eq!(input.algorithm, "RS256");
    assert_eq!(input.provider, "databaseEncrypted");
    assert_eq!(input.initial_status, "ACTIVE");
    assert_eq!(decrypted, URL_SAFE_NO_PAD.encode(parsed.contents()));
    assert_eq!(input.public_jwk["kty"], "RSA");
    assert_eq!(input.public_jwk["use"], "sig");
    assert_eq!(input.public_jwk["kid"], "runtime-key-1");
    assert_eq!(input.public_jwk["alg"], "RS256");
    Ok(())
}

#[test]
fn prepare_runtime_key_create_input_accepts_jwt_access_signing_eddsa() -> TestResult {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "key encryption key env guard".to_string())?;
    let kek = [0x52u8; 32];
    let _env = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode(kek));
    let key_data = aegaeon_crypto::signing::Ed25519SigningKey::generate()
        .map_err(|_| io::Error::other("ed25519 key generation"))?;
    let mut req = runtime_key_create_request("JWT_ACCESS_TOKEN_SIGNING");
    req.private_key_pem = Some(pkcs8_private_key_pem(key_data.pkcs8.clone()));

    let input = prepare_runtime_key_create_input(&req, runtime_key_input_environment_id(), "req-1")
        .map_err(|_| io::Error::other("JWT access runtime key request should validate"))?;
    let decrypted = decrypt_key_handle(
        &input.encrypted_key_handle,
        &kek,
        runtime_key_input_context(&input),
    )?;

    assert_eq!(input.usage, RuntimeKeyUsageInput::JwtAccessTokenSigning);
    assert_eq!(input.algorithm, "EdDSA");
    assert_eq!(decrypted, URL_SAFE_NO_PAD.encode(key_data.pkcs8));
    assert_eq!(input.public_jwk["kty"], "OKP");
    assert_eq!(input.public_jwk["crv"], "Ed25519");
    assert_eq!(input.public_jwk["use"], "sig");
    assert_eq!(input.public_jwk["kid"], "runtime-key-1");
    assert_eq!(input.public_jwk["alg"], "EdDSA");
    Ok(())
}

#[test]
fn prepare_runtime_key_create_input_rejects_jwt_introspection_signing_es256() -> TestResult {
    let mut req = runtime_key_create_request("JWT_INTROSPECTION_SIGNING");
    req.algorithm = Some("ES256".to_string());
    let key_data = aegaeon_crypto::signing::EcdsaP256SigningKey::generate()
        .map_err(|_| io::Error::other("es256 key generation"))?;
    req.private_key_pem = Some(pkcs8_private_key_pem(key_data.pkcs8));

    assert!(prepare_runtime_key_create_input(&req, runtime_key_input_environment_id(), "req-1")
        .is_err());
    Ok(())
}

#[test]
fn prepare_runtime_key_create_input_rejects_federation_signing() {
    let req = runtime_key_create_request("FEDERATION_SIGNING");

    assert!(
        prepare_runtime_key_create_input(&req, runtime_key_input_environment_id(), "req-1")
            .is_err()
    );
}

#[test]
fn prepare_runtime_key_create_input_rejects_unsupported_algorithm() {
    let mut req = runtime_key_create_request("OIDC_ID_TOKEN_SIGNING");
    req.algorithm = Some("ES256".to_string());
    assert!(prepare_runtime_key_create_input(&req, runtime_key_input_environment_id(), "req-1")
        .is_err());
}

#[test]
fn prepare_runtime_key_create_input_rejects_missing_private_key() {
    let mut req = runtime_key_create_request("OIDC_ID_TOKEN_SIGNING");
    req.private_key_pem = None;
    assert!(prepare_runtime_key_create_input(&req, runtime_key_input_environment_id(), "req-1")
        .is_err());
}

#[test]
fn prepare_runtime_key_create_input_rejects_database_encrypted_provider_configuration() {
    let mut req = runtime_key_create_request("OIDC_ID_TOKEN_SIGNING");
    req.provider_configuration = Some(serde_json::json!({ "region": "unused" }));
    assert!(prepare_runtime_key_create_input(&req, runtime_key_input_environment_id(), "req-1")
        .is_err());
}

#[cfg(not(feature = "kms-aws"))]
#[tokio::test]
async fn prepare_runtime_key_create_input_rejects_aws_kms_without_feature() {
    let mut req = runtime_key_create_request("OIDC_ID_TOKEN_SIGNING");
    req.provider = "awsKms".to_string();
    req.provider_configuration = Some(serde_json::json!({
        "region": "ap-northeast-1",
        "keyId": "arn:aws:kms:ap-northeast-1:123456789012:key/example",
    }));
    req.private_key_pem = None;

    assert!(
        prepare_runtime_key_create_input_async(&req, runtime_key_input_environment_id(), "req-1")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn prepare_runtime_key_create_input_rejects_aws_kms_for_non_oidc_signing_usage() {
    let mut req = runtime_key_create_request("JWT_ACCESS_TOKEN_SIGNING");
    req.provider = "awsKms".to_string();
    req.provider_configuration = Some(serde_json::json!({
        "region": "ap-northeast-1",
        "keyId": "arn:aws:kms:ap-northeast-1:123456789012:key/example",
    }));
    req.private_key_pem = None;

    assert!(
        prepare_runtime_key_create_input_async(&req, runtime_key_input_environment_id(), "req-1")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn prepare_runtime_key_create_input_rejects_aws_kms_private_key_material() {
    let mut req = runtime_key_create_request("OIDC_ID_TOKEN_SIGNING");
    req.provider = "awsKms".to_string();
    req.provider_configuration = Some(serde_json::json!({
        "region": "ap-northeast-1",
        "keyId": "arn:aws:kms:ap-northeast-1:123456789012:key/example",
    }));

    assert!(
        prepare_runtime_key_create_input_async(&req, runtime_key_input_environment_id(), "req-1")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn prepare_runtime_key_create_input_rejects_aws_kms_unknown_configuration_fields() {
    let mut req = runtime_key_create_request("OIDC_ID_TOKEN_SIGNING");
    req.provider = "awsKms".to_string();
    req.provider_configuration = Some(serde_json::json!({
        "region": "ap-northeast-1",
        "keyId": "arn:aws:kms:ap-northeast-1:123456789012:key/example",
        "endpointUrl": "https://kms.example.test",
    }));
    req.private_key_pem = None;

    assert!(
        prepare_runtime_key_create_input_async(&req, runtime_key_input_environment_id(), "req-1")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn prepare_runtime_key_create_input_rejects_aws_kms_missing_key_id() {
    let mut req = runtime_key_create_request("OIDC_ID_TOKEN_SIGNING");
    req.provider = "awsKms".to_string();
    req.provider_configuration = Some(serde_json::json!({
        "region": "ap-northeast-1",
    }));
    req.private_key_pem = None;

    assert!(
        prepare_runtime_key_create_input_async(&req, runtime_key_input_environment_id(), "req-1")
            .await
            .is_err()
    );
}

#[test]
fn runtime_key_create_audit_data_omits_secret_material() -> TestResult {
    let input = RuntimeKeyCreateInput {
        usage: RuntimeKeyUsageInput::OidcRequestObjectDecryption,
        kid: "runtime-key-1".to_string(),
        algorithm: "RSA-OAEP+A256GCM".to_string(),
        provider: "databaseEncrypted".to_string(),
        initial_status: "NEXT",
        public_jwk: serde_json::json!({
            "kty": "RSA",
            "kid": "runtime-key-1",
            "alg": "RSA-OAEP",
            "use": "enc",
        }),
        encrypted_key_handle: "encrypted-key-handle-secret".to_string(),
        provider_configuration: serde_json::json!({}),
        comment: Some("audit note".to_string()),
    };

    let audit = runtime_key_create_audit_data(&input);
    let serialized = serde_json::to_string(&audit)?;

    assert!(serialized.contains("OIDC_REQUEST_OBJECT_DECRYPTION"));
    assert!(!serialized.contains("encrypted-key-handle-secret"));
    assert!(!serialized.contains("PRIVATE KEY"));
    assert!(audit.get("publicJwk").is_none());
    assert!(audit.get("providerConfiguration").is_none());
    assert_eq!(audit["providerConfigurationRedacted"], true);
    Ok(())
}

#[test]
fn runtime_key_lifecycle_audit_data_omits_secret_material() -> TestResult {
    let runtime_key = RuntimeKey {
        id: Uuid::new_v4().to_string(),
        environment_id: Uuid::new_v4().to_string(),
        usage: "OIDC_ID_TOKEN_SIGNING".to_string(),
        kid: "runtime-key-1".to_string(),
        algorithm: "RS256".to_string(),
        provider: "databaseEncrypted".to_string(),
        status: "ACTIVE".to_string(),
        public_jwk: serde_json::json!({
            "kty": "RSA",
            "kid": "runtime-key-1",
            "alg": "RS256",
            "use": "sig",
        }),
        provider_configuration: serde_json::json!({}),
        retiring_expires_at: None,
        created_at: "2026-06-05T00:00:00.000Z".to_string(),
    };

    let audit = runtime_key_lifecycle_audit_data(
        &runtime_key,
        "ACTIVATE_NEXT",
        Some("activate rotation"),
    );
    let serialized = serde_json::to_string(&audit)?;

    assert!(serialized.contains("OIDC_ID_TOKEN_SIGNING"));
    assert!(!serialized.contains("privateKeyPem"));
    assert!(!serialized.contains("keyHandle"));
    assert!(!serialized.contains("PRIVATE KEY"));
    assert!(audit.get("publicJwk").is_none());
    Ok(())
}
