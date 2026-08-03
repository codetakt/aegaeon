use super::*;
use crate::jwk_types::Jwk;
use base64::Engine as _;

fn test_environment_id() -> uuid::Uuid {
    uuid::Uuid::from_u128(0x4444_5555_6666_7777_8888_9999_aaaa_bbbb)
}

fn encrypted_key_handle_fixture() -> String {
    format!(
        "{}{}",
        crate::key_encryption::KEY_HANDLE_ENVELOPE_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 28])
    )
}

fn rsa_sig_key(usage: RuntimeKeyUsage, status: RuntimeKeyStatus) -> RuntimeKey {
    RuntimeKey {
        environment_id: test_environment_id(),
        usage,
        algorithm: RuntimeKeyAlgorithm::Rs256,
        provider: RuntimeKeyProvider::DatabaseEncrypted,
        status,
        retiring_expires_at_epoch_secs: (status == RuntimeKeyStatus::Retiring)
            .then_some(4_102_444_800),
        kid: "oidc-sig-1".to_string(),
        public_jwk: Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            kid: "oidc-sig-1".to_string(),
            alg: Some("RS256".to_string()),
            n: Some("AQAB".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        },
        key_handle: encrypted_key_handle_fixture(),
        provider_configuration: serde_json::json!({}),
    }
}

fn rsa_enc_key() -> RuntimeKey {
    RuntimeKey {
        environment_id: test_environment_id(),
        usage: RuntimeKeyUsage::OidcRequestObjectDecryption,
        algorithm: RuntimeKeyAlgorithm::RsaOaepA256Gcm,
        provider: RuntimeKeyProvider::DatabaseEncrypted,
        status: RuntimeKeyStatus::Active,
        retiring_expires_at_epoch_secs: None,
        kid: "oidc-enc-1".to_string(),
        public_jwk: Jwk {
            kty: "RSA".to_string(),
            use_: Some("enc".to_string()),
            kid: "oidc-enc-1".to_string(),
            alg: Some("RSA-OAEP".to_string()),
            n: Some("AQAB".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        },
        key_handle: encrypted_key_handle_fixture(),
        provider_configuration: serde_json::json!({}),
    }
}

fn aws_kms_oidc_sig_key() -> RuntimeKey {
    let mut key = rsa_sig_key(
        RuntimeKeyUsage::OidcIdTokenSigning,
        RuntimeKeyStatus::Active,
    );
    key.provider = RuntimeKeyProvider::AwsKms;
    key.provider_configuration = serde_json::json!({ "region": "ap-northeast-1" });
    key
}

#[test]
fn rejects_retiring_runtime_key_without_expiry() {
    let mut key = rsa_sig_key(
        RuntimeKeyUsage::OidcIdTokenSigning,
        RuntimeKeyStatus::Retiring,
    );
    key.retiring_expires_at_epoch_secs = None;

    let result = RuntimeKeySet::try_new(vec![key]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidKey {
            field: "retiring_expires_at",
            ..
        })
    ));
}

#[test]
fn rejects_active_runtime_key_with_retiring_expiry() {
    let mut key = rsa_sig_key(
        RuntimeKeyUsage::OidcIdTokenSigning,
        RuntimeKeyStatus::Active,
    );
    key.retiring_expires_at_epoch_secs = Some(4_102_444_800);

    let result = RuntimeKeySet::try_new(vec![key]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidKey {
            field: "retiring_expires_at",
            ..
        })
    ));
}

#[test]
fn accepts_oidc_runtime_key_set() -> Result<(), String> {
    let key_set = RuntimeKeySet::try_new(vec![
        rsa_sig_key(
            RuntimeKeyUsage::OidcIdTokenSigning,
            RuntimeKeyStatus::Active,
        ),
        rsa_enc_key(),
    ])
    .map_err(|err| format!("valid key set: {err}"))?;

    assert!(key_set
        .active_key(RuntimeKeyUsage::OidcIdTokenSigning)
        .is_some());
    assert!(key_set
        .active_key(RuntimeKeyUsage::OidcRequestObjectDecryption)
        .is_some());
    Ok(())
}

#[test]
fn rejects_database_encrypted_runtime_key_provider_configuration() {
    let mut key = rsa_sig_key(
        RuntimeKeyUsage::OidcIdTokenSigning,
        RuntimeKeyStatus::Active,
    );
    key.provider_configuration = serde_json::json!({ "region": "unused" });

    let result = RuntimeKeySet::try_new(vec![key]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidKey {
            field: "provider_configuration",
            ..
        })
    ));
}

#[test]
fn rejects_legacy_runtime_key_handle_envelope() {
    let mut key = rsa_sig_key(
        RuntimeKeyUsage::OidcIdTokenSigning,
        RuntimeKeyStatus::Active,
    );
    key.key_handle = "legacy-encrypted-handle".to_string();

    let result = RuntimeKeySet::try_new(vec![key]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidKey {
            field: "key_handle",
            ..
        })
    ));
}

#[test]
fn accepts_aws_kms_oidc_id_token_signing_runtime_key() -> Result<(), String> {
    let key_set = RuntimeKeySet::try_new(vec![aws_kms_oidc_sig_key()])
        .map_err(|err| format!("valid AWS KMS OIDC key: {err}"))?;

    assert!(key_set
        .active_key(RuntimeKeyUsage::OidcIdTokenSigning)
        .is_some());
    Ok(())
}

#[test]
fn rejects_aws_kms_runtime_key_without_region() {
    let mut key = aws_kms_oidc_sig_key();
    key.provider_configuration = serde_json::json!({});

    let result = RuntimeKeySet::try_new(vec![key]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidKey {
            field: "provider_configuration",
            ..
        })
    ));
}

#[test]
fn rejects_aws_kms_runtime_key_with_blank_region() {
    let mut key = aws_kms_oidc_sig_key();
    key.provider_configuration = serde_json::json!({ "region": " " });

    let result = RuntimeKeySet::try_new(vec![key]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidKey {
            field: "provider_configuration.region",
            ..
        })
    ));
}

#[test]
fn rejects_aws_kms_runtime_key_with_public_key_identifier() {
    let mut key = aws_kms_oidc_sig_key();
    key.provider_configuration = serde_json::json!({
        "region": "ap-northeast-1",
        "keyId": "arn:aws:kms:ap-northeast-1:111122223333:key/example",
    });

    let result = RuntimeKeySet::try_new(vec![key]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidKey {
            field: "provider_configuration",
            ..
        })
    ));
}

#[test]
fn rejects_aws_kms_runtime_key_for_non_oidc_id_token_usage() {
    let mut key = rsa_enc_key();
    key.provider = RuntimeKeyProvider::AwsKms;
    key.provider_configuration = serde_json::json!({ "region": "ap-northeast-1" });

    let result = RuntimeKeySet::try_new(vec![key]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidKey {
            field: "provider",
            ..
        })
    ));
}

#[test]
fn rejects_duplicate_active_usage() {
    let result = RuntimeKeySet::try_new(vec![
        rsa_sig_key(
            RuntimeKeyUsage::OidcIdTokenSigning,
            RuntimeKeyStatus::Active,
        ),
        rsa_sig_key(
            RuntimeKeyUsage::OidcIdTokenSigning,
            RuntimeKeyStatus::Active,
        ),
    ]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::DuplicateActiveUsage(
            "OIDC_ID_TOKEN_SIGNING"
        ))
    ));
}

#[test]
fn rejects_unbounded_retiring_keys_per_usage() {
    let mut keys = Vec::new();
    keys.push(rsa_sig_key(
        RuntimeKeyUsage::OidcIdTokenSigning,
        RuntimeKeyStatus::Active,
    ));
    keys.extend((0..5).map(|index| {
        let mut key = rsa_sig_key(
            RuntimeKeyUsage::OidcIdTokenSigning,
            RuntimeKeyStatus::Retiring,
        );
        key.kid = format!("oidc-sig-retiring-{index}");
        key.public_jwk.kid = key.kid.clone();
        key
    }));

    let result = RuntimeKeySet::try_new(keys);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::TooManyRetiringKeys {
            usage: "OIDC_ID_TOKEN_SIGNING",
            count: 5,
            max: 4,
        })
    ));
}

#[test]
fn rejects_algorithm_usage_mismatch() {
    let result = RuntimeKeySet::try_new(vec![rsa_sig_key(
        RuntimeKeyUsage::OidcRequestObjectDecryption,
        RuntimeKeyStatus::Active,
    )]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidKey {
            field: "algorithm",
            ..
        })
    ));
}

#[test]
fn rejects_runtime_signing_key_outside_policy_allowlist() -> Result<(), String> {
    let key_set = RuntimeKeySet::try_new(vec![rsa_sig_key(
        RuntimeKeyUsage::OidcIdTokenSigning,
        RuntimeKeyStatus::Active,
    )])
    .map_err(|err| format!("valid key set: {err}"))?;

    let result = key_set.validate_allowed_signing_algorithms(&["EdDSA".to_string()]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::PolicyDisallowedSigningAlgorithm {
            usage: "OIDC_ID_TOKEN_SIGNING",
            algorithm: "RS256",
        })
    ));
    Ok(())
}

#[test]
fn accepts_runtime_signing_key_inside_policy_allowlist() -> Result<(), String> {
    let key_set = RuntimeKeySet::try_new(vec![rsa_sig_key(
        RuntimeKeyUsage::OidcIdTokenSigning,
        RuntimeKeyStatus::Active,
    )])
    .map_err(|err| format!("valid key set: {err}"))?;

    key_set
        .validate_allowed_signing_algorithms(&["RS256".to_string(), "EdDSA".to_string()])
        .map_err(|err| format!("allowed key set: {err}"))
}

#[test]
fn rejects_ps256_as_runtime_key_algorithm() {
    let result = RuntimeKeyAlgorithm::try_from_db("PS256");

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidAlgorithm(algorithm)) if algorithm == "PS256"
    ));
}

#[test]
fn rejects_es256_as_runtime_key_algorithm() {
    let result = RuntimeKeyAlgorithm::try_from_db("ES256");

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidAlgorithm(algorithm)) if algorithm == "ES256"
    ));
}

#[test]
fn rejects_federation_signing_runtime_key_usage() {
    let result = RuntimeKeyUsage::try_from_db("FEDERATION_SIGNING");

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidUsage(usage)) if usage == "FEDERATION_SIGNING"
    ));
}

#[test]
fn rejects_unknown_policy_signing_algorithm() -> Result<(), String> {
    let key_set = RuntimeKeySet::try_new(Vec::new()).map_err(|err| format!("empty set: {err}"))?;

    let result = key_set.validate_allowed_signing_algorithms(&["PS256".to_string()]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidPolicySigningAlgorithm(_))
    ));
    Ok(())
}

#[test]
fn rejects_es256_as_policy_signing_algorithm() -> Result<(), String> {
    let key_set = RuntimeKeySet::try_new(Vec::new()).map_err(|err| format!("empty set: {err}"))?;

    let result = key_set.validate_allowed_signing_algorithms(&["ES256".to_string()]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidPolicySigningAlgorithm(algorithm)) if algorithm == "ES256"
    ));
    Ok(())
}

#[test]
fn rejects_public_jwk_kid_mismatch() {
    let mut key = rsa_sig_key(
        RuntimeKeyUsage::OidcIdTokenSigning,
        RuntimeKeyStatus::Active,
    );
    key.public_jwk.kid = "other".to_string();

    let result = RuntimeKeySet::try_new(vec![key]);

    assert!(matches!(
        result,
        Err(RuntimeKeySetError::InvalidKey {
            field: "public_jwk.kid",
            ..
        })
    ));
}
