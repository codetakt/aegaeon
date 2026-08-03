use super::*;
use crate::runtime_keys::{
    RuntimeKey, RuntimeKeyAlgorithm, RuntimeKeyProvider, RuntimeKeySet, RuntimeKeyStatus,
    RuntimeKeyUsage,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use std::ffi::OsString;

type TestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(err) => fail_test!("{}: {:?}", $context, err),
        }
    };
}

macro_rules! must_some {
    ($value:expr, $context:expr $(,)?) => {
        match $value {
            Some(value) => value,
            None => fail_test!("{}", $context),
        }
    };
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var_os(key);
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn managed_runtime_key_environment_id() -> uuid::Uuid {
    uuid::Uuid::from_u128(0x2222_3333_4444_5555_6666_7777_8888_9999)
}

fn runtime_key_handle_context(
    usage: RuntimeKeyUsage,
    algorithm: RuntimeKeyAlgorithm,
    kid: &str,
) -> crate::key_encryption::KeyHandleEncryptionContext<'_> {
    crate::key_encryption::KeyHandleEncryptionContext::new(
        managed_runtime_key_environment_id(),
        usage.as_db_str(),
        RuntimeKeyProvider::DatabaseEncrypted.as_db_str(),
        algorithm.as_str(),
        kid,
    )
}

fn encrypt_runtime_key_pkcs8_handle(
    pkcs8: &[u8],
    kek: &[u8; 32],
    usage: RuntimeKeyUsage,
    algorithm: RuntimeKeyAlgorithm,
    kid: &str,
) -> Result<String, crate::key_encryption::KeyHandleEncryptionError> {
    crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(pkcs8),
        kek,
        runtime_key_handle_context(usage, algorithm, kid),
    )
}

#[test]
fn federation_key_generation() {
    let km = InMemoryKeyManager::new();
    let federation_jwk = FederationKeyManager::federation_public_jwk(&km);
    assert!(federation_jwk.is_some(), "must have federation JWK");
    let Some(jwk) = federation_jwk else {
        return;
    };
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");
    assert_eq!(jwk["alg"], "ES256");
    assert!(jwk["x"].is_string());
    assert!(jwk["y"].is_string());
    assert!(
        matches!(jwk["kid"].as_str(), Some(kid) if kid.starts_with("fed-")),
        "kid should be present and use the fed- prefix"
    );
}

#[test]
fn federation_sign_produces_64_byte_signature() {
    let km = InMemoryKeyManager::new();
    let signature_result = FederationKeyManager::sign_federation(&km, b"test signing input");
    assert!(
        signature_result.is_ok(),
        "federation signing should succeed for test input"
    );
    let Ok(sig) = signature_result else {
        return;
    };
    assert_eq!(sig.len(), 64, "ES256 signature must be 64 bytes (R||S)");
}

#[test]
fn federation_sign_uses_random_nonce() {
    let km = InMemoryKeyManager::new();
    let sig1_result = FederationKeyManager::sign_federation(&km, b"msg");
    let sig2_result = FederationKeyManager::sign_federation(&km, b"msg");
    assert!(
        sig1_result.is_ok(),
        "first federation signature should succeed"
    );
    assert!(
        sig2_result.is_ok(),
        "second federation signature should succeed"
    );
    let Ok(sig1) = sig1_result else {
        return;
    };
    let Ok(sig2) = sig2_result else {
        return;
    };
    assert_ne!(sig1, sig2, "ECDSA signatures should use random nonce");
}

#[test]
fn federation_alg_is_es256() {
    let km = InMemoryKeyManager::new();
    assert_eq!(FederationKeyManager::federation_alg(&km), "ES256");
}

#[test]
fn federation_sign_verify_roundtrip() {
    let km = InMemoryKeyManager::new();
    let msg = b"header.payload";
    let signature_result = FederationKeyManager::sign_federation(&km, msg);
    assert!(
        signature_result.is_ok(),
        "federation signing should succeed for roundtrip verification"
    );
    let Ok(sig) = signature_result else {
        return;
    };

    let federation_jwk = FederationKeyManager::federation_public_jwk(&km);
    assert!(
        federation_jwk.is_some(),
        "federation public JWK should be available for roundtrip verification"
    );
    let Some(jwk) = federation_jwk else {
        return;
    };
    let x_value = jwk["x"].as_str();
    let y_value = jwk["y"].as_str();
    assert!(x_value.is_some(), "x coordinate should be present");
    assert!(y_value.is_some(), "y coordinate should be present");
    let Some(x_value) = x_value else {
        return;
    };
    let Some(y_value) = y_value else {
        return;
    };
    let x_result = URL_SAFE_NO_PAD.decode(x_value);
    let y_result = URL_SAFE_NO_PAD.decode(y_value);
    assert!(x_result.is_ok(), "x coordinate should be base64url encoded");
    assert!(y_result.is_ok(), "y coordinate should be base64url encoded");
    let Ok(x) = x_result else {
        return;
    };
    let Ok(y) = y_result else {
        return;
    };
    let mut pub_key = Vec::with_capacity(65);
    pub_key.push(0x04);
    pub_key.extend_from_slice(&x);
    pub_key.extend_from_slice(&y);

    let verify_result = aegaeon_crypto::signature::verify_ecdsa_p256_fixed(&pub_key, msg, &sig);
    assert!(
        verify_result.is_ok(),
        "federation signature should verify against the published JWK"
    );
}

#[test]
fn public_jwt_key_manager_publishes_eddsa_jwk() -> TestResult {
    let km = must_ok!(InMemoryPublicJwtKeyManager::new(), "public JWT key manager",);
    let jwk = must_some!(km.jwt_signing_public_jwk(), "public JWT JWK");

    assert_eq!(km.jwt_signing_alg(), "EdDSA");
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["alg"], "EdDSA");
    assert!(jwk["x"].as_str().is_some_and(|value| !value.is_empty()));
    assert_eq!(jwk["kid"].as_str(), Some(km.key_id().as_str()));
    Ok(())
}

#[test]
fn public_jwt_key_manager_signs_and_verifies() -> TestResult {
    let km = must_ok!(InMemoryPublicJwtKeyManager::new(), "public JWT key manager",);
    let message = b"jwt signing input";
    let signature = must_ok!(km.sign(message), "sign");

    assert!(must_ok!(km.verify(message, &signature), "verify"));
    assert!(!must_ok!(km.verify(b"different", &signature), "verify"));
    Ok(())
}

fn managed_eddsa_runtime_key(
    kid: &str,
    status: RuntimeKeyStatus,
    encrypted_key_handle: String,
    key_data: &aegaeon_crypto::signing::Ed25519KeyData,
) -> RuntimeKey {
    RuntimeKey {
        environment_id: managed_runtime_key_environment_id(),
        usage: RuntimeKeyUsage::JwtAccessTokenSigning,
        algorithm: RuntimeKeyAlgorithm::EdDsa,
        provider: RuntimeKeyProvider::DatabaseEncrypted,
        status,
        retiring_expires_at_epoch_secs: (status == RuntimeKeyStatus::Retiring)
            .then_some(4_102_444_800),
        kid: kid.to_string(),
        public_jwk: crate::jwk_types::Jwk {
            kty: "OKP".to_string(),
            use_: Some("sig".to_string()),
            kid: kid.to_string(),
            alg: Some("EdDSA".to_string()),
            n: None,
            e: None,
            x: Some(URL_SAFE_NO_PAD.encode(&key_data.public_key)),
            y: None,
            crv: Some("Ed25519".to_string()),
        },
        key_handle: encrypted_key_handle,
        provider_configuration: json!({}),
    }
}

#[test]
fn managed_jwt_key_manager_signs_active_and_verifies_retiring_keys() -> TestResult {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|err| format!("key encryption env guard: {err}"))?;
    let kek = [0x44u8; 32];
    let _env = EnvVarGuard::new(
        crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
        Some(&URL_SAFE_NO_PAD.encode(kek)),
    );
    let active_key = must_ok!(
        aegaeon_crypto::signing::Ed25519SigningKey::generate(),
        "active Ed25519 key",
    );
    let retiring_key = must_ok!(
        aegaeon_crypto::signing::Ed25519SigningKey::generate(),
        "retiring Ed25519 key",
    );
    let expired_key = must_ok!(
        aegaeon_crypto::signing::Ed25519SigningKey::generate(),
        "expired retiring Ed25519 key",
    );
    let active_handle = must_ok!(
        encrypt_runtime_key_pkcs8_handle(
            &active_key.pkcs8,
            &kek,
            RuntimeKeyUsage::JwtAccessTokenSigning,
            RuntimeKeyAlgorithm::EdDsa,
            "jwt-active",
        ),
        "encrypt active key",
    );
    let retiring_handle = must_ok!(
        encrypt_runtime_key_pkcs8_handle(
            &retiring_key.pkcs8,
            &kek,
            RuntimeKeyUsage::JwtAccessTokenSigning,
            RuntimeKeyAlgorithm::EdDsa,
            "jwt-retiring",
        ),
        "encrypt retiring key",
    );
    let expired_handle = must_ok!(
        encrypt_runtime_key_pkcs8_handle(
            &expired_key.pkcs8,
            &kek,
            RuntimeKeyUsage::JwtAccessTokenSigning,
            RuntimeKeyAlgorithm::EdDsa,
            "jwt-expired",
        ),
        "encrypt expired retiring key",
    );
    let mut expired_runtime_key = managed_eddsa_runtime_key(
        "jwt-expired",
        RuntimeKeyStatus::Retiring,
        expired_handle,
        &expired_key,
    );
    expired_runtime_key.retiring_expires_at_epoch_secs = Some(0);
    let runtime_keys = must_ok!(
        RuntimeKeySet::try_new(vec![
            managed_eddsa_runtime_key(
                "jwt-active",
                RuntimeKeyStatus::Active,
                active_handle,
                &active_key,
            ),
            managed_eddsa_runtime_key(
                "jwt-retiring",
                RuntimeKeyStatus::Retiring,
                retiring_handle,
                &retiring_key,
            ),
            expired_runtime_key,
        ]),
        "runtime key set",
    );
    let manager = must_ok!(
        ManagedJwtKeyManager::try_from_runtime_keys(
            &runtime_keys,
            RuntimeKeyUsage::JwtAccessTokenSigning,
        ),
        "managed JWT key manager",
    );

    let message = b"header.payload";
    let active_signature = must_ok!(manager.sign(message), "active sign");
    let retiring_signer = must_ok!(
        aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(&retiring_key.pkcs8),
        "retiring signer",
    );
    let retiring_signature = must_ok!(retiring_signer.sign(message), "retiring sign");
    let expired_signer = must_ok!(
        aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(&expired_key.pkcs8),
        "expired retiring signer",
    );
    let expired_signature = must_ok!(expired_signer.sign(message), "expired retiring sign");

    assert_eq!(manager.key_id(), "jwt-active");
    assert_eq!(manager.jwt_signing_alg(), "EdDSA");
    assert_eq!(manager.jwt_signing_public_jwks().len(), 2);
    assert!(must_ok!(
        manager.verify_jwt_signature("jwt-active", "EdDSA", message, &active_signature),
        "verify active",
    ));
    assert!(must_ok!(
        manager.verify_jwt_signature("jwt-retiring", "EdDSA", message, &retiring_signature),
        "verify retiring",
    ));
    assert!(!must_ok!(
        manager.verify_jwt_signature("jwt-expired", "EdDSA", message, &expired_signature),
        "reject expired retiring",
    ));
    assert!(!must_ok!(
        manager.verify_jwt_signature("jwt-retiring", "EdDSA", b"different", &retiring_signature),
        "reject tampered",
    ));
    Ok(())
}

#[test]
fn managed_jwt_key_manager_rejects_public_jwk_mismatch() -> TestResult {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|err| format!("key encryption env guard: {err}"))?;
    let kek = [0x46u8; 32];
    let _env = EnvVarGuard::new(
        crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
        Some(&URL_SAFE_NO_PAD.encode(kek)),
    );
    let key_data = must_ok!(
        aegaeon_crypto::signing::Ed25519SigningKey::generate(),
        "Ed25519 key",
    );
    let key_handle = must_ok!(
        encrypt_runtime_key_pkcs8_handle(
            &key_data.pkcs8,
            &kek,
            RuntimeKeyUsage::JwtAccessTokenSigning,
            RuntimeKeyAlgorithm::EdDsa,
            "jwt-mismatch",
        ),
        "encrypt JWT key",
    );
    let mut runtime_key = managed_eddsa_runtime_key(
        "jwt-mismatch",
        RuntimeKeyStatus::Active,
        key_handle,
        &key_data,
    );
    runtime_key.public_jwk.x = Some(URL_SAFE_NO_PAD.encode([0xa5u8; 32]));
    let runtime_keys = must_ok!(
        RuntimeKeySet::try_new(vec![runtime_key]),
        "shape-valid runtime key set",
    );

    assert!(matches!(
        ManagedJwtKeyManager::try_from_runtime_keys(
            &runtime_keys,
            RuntimeKeyUsage::JwtAccessTokenSigning,
        ),
        Err(KeyManagerError::OperationFailed)
    ));
    Ok(())
}

#[test]
fn hmac_sign_still_works() {
    let km = InMemoryKeyManager::new();
    let sign_result = km.sign(b"test");
    assert!(sign_result.is_ok(), "HMAC sign should succeed");
    let Ok(sig) = sign_result else {
        return;
    };
    assert_eq!(sig.len(), 32);
    let verify_result = km.verify(b"test", &sig);
    assert!(matches!(verify_result, Ok(true)));
}
