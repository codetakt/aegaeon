use super::*;
use crate::kms::{InMemoryPublicJwtKeyManager, KeyManager};
use crate::runtime_keys::{RuntimeKey, RuntimeKeyAlgorithm, RuntimeKeyProvider, RuntimeKeyStatus};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn key(
    manager: &dyn KeyManager,
    status: RuntimeKeyStatus,
) -> Result<RuntimeKey, Box<dyn std::error::Error>> {
    Ok(RuntimeKey {
        environment_id: uuid::Uuid::new_v4(),
        usage: RuntimeKeyUsage::JwtAccessTokenSigning,
        algorithm: RuntimeKeyAlgorithm::EdDsa,
        provider: RuntimeKeyProvider::DatabaseEncrypted,
        status,
        retiring_expires_at_epoch_secs: (status == RuntimeKeyStatus::Retiring).then_some(100),
        kid: manager.key_id(),
        public_jwk: serde_json::from_value(manager.jwt_signing_public_jwk().ok_or("public key")?)?,
        // Shape-valid but undecryptable handle proves public verification never decrypts it.
        key_handle: format!(
            "{}{}",
            crate::key_encryption::KEY_HANDLE_ENVELOPE_PREFIX,
            URL_SAFE_NO_PAD.encode([0u8; 28])
        ),
        provider_configuration: json!({}),
    })
}

#[test]
fn managed_access_verifier_enforces_status_purpose_algorithm_and_exclusive_expiry() -> TestResult {
    let manager = InMemoryPublicJwtKeyManager::new()?;
    let signature = manager.sign(b"message")?;
    for status in [
        RuntimeKeyStatus::Active,
        RuntimeKeyStatus::Retiring,
        RuntimeKeyStatus::Next,
        RuntimeKeyStatus::Revoked,
    ] {
        let keys = RuntimeKeySet::try_new(vec![key(&manager, status)?])?;
        let mut verifier = ManagedAccessTokenVerifier::try_from_runtime_keys(&keys)?;
        verifier.now = || Ok(99);
        assert_eq!(
            verifier.verify_access_token_signature(
                &manager.key_id(),
                "EdDSA",
                b"message",
                &signature
            )?,
            matches!(
                status,
                RuntimeKeyStatus::Active | RuntimeKeyStatus::Retiring
            )
        );
        assert!(!verifier.verify_access_token_signature(
            &manager.key_id(),
            "RS256",
            b"message",
            &signature
        )?);
        assert!(
            !verifier.verify_access_token_signature("unknown", "EdDSA", b"message", &signature)?
        );
        assert!(!verifier.verify_access_token_signature(
            &manager.key_id(),
            "EdDSA",
            b"changed",
            &signature
        )?);
        verifier.now = || Ok(100);
        assert_eq!(
            verifier.verify_access_token_signature(
                &manager.key_id(),
                "EdDSA",
                b"message",
                &signature
            )?,
            status == RuntimeKeyStatus::Active
        );
    }
    let mut wrong = key(&manager, RuntimeKeyStatus::Active)?;
    wrong.usage = RuntimeKeyUsage::JwtIntrospectionSigning;
    let verifier =
        ManagedAccessTokenVerifier::try_from_runtime_keys(&RuntimeKeySet::try_new(vec![wrong])?)?;
    assert!(!verifier.verify_access_token_signature(
        &manager.key_id(),
        "EdDSA",
        b"message",
        &signature
    )?);
    let verifier = ManagedAccessTokenVerifier::try_from_runtime_keys(&RuntimeKeySet::default())?;
    assert!(!verifier.verify_access_token_signature(
        &manager.key_id(),
        "EdDSA",
        b"message",
        &signature
    )?);
    Ok(())
}

#[test]
fn managed_access_verifier_clock_failure_is_operational() -> TestResult {
    let manager = InMemoryPublicJwtKeyManager::new()?;
    let keys = RuntimeKeySet::try_new(vec![key(&manager, RuntimeKeyStatus::Retiring)?])?;
    let mut verifier = ManagedAccessTokenVerifier::try_from_runtime_keys(&keys)?;
    verifier.now = || Err(KeyManagerError::OperationFailed);
    assert!(matches!(
        verifier.verify_access_token_signature(
            &manager.key_id(),
            "EdDSA",
            b"message",
            &manager.sign(b"message")?
        ),
        Err(KeyManagerError::OperationFailed)
    ));
    verifier.now = || Ok(99);
    assert!(verifier.verify_access_token_signature(
        &manager.key_id(),
        "EdDSA",
        b"message",
        &manager.sign(b"message")?
    )?);
    Ok(())
}

#[test]
fn managed_access_verifier_invalid_public_material_fails_initialization() -> TestResult {
    let manager = InMemoryPublicJwtKeyManager::new()?;
    let mut invalid = key(&manager, RuntimeKeyStatus::Active)?;
    invalid.public_jwk.x = Some(URL_SAFE_NO_PAD.encode([0u8; 31]));
    // RuntimeKeySet validates JWK shape; the verification capability decodes key bytes.
    let keys = RuntimeKeySet::try_new(vec![invalid])?;
    assert!(matches!(
        ManagedAccessTokenVerifier::try_from_runtime_keys(&keys),
        Err(KeyManagerError::OperationFailed)
    ));
    Ok(())
}
