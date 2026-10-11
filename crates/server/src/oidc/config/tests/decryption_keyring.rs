use super::*;
use crate::runtime_keys::RuntimeKeyStatus;
const KEK: [u8; 32] = [0x7e; 32];

fn signing() -> Result<RuntimeKey, Box<dyn StdError>> {
    let der = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)?;
    Ok(managed_oidc_signing_runtime_key(
        "signing",
        encrypt_managed_oidc_key_handle(
            &URL_SAFE_NO_PAD.encode(der.contents()),
            &KEK,
            RuntimeKeyProvider::DatabaseEncrypted,
            "signing",
        )?,
    )?)
}

fn encryption(
    kid: &str,
    status: RuntimeKeyStatus,
    deadline: Option<i64>,
) -> Result<RuntimeKey, Box<dyn StdError>> {
    let der = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)?;
    let material = OidcRequestObjectEncryptionKey::from_rsa_pkcs8_der(kid.into(), der.contents())?;
    let key_handle = crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(der.contents()),
        &KEK,
        crate::key_encryption::KeyHandleEncryptionContext::new(
            managed_oidc_runtime_key_environment_id(),
            "OIDC_REQUEST_OBJECT_DECRYPTION",
            "databaseEncrypted",
            "RSA-OAEP+A256GCM",
            kid,
        ),
    )?;
    Ok(RuntimeKey {
        environment_id: managed_oidc_runtime_key_environment_id(),
        usage: RuntimeKeyUsage::OidcRequestObjectDecryption,
        algorithm: RuntimeKeyAlgorithm::RsaOaepA256Gcm,
        provider: RuntimeKeyProvider::DatabaseEncrypted,
        status,
        retiring_expires_at_epoch_secs: deadline,
        kid: kid.into(),
        public_jwk: material.public_jwk().clone(),
        key_handle,
        provider_configuration: serde_json::json!({}),
    })
}

#[test]
fn request_object_decryption_keyring_sync_async_selection_and_publication() -> TestResult {
    let _lock = env_lock()?;
    let _kek_guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock()?;
    let _env = EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode(KEK)),
    );
    let now = crate::util::now_unix_epoch_secs_i64()?;
    let deadline = now + 300;
    let keys = RuntimeKeySet::try_new(vec![
        signing()?,
        encryption("active", RuntimeKeyStatus::Active, None)?,
        encryption("retiring", RuntimeKeyStatus::Retiring, Some(deadline))?,
        encryption("expired", RuntimeKeyStatus::Retiring, Some(now))?,
        encryption("next", RuntimeKeyStatus::Next, None)?,
        encryption("revoked", RuntimeKeyStatus::Revoked, None)?,
    ])?;
    let sync =
        OidcConfig::from_management_snapshot("https://issuer.example", &oidc_policy(true), &keys)?
            .ok_or("config")?;
    let asynchronous = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(OidcConfig::from_management_snapshot_async(
            "https://issuer.example",
            &oidc_policy(true),
            &keys,
        ))?
        .ok_or("config")?;
    for cfg in [sync, asynchronous] {
        let key = cfg.request_object_encryption_key.as_ref().ok_or("key")?;
        assert_eq!(key.kid(), "active");
        assert!(key.select_pkcs8_at(Some("active"), now).is_ok());
        assert!(key.select_pkcs8_at(Some("retiring"), deadline - 1).is_ok());
        assert!(key.select_pkcs8_at(Some("retiring"), deadline).is_err());
        assert!(key.select_pkcs8_at(Some("retiring"), deadline + 1).is_err());
        for kid in [
            None,
            Some(""),
            Some("ACTIVE"),
            Some("unknown"),
            Some("signing"),
            Some("expired"),
            Some("next"),
            Some("revoked"),
        ] {
            assert!(key.select_pkcs8_at(kid, now).is_err());
        }
        let published = cfg.jwks();
        let enc: Vec<_> = published
            .keys
            .iter()
            .filter(|jwk| jwk.use_.as_deref() == Some("enc"))
            .collect();
        assert_eq!(enc.len(), 1);
        assert_eq!(enc[0].kid, "active");
        let debug = format!("{key:?}");
        assert!(!debug.contains(&URL_SAFE_NO_PAD.encode(key.pkcs8_der())));
        assert!(!debug.contains("pkcs8_der"));
    }
    Ok(())
}

#[test]
fn request_object_decryption_keyring_rejects_duplicates_collisions_and_mismatch() -> TestResult {
    let _lock = env_lock()?;
    let _kek_guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock()?;
    let _env = EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode(KEK)),
    );
    let deadline = crate::util::now_unix_epoch_secs_i64()? + 300;
    let active = encryption("active", RuntimeKeyStatus::Active, None)?;
    let duplicate = encryption("active", RuntimeKeyStatus::Retiring, Some(deadline))?;
    let conflict = encryption("signing", RuntimeKeyStatus::Retiring, Some(deadline))?;
    let mut mismatch = encryption("mismatch", RuntimeKeyStatus::Retiring, Some(deadline))?;
    mismatch.public_jwk.n = Some(URL_SAFE_NO_PAD.encode([0x55; 256]));
    for invalid in [duplicate, conflict, mismatch] {
        let keys = RuntimeKeySet::try_new(vec![signing()?, active.clone(), invalid])?;
        assert!(OidcConfig::from_management_snapshot(
            "https://issuer.example",
            &oidc_policy(true),
            &keys
        )
        .is_err());
    }
    // A retiring signing identity also cannot become a private decryption selector.
    let der = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)?;
    let mut retired_signing = managed_oidc_signing_runtime_key(
        "retired-signing",
        encrypt_managed_oidc_key_handle(
            &URL_SAFE_NO_PAD.encode(der.contents()),
            &KEK,
            RuntimeKeyProvider::DatabaseEncrypted,
            "retired-signing",
        )?,
    )?;
    retired_signing.status = RuntimeKeyStatus::Retiring;
    retired_signing.retiring_expires_at_epoch_secs = Some(deadline);
    let keys = RuntimeKeySet::try_new(vec![
        signing()?,
        active,
        retired_signing,
        encryption(
            "retired-signing",
            RuntimeKeyStatus::Retiring,
            Some(deadline),
        )?,
    ])?;
    assert!(OidcConfig::from_management_snapshot(
        "https://issuer.example",
        &oidc_policy(true),
        &keys
    )
    .is_err());
    Ok(())
}

#[test]
fn request_object_decryption_keyring_requires_active_capability() -> TestResult {
    let _lock = env_lock()?;
    let _kek_guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock()?;
    let _env = EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode(KEK)),
    );
    let keys = RuntimeKeySet::try_new(vec![
        signing()?,
        encryption("retiring", RuntimeKeyStatus::Retiring, Some(i64::MAX))?,
    ])?;
    let cfg =
        OidcConfig::from_management_snapshot("https://issuer.example", &oidc_policy(true), &keys)?
            .ok_or("config")?;
    assert!(cfg.request_object_encryption_key.is_none());
    assert_eq!(cfg.jwks().keys.len(), 1);
    Ok(())
}
