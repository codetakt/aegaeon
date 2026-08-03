use super::*;

#[test]
fn oidc_config_from_management_snapshot_uses_database_encrypted_signing_key() -> TestResult {
    let _lock = env_lock()?;
    let _kek_guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock()?;
    let kek = [0x7au8; 32];
    let _kek_env = EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode(kek)),
    );
    let parsed = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)?;
    let plaintext_handle = URL_SAFE_NO_PAD.encode(parsed.contents());
    let encrypted_handle = encrypt_managed_oidc_key_handle(
        &plaintext_handle,
        &kek,
        RuntimeKeyProvider::DatabaseEncrypted,
        "managed-oidc-1",
    )?;
    let runtime_key = managed_oidc_signing_runtime_key("managed-oidc-1", encrypted_handle)?;
    let runtime_keys = RuntimeKeySet::try_new(vec![runtime_key])?;

    let config = OidcConfig::from_management_snapshot(
        "https://issuer.example",
        &oidc_policy(true),
        &runtime_keys,
    )?
    .ok_or_else(|| io::Error::other("OIDC config missing"))?;

    assert_eq!(config.signing_key.kid(), "managed-oidc-1");
    assert_eq!(config.jwks().keys[0].kid, "managed-oidc-1");
    Ok(())
}

#[test]
fn oidc_config_from_management_snapshot_rejects_public_jwk_mismatch() -> TestResult {
    let _lock = env_lock()?;
    let _kek_guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock()?;
    let kek = [0x7cu8; 32];
    let _kek_env = EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode(kek)),
    );
    let parsed = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)?;
    let plaintext_handle = URL_SAFE_NO_PAD.encode(parsed.contents());
    let encrypted_handle = encrypt_managed_oidc_key_handle(
        &plaintext_handle,
        &kek,
        RuntimeKeyProvider::DatabaseEncrypted,
        "managed-oidc-mismatch",
    )?;
    let mut runtime_key =
        managed_oidc_signing_runtime_key("managed-oidc-mismatch", encrypted_handle)?;
    runtime_key.public_jwk.n = Some(URL_SAFE_NO_PAD.encode([0x55u8; 256]));
    let runtime_keys = RuntimeKeySet::try_new(vec![runtime_key])?;

    let err = require_err(
        OidcConfig::from_management_snapshot(
            "https://issuer.example",
            &oidc_policy(true),
            &runtime_keys,
        ),
        "OIDC managed signing key must reject mismatched public JWK",
    )?;

    assert!(matches!(
        err,
        OidcConfigError::ManagedPublicJwkMismatch(kid)
            if kid == "managed-oidc-mismatch"
    ));
    Ok(())
}

#[test]
fn oidc_config_from_management_snapshot_omits_expired_retiring_signing_keys() -> TestResult {
    let _lock = env_lock()?;
    let _kek_guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock()?;
    let kek = [0x7du8; 32];
    let _kek_env = EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode(kek)),
    );
    let parsed = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)?;
    let plaintext_handle = URL_SAFE_NO_PAD.encode(parsed.contents());
    let active_key = managed_oidc_signing_runtime_key(
        "managed-oidc-active",
        encrypt_managed_oidc_key_handle(
            &plaintext_handle,
            &kek,
            RuntimeKeyProvider::DatabaseEncrypted,
            "managed-oidc-active",
        )?,
    )?;
    let mut retiring_key = managed_oidc_signing_runtime_key(
        "managed-oidc-retiring",
        encrypt_managed_oidc_key_handle(
            &plaintext_handle,
            &kek,
            RuntimeKeyProvider::DatabaseEncrypted,
            "managed-oidc-retiring",
        )?,
    )?;
    retiring_key.status = crate::runtime_keys::RuntimeKeyStatus::Retiring;
    retiring_key.retiring_expires_at_epoch_secs = Some(4_102_444_800);
    let mut expired_key = managed_oidc_signing_runtime_key(
        "managed-oidc-expired",
        encrypt_managed_oidc_key_handle(
            &plaintext_handle,
            &kek,
            RuntimeKeyProvider::DatabaseEncrypted,
            "managed-oidc-expired",
        )?,
    )?;
    expired_key.status = crate::runtime_keys::RuntimeKeyStatus::Retiring;
    expired_key.retiring_expires_at_epoch_secs = Some(0);
    let runtime_keys = RuntimeKeySet::try_new(vec![active_key, retiring_key, expired_key])?;

    let config = OidcConfig::from_management_snapshot(
        "https://issuer.example",
        &oidc_policy(true),
        &runtime_keys,
    )?
    .ok_or_else(|| io::Error::other("OIDC config missing"))?;
    let kids = config
        .jwks()
        .keys
        .into_iter()
        .map(|jwk| jwk.kid)
        .collect::<Vec<_>>();

    assert_eq!(
        kids,
        vec![
            "managed-oidc-active".to_string(),
            "managed-oidc-retiring".to_string(),
        ]
    );
    Ok(())
}

#[test]
fn oidc_config_from_management_snapshot_ignores_startup_environment_policy() -> TestResult {
    let _lock = env_lock()?;
    let _kek_guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD.lock()?;
    let kek = [0x7bu8; 32];
    let _kek_env = EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode(kek)),
    );
    let _enabled = EnvVarGuard::new("AEGAEON_OIDC_ENABLED", Some("0"));
    let _ttl = EnvVarGuard::new("AEGAEON_OIDC_ID_TOKEN_TTL", Some("not-a-number"));
    let _signing = EnvVarGuard::new("AEGAEON_OIDC_SIGNING_KEY_PEM", Some("not a pem"));
    let _additional = EnvVarGuard::new("AEGAEON_OIDC_JWKS_ADDITIONAL", Some("{"));
    let parsed = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)?;
    let plaintext_handle = URL_SAFE_NO_PAD.encode(parsed.contents());
    let encrypted_handle = encrypt_managed_oidc_key_handle(
        &plaintext_handle,
        &kek,
        RuntimeKeyProvider::DatabaseEncrypted,
        "managed-oidc-2",
    )?;
    let runtime_key = managed_oidc_signing_runtime_key("managed-oidc-2", encrypted_handle)?;
    let runtime_keys = RuntimeKeySet::try_new(vec![runtime_key])?;

    let config = OidcConfig::from_management_snapshot(
        "https://issuer.example",
        &oidc_policy(true),
        &runtime_keys,
    )?
    .ok_or_else(|| io::Error::other("OIDC config missing"))?;

    assert_eq!(config.signing_key.kid(), "managed-oidc-2");
    assert_eq!(config.id_token_ttl_secs, 3600);
    Ok(())
}

#[test]
fn oidc_config_from_management_snapshot_requires_active_managed_signing_key() -> TestResult {
    let err = require_err(
        OidcConfig::from_management_snapshot(
            "https://issuer.example",
            &oidc_policy(true),
            &RuntimeKeySet::default(),
        ),
        "OIDC enabled management snapshot must require a signing key",
    )?;

    assert!(matches!(
        err,
        OidcConfigError::ManagedKeyMissing("OIDC ID Token signing")
    ));
    Ok(())
}
