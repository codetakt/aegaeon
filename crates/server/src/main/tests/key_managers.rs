use super::*;
use aegaeon_server::runtime_keys::RuntimeKeySet;

const TEST_DATABASE_URL: &str = "postgres://aegaeon:test@127.0.0.1/aegaeon_test";
const TEST_REDIS_URL: &str = "redis://127.0.0.1:6379/0";

fn set_base_shared_runtime_store_env() -> Vec<EnvVarGuard> {
    [
        "AEGAEON_AUTH_CODE_REDIS_URL",
        "AEGAEON_AUTH_SESSION_REDIS_URL",
        "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
        "AEGAEON_DEVICE_CODE_REDIS_URL",
        "AEGAEON_DEVICE_CSRF_REDIS_URL",
        "AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL",
        "AEGAEON_DPOP_NONCE_REDIS_URL",
        "AEGAEON_DPOP_REDIS_URL",
        "AEGAEON_JWKS_REDIS_URL",
        "AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL",
        "AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL",
        "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
        "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        "AEGAEON_PAR_REDIS_URL",
        "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
        "AEGAEON_STEPUP_REDIS_URL",
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        "AEGAEON_UPSTREAM_AUTH_REDIS_URL",
        "AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL",
    ]
    .into_iter()
    .map(|key| EnvVarGuard::new(key, Some(TEST_REDIS_URL)))
    .collect()
}

#[test]
fn disabled_key_manager_fails_closed_without_runtime_key_material() {
    let manager = DisabledKeyManager;

    assert!(matches!(
        manager.sign(b"message"),
        Err(KeyManagerError::KeyNotFound)
    ));
    assert!(matches!(
        manager.verify(b"message", b"signature"),
        Err(KeyManagerError::KeyNotFound)
    ));
    assert!(manager.jwt_signing_public_jwk().is_none());
}

#[test]
fn disabled_key_managers_are_used_for_disabled_runtime_surfaces() -> TestResult {
    let _lock = env_lock()?;
    let _database_url = EnvVarGuard::new("AEGAEON_DATABASE_URL", Some(TEST_DATABASE_URL));
    let _shared_runtime_stores = set_base_shared_runtime_store_env();
    let cfg = BootstrapConfig::try_from_env()?.into_runtime_baseline();
    let runtime_keys = RuntimeKeySet::default();

    let (key_manager, introspection_key_manager) = runtime_key_managers(&cfg, &runtime_keys)?;
    assert!(introspection_key_manager.is_none());
    assert!(matches!(
        key_manager.sign(b"message"),
        Err(KeyManagerError::KeyNotFound)
    ));
    Ok(())
}

#[test]
fn introspection_startup_selects_legacy_eddsa_with_dual_slots() -> TestResult {
    use aegaeon_server::runtime_keys::{
        RuntimeKey, RuntimeKeyAlgorithm as Alg, RuntimeKeyProvider, RuntimeKeyStatus,
        RuntimeKeyUsage as Usage,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let _lock = env_lock()?;
    let _database = EnvVarGuard::new("AEGAEON_DATABASE_URL", Some(TEST_DATABASE_URL));
    let _stores = set_base_shared_runtime_store_env();
    let kek = [0x32; 32];
    let _kek = EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode(kek)),
    );
    let mut cfg = BootstrapConfig::try_from_env()?.into_runtime_baseline();
    let mut policy = aegaeon_server::management::types::PolicyDocument {
        jwt_introspection_enabled: true,
        jwt_access_tokens_enabled: false,
        ..Default::default()
    };
    cfg.apply_management_policy(&policy)?;
    let output = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .output()?;
    if !output.status.success() {
        return Err("fixture generation".into());
    }
    let der = pem::parse(output.stdout)?.into_contents();
    use ring::signature::KeyPair as _;
    let primitive = ring::signature::RsaKeyPair::from_pkcs8(&der).map_err(|_| "fixture key")?;
    let public_blocks = simple_asn1::from_der(primitive.public_key().as_ref())?;
    let [simple_asn1::ASN1Block::Sequence(_, fields)] = public_blocks.as_slice() else {
        return Err("fixture public key".into());
    };
    let [simple_asn1::ASN1Block::Integer(_, n), simple_asn1::ASN1Block::Integer(_, e)] =
        fields.as_slice()
    else {
        return Err("fixture public components".into());
    };
    let public = aegaeon_server::jwk_types::Jwk {
        kty: "RSA".into(),
        use_: Some("sig".into()),
        kid: "rsa".into(),
        alg: Some("RS256".into()),
        n: Some(URL_SAFE_NO_PAD.encode(n.to_biguint().ok_or("n")?.to_bytes_be())),
        e: Some(URL_SAFE_NO_PAD.encode(e.to_biguint().ok_or("e")?.to_bytes_be())),
        x: None,
        y: None,
        crv: None,
    };
    let mut rsa = RuntimeKey {
        environment_id: uuid::Uuid::from_u128(432),
        usage: Usage::JwtIntrospectionSigning,
        algorithm: Alg::Rs256,
        provider: RuntimeKeyProvider::DatabaseEncrypted,
        status: RuntimeKeyStatus::Active,
        retiring_expires_at_epoch_secs: None,
        kid: "rsa".into(),
        public_jwk: public,
        key_handle: String::new(),
        provider_configuration: serde_json::json!({}),
    };
    rsa.key_handle = aegaeon_server::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(der),
        &kek,
        rsa.key_handle_encryption_context(),
    )?;
    let ed = aegaeon_crypto::signing::Ed25519SigningKey::generate().map_err(|_| "fixture")?;
    let mut edkey = rsa.clone();
    edkey.algorithm = Alg::EdDsa;
    edkey.kid = "ed".into();
    edkey.public_jwk = aegaeon_server::jwk_types::Jwk {
        kty: "OKP".into(),
        use_: Some("sig".into()),
        kid: "ed".into(),
        alg: Some("EdDSA".into()),
        n: None,
        e: None,
        x: Some(URL_SAFE_NO_PAD.encode(ed.public_key)),
        y: None,
        crv: Some("Ed25519".into()),
    };
    edkey.key_handle = aegaeon_server::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(ed.pkcs8),
        &kek,
        edkey.key_handle_encryption_context(),
    )?;
    for keys in [vec![edkey.clone()], vec![rsa.clone(), edkey]] {
        let (manager, secondary) = runtime_key_managers(&cfg, &RuntimeKeySet::try_new(keys)?)?;
        assert!(secondary.is_none());
        assert_eq!(manager.jwt_signing_alg(), "EdDSA");
        assert_eq!(manager.key_id(), "ed");
    }
    let rsa_only = RuntimeKeySet::try_new(vec![rsa])?;
    assert!(runtime_key_managers(&cfg, &rsa_only).is_err());
    policy.jwt_introspection_enabled = false;
    cfg.apply_management_policy(&policy)?;
    assert!(runtime_key_managers(&cfg, &rsa_only).is_ok());
    Ok(())
}
