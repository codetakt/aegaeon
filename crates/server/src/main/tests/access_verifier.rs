//! Exercise the production startup constructors for each JWT capability combination.
use super::*;
use aegaeon_server::authcode::types::AccessToken;
use aegaeon_server::config::RuntimeStateNamespace;
use aegaeon_server::runtime_keys::{
    RuntimeKey, RuntimeKeyAlgorithm, RuntimeKeyProvider, RuntimeKeySet, RuntimeKeyStatus,
    RuntimeKeyUsage,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;

fn runtime_key(
    kid: &str,
    usage: RuntimeKeyUsage,
    status: RuntimeKeyStatus,
    kek: &[u8; 32],
) -> Result<(RuntimeKey, aegaeon_crypto::signing::Ed25519SigningKey), Box<dyn StdError>> {
    let data = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let signer = aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(&data.pkcs8)?;
    let environment_id = uuid::Uuid::new_v4();
    let context = aegaeon_server::key_encryption::KeyHandleEncryptionContext::new(
        environment_id,
        usage.as_db_str(),
        RuntimeKeyProvider::DatabaseEncrypted.as_db_str(),
        "EdDSA",
        kid,
    );
    let handle = if status == RuntimeKeyStatus::Active {
        aegaeon_server::key_encryption::encrypt_key_handle(
            &URL_SAFE_NO_PAD.encode(&data.pkcs8),
            kek,
            context,
        )?
    } else {
        format!(
            "{}{}",
            aegaeon_server::key_encryption::KEY_HANDLE_ENVELOPE_PREFIX,
            URL_SAFE_NO_PAD.encode([0u8; 28])
        )
    };
    Ok((
        RuntimeKey {
            environment_id,
            usage,
            algorithm: RuntimeKeyAlgorithm::EdDsa,
            provider: RuntimeKeyProvider::DatabaseEncrypted,
            status,
            retiring_expires_at_epoch_secs: (status == RuntimeKeyStatus::Retiring)
                .then_some(4_102_444_800),
            kid: kid.into(),
            public_jwk: serde_json::from_value(
                json!({"kid":kid,"kty":"OKP","use":"sig","alg":"EdDSA","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(data.public_key)}),
            )?,
            key_handle: handle,
            provider_configuration: json!({}),
        },
        signer,
    ))
}

fn token(
    kid: &str,
    signer: &aegaeon_crypto::signing::Ed25519SigningKey,
) -> Result<AccessToken, Box<dyn StdError>> {
    let now = aegaeon_server::util::now_unix_epoch_secs()?;
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"typ":"at+jwt","alg":"EdDSA","kid":kid}))?), URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":"https://issuer.example","sub":"subject","aud":"resource","exp":now+300,"iat":now,"jti":"id"}))?));
    let mut access = AccessToken::new("owner".into(), "subject".into(), None, 300);
    access.token = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signer.sign(input.as_bytes())?)
    );
    Ok(access)
}

#[test]
fn startup_access_verifier_is_independent_of_issuance_and_response_flags() -> TestResult {
    let _lock = env_lock()?;
    // These constructors create lazy Redis clients; this test performs no store I/O.
    let _database = EnvVarGuard::new(
        "AEGAEON_DATABASE_URL",
        Some("postgres://aegaeon:test@127.0.0.1/aegaeon_test"),
    );
    let _shared = super::key_managers::set_base_shared_runtime_store_env();
    let baseline = BootstrapConfig::try_from_env()?.into_runtime_baseline();
    let kek = [0x25u8; 32];
    let _kek = EnvVarGuard::new(
        aegaeon_server::key_encryption::KEY_ENCRYPTION_KEY_ENV,
        Some(&URL_SAFE_NO_PAD.encode(kek)),
    );
    let (active, _) = runtime_key(
        "access-active",
        RuntimeKeyUsage::JwtAccessTokenSigning,
        RuntimeKeyStatus::Active,
        &kek,
    )?;
    let (retiring, signer) = runtime_key(
        "access-retiring",
        RuntimeKeyUsage::JwtAccessTokenSigning,
        RuntimeKeyStatus::Retiring,
        &kek,
    )?;
    let (response, response_signer) = runtime_key(
        "response",
        RuntimeKeyUsage::JwtIntrospectionSigning,
        RuntimeKeyStatus::Active,
        &kek,
    )?;
    for access_enabled in [false, true] {
        for response_enabled in [false, true] {
            let mut cfg = baseline.clone();
            cfg.enable_jwt_access_tokens = access_enabled;
            cfg.enable_jwt_introspection = response_enabled;
            let mut keys = vec![retiring.clone()];
            if access_enabled {
                keys.push(active.clone());
            }
            if response_enabled {
                keys.push(response.clone());
            }
            let keys = RuntimeKeySet::try_new(keys)?;
            let (primary, _) = runtime_key_managers(&cfg, &keys)?;
            let namespace = RuntimeStateNamespace::from_environment_id(uuid::Uuid::new_v4());
            let runtime = token_runtime_from_shared_env(
                &cfg,
                primary,
                &keys,
                None,
                None,
                "https://issuer.example",
                &namespace,
            )?;
            runtime
                .validator
                .validate_stored_access_token_jwt(&token("access-retiring", &signer)?, None)?;
            let wrong = runtime
                .validator
                .validate_stored_access_token_jwt(&token("response", &response_signer)?, None)
                .expect_err("response key cannot validate access tokens");
            assert!(!wrong.is_internal());
        }
    }
    let cfg = baseline;
    let keys = RuntimeKeySet::default();
    let (primary, _) = runtime_key_managers(&cfg, &keys)?;
    let namespace = RuntimeStateNamespace::from_environment_id(uuid::Uuid::new_v4());
    let runtime = token_runtime_from_shared_env(
        &cfg,
        primary,
        &keys,
        None,
        None,
        "https://issuer.example",
        &namespace,
    )?;
    assert!(runtime
        .validator
        .validate_stored_access_token_jwt(&token("access-retiring", &signer)?, None)
        .is_err());
    runtime.validator.validate_stored_access_token_jwt(
        &AccessToken::new("owner".into(), "subject".into(), None, 300),
        None,
    )?;
    Ok(())
}
