use super::*;
use aegaeon_jose::{verify_compact_with_context, JoseContext, VerificationKey};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

type KmsTestResult<T = ()> = anyhow::Result<T>;

struct OidcAwsKmsTestConfig {
    region: String,
    key_id: String,
    kid: String,
}

fn localstack_kms_available() -> bool {
    std::net::TcpStream::connect("127.0.0.1:4566").is_ok()
}

fn localstack_kms_required() -> bool {
    std::env::var("AEG_KMS_REQUIRE_LOCALSTACK")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn configure_localstack_aws_env() -> Vec<EnvVarGuard> {
    vec![
        EnvVarGuard::new("AWS_ACCESS_KEY_ID", Some("test")),
        EnvVarGuard::new("AWS_SECRET_ACCESS_KEY", Some("test")),
        EnvVarGuard::new("AWS_REGION", Some("us-east-1")),
        EnvVarGuard::new("AWS_ENDPOINT_URL", Some("http://localhost:4566")),
    ]
}

fn create_localstack_rsa_signing_key() -> KmsTestResult<String> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use aws_sdk_kms::types::{KeySpec, KeyUsageType};

        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let client = aws_sdk_kms::Client::new(&config);
        let resp = client
            .create_key()
            .key_usage(KeyUsageType::SignVerify)
            .key_spec(KeySpec::Rsa2048)
            .send()
            .await?;
        resp.key_metadata
            .ok_or_else(|| anyhow::anyhow!("create_key response did not include key metadata"))
            .map(|metadata| metadata.key_id)
    })
}

fn oidc_aws_kms_test_config_from_env() -> KmsTestResult<Option<OidcAwsKmsTestConfig>> {
    let Some(key_id) = std::env::var("AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    let region = std::env::var("AEGAEON_OIDC_SIGNING_AWS_REGION")
        .or_else(|_| std::env::var("AWS_REGION"))
        .map_err(|_| {
            anyhow::anyhow!(
                "AEGAEON_OIDC_SIGNING_AWS_REGION or AWS_REGION is required for real AWS KMS parity"
            )
        })?
        .trim()
        .to_string();
    if region.is_empty() {
        anyhow::bail!("AEGAEON_OIDC_SIGNING_AWS_REGION or AWS_REGION must be non-empty");
    }

    let kid = std::env::var("AEGAEON_OIDC_SIGNING_KID")
        .map(|value| value.trim().to_string())
        .map_err(|_| {
            anyhow::anyhow!("AEGAEON_OIDC_SIGNING_KID is required for real AWS KMS parity")
        })?;
    if kid.is_empty() {
        anyhow::bail!("AEGAEON_OIDC_SIGNING_KID must be non-empty");
    }

    Ok(Some(OidcAwsKmsTestConfig {
        region,
        key_id,
        kid,
    }))
}

fn sample_id_token_claims() -> KmsTestResult<crate::oidc::IdTokenClaims> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    Ok(crate::oidc::IdTokenClaims {
        iss: "https://issuer.example".to_string(),
        sub: "subject-123".to_string(),
        aud: crate::oidc::Audience::Single("client-123".to_string()),
        exp: now + 600,
        iat: now,
        auth_time: None,
        nonce: Some("nonce-123".to_string()),
        acr: None,
        amr: None,
        azp: None,
        sid: Some("sid-123".to_string()),
        at_hash: None,
        c_hash: None,
        nbf: None,
        jti: Some("jti-123".to_string()),
        additional_claims: Default::default(),
    })
}

fn rsa_components_from_signing_key(
    signing_key: &OidcSigningKey,
) -> KmsTestResult<(Vec<u8>, Vec<u8>)> {
    let jwks = signing_key.jwks();
    let jwk = jwks
        .keys
        .first()
        .ok_or_else(|| anyhow::anyhow!("signing key did not expose a public JWK"))?;
    let modulus = URL_SAFE_NO_PAD.decode(
        jwk.n
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("public JWK is missing RSA modulus"))?,
    )?;
    let exponent = URL_SAFE_NO_PAD.decode(
        jwk.e
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("public JWK is missing RSA exponent"))?,
    )?;
    Ok((modulus, exponent))
}

fn verify_id_token_claims(
    signing_key: &OidcSigningKey,
    token: &str,
) -> KmsTestResult<crate::oidc::IdTokenClaims> {
    let (modulus, exponent) = rsa_components_from_signing_key(signing_key)?;
    let payload = verify_compact_with_context(
        token,
        VerificationKey::RsaPkcs1Sha256 {
            modulus: &modulus,
            exponent: &exponent,
        },
        &JoseContext::default(),
    )?;

    Ok(serde_json::from_slice(&payload)?)
}

fn kms_runtime_key_from_authoritative_provider(
    config: &OidcAwsKmsTestConfig,
    kek: &[u8; 32],
) -> KmsTestResult<RuntimeKey> {
    let provider_checked_key = OidcSigningKey::from_aws_kms(
        config.region.clone(),
        config.key_id.clone(),
        config.kid.clone(),
    )?;
    let public_jwk = provider_checked_key
        .jwks()
        .keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("AWS KMS signer did not expose a public JWK"))?;
    let key_handle = encrypt_managed_oidc_key_handle(
        &config.key_id,
        kek,
        RuntimeKeyProvider::AwsKms,
        &config.kid,
    )?;

    Ok(RuntimeKey {
        environment_id: managed_oidc_runtime_key_environment_id(),
        usage: RuntimeKeyUsage::OidcIdTokenSigning,
        algorithm: RuntimeKeyAlgorithm::Rs256,
        provider: RuntimeKeyProvider::AwsKms,
        status: crate::runtime_keys::RuntimeKeyStatus::Active,
        retiring_expires_at_epoch_secs: None,
        kid: config.kid.clone(),
        public_jwk,
        key_handle,
        provider_configuration: serde_json::json!({ "region": config.region }),
    })
}

fn local_runtime_key_from_managed_private_key(
    kid: &str,
    kek: &[u8; 32],
) -> KmsTestResult<RuntimeKey> {
    let parsed = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)?;
    let plaintext_handle = URL_SAFE_NO_PAD.encode(parsed.contents());
    let encrypted_handle = encrypt_managed_oidc_key_handle(
        &plaintext_handle,
        kek,
        RuntimeKeyProvider::DatabaseEncrypted,
        kid,
    )?;
    Ok(managed_oidc_signing_runtime_key(kid, encrypted_handle)?)
}

fn oidc_config_from_runtime_key(runtime_key: RuntimeKey) -> KmsTestResult<OidcConfig> {
    let runtime_keys = RuntimeKeySet::try_new(vec![runtime_key])?;
    OidcConfig::from_management_snapshot(
        "https://issuer.example",
        &oidc_policy(true),
        &runtime_keys,
    )?
    .ok_or_else(|| anyhow::anyhow!("OIDC config missing"))
}

#[test]
fn test_oidc_aws_kms_runtime_key_material_issues_verifiable_rs256_jwt() -> KmsTestResult {
    let _env_lock = env_lock()?;
    let _kek_lock = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|err| io::Error::other(err.to_string()))?;
    let mut _localstack_env = Vec::new();
    let test_config = if let Some(config) = oidc_aws_kms_test_config_from_env()? {
        config
    } else {
        if !localstack_kms_available() {
            if localstack_kms_required() {
                anyhow::bail!(
                    "LocalStack is required for OIDC AWS KMS parity evidence but is not available on 127.0.0.1:4566"
                );
            }
            println!("LocalStack not available, skipping OIDC AWS KMS signing test");
            return Ok(());
        }

        _localstack_env = configure_localstack_aws_env();
        OidcAwsKmsTestConfig {
            region: "us-east-1".to_string(),
            key_id: create_localstack_rsa_signing_key()?,
            kid: "oidc-kms-test-1".to_string(),
        }
    };

    let kek = [0x42u8; 32];
    let _kek_env = EnvVarGuard::new(
        crate::key_encryption::KEY_ENCRYPTION_KEY_ENV,
        Some(&URL_SAFE_NO_PAD.encode(kek)),
    );
    let kms_config = oidc_config_from_runtime_key(kms_runtime_key_from_authoritative_provider(
        &test_config,
        &kek,
    )?)?;
    let local_config = oidc_config_from_runtime_key(local_runtime_key_from_managed_private_key(
        "oidc-local-test-1",
        &kek,
    )?)?;
    let claims = sample_id_token_claims()?;

    let kms_token = kms_config.signing_key.sign_rs256_jwt(&claims)?;
    let local_token = local_config.signing_key.sign_rs256_jwt(&claims)?;

    let kms_header = jsonwebtoken::decode_header(&kms_token)?;
    let local_header = jsonwebtoken::decode_header(&local_token)?;
    assert_eq!(kms_header.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(local_header.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(kms_header.typ.as_deref(), Some("JWT"));
    assert_eq!(local_header.typ.as_deref(), Some("JWT"));
    assert_eq!(kms_header.kid.as_deref(), Some(test_config.kid.as_str()));
    assert_eq!(local_header.kid.as_deref(), Some("oidc-local-test-1"));

    let kms_verified = verify_id_token_claims(&kms_config.signing_key, &kms_token)?;
    let local_verified = verify_id_token_claims(&local_config.signing_key, &local_token)?;
    assert_eq!(kms_verified.iss, claims.iss);
    assert_eq!(kms_verified.sub, claims.sub);
    assert_eq!(local_verified.iss, claims.iss);
    assert_eq!(local_verified.sub, claims.sub);
    assert_eq!(
        kms_config
            .signing_key
            .jwks()
            .keys
            .first()
            .and_then(|jwk| jwk.alg.as_deref()),
        Some("RS256")
    );
    assert_eq!(
        local_config
            .signing_key
            .jwks()
            .keys
            .first()
            .and_then(|jwk| jwk.alg.as_deref()),
        Some("RS256")
    );
    Ok(())
}
