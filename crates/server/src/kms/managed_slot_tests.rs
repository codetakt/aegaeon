use super::{KeyManager, ManagedJwtKeyManager};
use crate::runtime_keys::{
    RuntimeKey, RuntimeKeyAlgorithm as Alg, RuntimeKeyProvider, RuntimeKeySet,
    RuntimeKeyStatus as Status, RuntimeKeyUsage as Usage,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

// Only ephemeral test material is generated; private bytes never enter logs or files.
pub(crate) fn rsa_pkcs8(bits: usize) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            &format!("rsa_keygen_bits:{bits}"),
        ])
        .output()?;
    if !output.status.success() {
        return Err("RSA fixture generation failed".into());
    }
    Ok(pem::parse(output.stdout)?.into_contents())
}

pub(crate) fn rsa_key(
    der: &[u8],
    kid: &str,
    status: Status,
) -> std::result::Result<RuntimeKey, Box<dyn std::error::Error>> {
    let signer = super::managed_rsa::ManagedRsaSigningKey::from_pkcs8(der)?;
    let mut key = RuntimeKey {
        environment_id: uuid::Uuid::from_u128(123),
        usage: Usage::JwtIntrospectionSigning,
        algorithm: Alg::Rs256,
        provider: RuntimeKeyProvider::DatabaseEncrypted,
        status,
        retiring_expires_at_epoch_secs: (status == Status::Retiring).then_some(4_102_444_800),
        kid: kid.into(),
        public_jwk: signer.public_jwk(kid)?,
        key_handle: String::new(),
        provider_configuration: serde_json::json!({}),
    };
    key.key_handle = crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(der),
        &[0x73; 32],
        key.key_handle_encryption_context(),
    )?;
    Ok(key)
}

#[test]
fn managed_introspection_rsa_sizes_and_independent_signatures() -> Result {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "env lock")?;
    let _env = super::tests::EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode([0x73; 32])),
    );
    for bits in [2048, 3072, 4096] {
        let key = rsa_key(&rsa_pkcs8(bits)?, "rsa", Status::Active)?;
        let keys = RuntimeKeySet::try_new(vec![key.clone()])?;
        assert!(
            ManagedJwtKeyManager::try_from_runtime_keys(&keys, Usage::JwtIntrospectionSigning)
                .is_err()
        );
        let manager = ManagedJwtKeyManager::try_from_runtime_keys_for_algorithm(
            &keys,
            Usage::JwtIntrospectionSigning,
            Alg::Rs256,
        )?;
        let msg = b"eyJ0eXAiOiJ0b2tlbi1pbnRyb3NwZWN0aW9uK2p3dCJ9.eyJhY3RpdmUiOmZhbHNlfQ";
        let signature = manager.sign(msg)?;
        assert_eq!(signature.len(), bits / 8);
        assert!(manager.verify_jwt_signature("rsa", "RS256", msg, &signature)?);
        assert!(!manager.verify_jwt_signature("rsa", "EdDSA", msg, &signature)?);
        assert!(!manager.verify_jwt_signature("unknown", "RS256", msg, &signature)?);
        assert!(!manager.verify(b"changed", &signature)?);
        assert!(ManagedJwtKeyManager::try_from_runtime_keys_for_algorithm(
            &keys,
            Usage::OidcIdTokenSigning,
            Alg::Rs256
        )
        .is_err());
        assert!(ManagedJwtKeyManager::try_from_runtime_keys_for_algorithm(
            &keys,
            Usage::JwtAccessTokenSigning,
            Alg::Rs256
        )
        .is_err());
        let public_der = simple_asn1::to_der(&simple_asn1::ASN1Block::Sequence(
            0,
            vec![
                simple_asn1::ASN1Block::Integer(
                    0,
                    simple_asn1::BigUint::from_bytes_be(
                        &URL_SAFE_NO_PAD.decode(key.public_jwk.n.as_deref().ok_or("n")?)?,
                    )
                    .into(),
                ),
                simple_asn1::ASN1Block::Integer(
                    0,
                    simple_asn1::BigUint::from_bytes_be(
                        &URL_SAFE_NO_PAD.decode(key.public_jwk.e.as_deref().ok_or("e")?)?,
                    )
                    .into(),
                ),
            ],
        ))?;
        let dir =
            std::env::temp_dir().join(format!("aegaeon-rsa-public-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir)?;
        std::fs::write(dir.as_path().join("public.der"), public_der)?;
        std::fs::write(dir.as_path().join("signature"), signature)?;
        std::fs::write(dir.as_path().join("message"), msg)?;
        let output = std::process::Command::new("openssl")
            .current_dir(dir.as_path())
            .args([
                "dgst",
                "-sha256",
                "-verify",
                "public.der",
                "-keyform",
                "DER",
                "-signature",
                "signature",
                "message",
            ])
            .output()?;
        std::fs::remove_dir_all(&dir)?;
        assert!(
            output.status.success(),
            "independent OpenSSL verification failed"
        );
        let mut mismatch = key.clone();
        mismatch.public_jwk.e = Some("Aw".into());
        assert!(ManagedJwtKeyManager::try_from_runtime_keys_for_algorithm(
            &RuntimeKeySet::try_new(vec![mismatch])?,
            Usage::JwtIntrospectionSigning,
            Alg::Rs256
        )
        .is_err());
        let mut wrong_aad = key;
        wrong_aad.environment_id = uuid::Uuid::from_u128(124);
        assert!(ManagedJwtKeyManager::try_from_runtime_keys_for_algorithm(
            &RuntimeKeySet::try_new(vec![wrong_aad])?,
            Usage::JwtIntrospectionSigning,
            Alg::Rs256
        )
        .is_err());
    }
    for bits in [1024, 5120] {
        assert!(super::managed_rsa::ManagedRsaSigningKey::from_pkcs8(&rsa_pkcs8(bits)?).is_err());
    }
    assert!(super::managed_rsa::ManagedRsaSigningKey::from_pkcs8(b"malformed").is_err());
    Ok(())
}

#[test]
fn managed_introspection_dual_slots_and_retiring_public_only() -> Result {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "env lock")?;
    let _env = super::tests::EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode([0x73; 32])),
    );
    let der = rsa_pkcs8(2048)?;
    let active = rsa_key(&der, "rsa-active", Status::Active)?;
    let mut retired = rsa_key(&der, "rsa-retired", Status::Retiring)?;
    let signer = super::managed_rsa::ManagedRsaSigningKey::from_pkcs8(&der)?;
    let signature = signer.sign(b"message")?;
    // Retiring verification does not need usable private material.
    retired.key_handle = format!(
        "{}{}",
        crate::key_encryption::KEY_HANDLE_ENVELOPE_PREFIX,
        URL_SAFE_NO_PAD.encode([0; 28])
    );
    let ed = aegaeon_crypto::signing::Ed25519SigningKey::generate().map_err(|_| "Ed key")?;
    let mut edkey =
        super::tests::managed_eddsa_runtime_key("ed", Status::Active, String::new(), &ed);
    edkey.usage = Usage::JwtIntrospectionSigning;
    edkey.key_handle = crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(ed.pkcs8),
        &[0x73; 32],
        edkey.key_handle_encryption_context(),
    )?;
    let mut expired = retired.clone();
    expired.kid = "expired".into();
    expired.public_jwk.kid = "expired".into();
    expired.retiring_expires_at_epoch_secs = Some(1);
    let mut revoked = retired.clone();
    revoked.kid = "revoked".into();
    revoked.public_jwk.kid = "revoked".into();
    revoked.status = Status::Revoked;
    revoked.retiring_expires_at_epoch_secs = None;
    let keys = RuntimeKeySet::try_new(vec![active, edkey, retired, expired, revoked])?;
    assert!(keys.active_key(Usage::JwtIntrospectionSigning).is_none());
    let legacy =
        ManagedJwtKeyManager::try_from_runtime_keys(&keys, Usage::JwtIntrospectionSigning)?;
    assert_eq!(legacy.jwt_signing_alg(), "EdDSA");
    assert_eq!(legacy.key_id(), "ed");
    assert_eq!(legacy.jwt_signing_public_jwks().len(), 3);
    assert!(legacy.verify_jwt_signature("rsa-retired", "RS256", b"message", &signature)?);
    assert!(!legacy.verify_jwt_signature("expired", "RS256", b"message", &signature)?);
    assert!(!legacy.verify_jwt_signature("revoked", "RS256", b"message", &signature)?);
    assert!(!legacy.verify_jwt_signature("rsa-retired", "EdDSA", b"message", &signature)?);
    let public = serde_json::to_string(&legacy.jwt_signing_public_jwks())?;
    assert!(!public.contains("PRIVATE") && !public.contains("key_handle"));
    Ok(())
}
