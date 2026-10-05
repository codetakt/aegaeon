use super::{KeyManager, ManagedJwtKeyManager};
use crate::runtime_keys::{
    RuntimeKey, RuntimeKeyAlgorithm as Alg, RuntimeKeySet, RuntimeKeyStatus as Status,
    RuntimeKeyUsage as Usage,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn access_key(
    algorithm: Alg,
    kid: &str,
    status: Status,
) -> std::result::Result<RuntimeKey, Box<dyn std::error::Error>> {
    let (mut key, der) = if algorithm == Alg::Rs256 {
        let der = super::managed_slot_tests::rsa_pkcs8(2048)?;
        (super::managed_slot_tests::rsa_key(&der, kid, status)?, der)
    } else {
        let signer =
            aegaeon_crypto::signing::Ed25519SigningKey::generate().map_err(|_| "Ed key")?;
        let mut key = super::tests::managed_eddsa_runtime_key(kid, status, String::new(), &signer);
        key.retiring_expires_at_epoch_secs = (status == Status::Retiring).then_some(4_102_444_800);
        (key, signer.pkcs8)
    };
    key.usage = Usage::JwtAccessTokenSigning;
    key.key_handle = crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(der),
        &[0x73; 32],
        key.key_handle_encryption_context(),
    )?;
    Ok(key)
}

#[test]
fn managed_access_algorithms_preserve_cross_algorithm_retiring_verification() -> Result {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "env lock")?;
    let _env = super::tests::EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode([0x73; 32])),
    );
    for algorithm in [Alg::Rs256, Alg::EdDsa] {
        let old_algorithm = if algorithm == Alg::Rs256 {
            Alg::EdDsa
        } else {
            Alg::Rs256
        };
        let active = access_key(algorithm, "active", Status::Active)?;
        let mut old = access_key(old_algorithm, "old", Status::Active)?;
        let old_manager = ManagedJwtKeyManager::try_from_runtime_keys(
            &RuntimeKeySet::try_new(vec![old.clone()])?,
            Usage::JwtAccessTokenSigning,
        )?;
        let old_signature = old_manager.sign(b"old message")?;
        old.status = Status::Retiring;
        old.retiring_expires_at_epoch_secs = Some(4_102_444_800);
        // Public-only retirement must not require the old private envelope to decrypt.
        old.key_handle = format!(
            "{}{}",
            crate::key_encryption::KEY_HANDLE_ENVELOPE_PREFIX,
            URL_SAFE_NO_PAD.encode([0; 28])
        );
        let mut expired = old.clone();
        expired.kid = "expired".into();
        expired.public_jwk.kid = "expired".into();
        expired.retiring_expires_at_epoch_secs = Some(1);
        let mut revoked = old.clone();
        revoked.kid = "revoked".into();
        revoked.public_jwk.kid = "revoked".into();
        revoked.status = Status::Revoked;
        revoked.retiring_expires_at_epoch_secs = None;
        let other = super::managed_slot_tests::rsa_key(
            &super::managed_slot_tests::rsa_pkcs8(2048)?,
            "other-purpose",
            Status::Active,
        )?;
        let keys = RuntimeKeySet::try_new(vec![active.clone(), old, expired, revoked, other])?;
        let manager =
            ManagedJwtKeyManager::try_from_runtime_keys(&keys, Usage::JwtAccessTokenSigning)?;
        assert_eq!(manager.jwt_signing_alg(), algorithm.as_str());
        assert_eq!(manager.key_id(), "active");
        let signature = manager.sign(b"message")?;
        assert!(manager.verify(b"message", &signature)?);
        assert!(!manager.verify(b"changed", &signature)?);
        assert!(!manager.verify_jwt_signature(
            "active",
            old_algorithm.as_str(),
            b"message",
            &signature
        )?);
        assert!(!manager.verify_jwt_signature("other-purpose", "RS256", b"message", &signature)?);
        assert!(manager.verify_jwt_signature(
            "old",
            old_algorithm.as_str(),
            b"old message",
            &old_signature
        )?);
        assert!(!manager.verify_jwt_signature(
            "expired",
            old_algorithm.as_str(),
            b"old message",
            &old_signature
        )?);
        assert!(!manager.verify_jwt_signature(
            "revoked",
            old_algorithm.as_str(),
            b"old message",
            &old_signature
        )?);
        assert_eq!(manager.jwt_signing_public_jwks().len(), 2);
        assert!(ManagedJwtKeyManager::try_from_runtime_keys_for_algorithm(
            &keys,
            Usage::JwtAccessTokenSigning,
            old_algorithm
        )
        .is_err());
        assert!(RuntimeKeySet::try_new(vec![
            active.clone(),
            access_key(old_algorithm, "second", Status::Active)?
        ])
        .is_err());
        let mut mismatch = active.clone();
        if algorithm == Alg::Rs256 {
            mismatch.public_jwk.e = Some("Aw".into());
        } else {
            mismatch.public_jwk.x = Some(URL_SAFE_NO_PAD.encode([0; 32]));
        }
        assert!(ManagedJwtKeyManager::try_from_runtime_keys(
            &RuntimeKeySet::try_new(vec![mismatch])?,
            Usage::JwtAccessTokenSigning
        )
        .is_err());
        let mut wrong_aad = active;
        wrong_aad.environment_id = uuid::Uuid::from_u128(124);
        assert!(ManagedJwtKeyManager::try_from_runtime_keys(
            &RuntimeKeySet::try_new(vec![wrong_aad])?,
            Usage::JwtAccessTokenSigning
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn managed_access_rs256_signatures_verify_independently() -> Result {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ENV_GUARD
        .lock()
        .map_err(|_| "env lock")?;
    let _env = super::tests::EnvVarGuard::new(
        "AEGAEON_KEY_ENCRYPTION_KEY",
        Some(&URL_SAFE_NO_PAD.encode([0x73; 32])),
    );
    let key = access_key(Alg::Rs256, "rsa-access", Status::Active)?;
    let manager = ManagedJwtKeyManager::try_from_runtime_keys(
        &RuntimeKeySet::try_new(vec![key.clone()])?,
        Usage::JwtAccessTokenSigning,
    )?;
    let message = b"eyJ0eXAiOiJhdCtqd3QifQ.eyJzdWIiOiJjbGllbnQifQ";
    let public = simple_asn1::to_der(&simple_asn1::ASN1Block::Sequence(
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
        std::env::temp_dir().join(format!("aegaeon-access-rsa-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir)?;
    let result: Result = (|| {
        std::fs::write(dir.join("public.der"), public)?;
        std::fs::write(dir.join("signature"), manager.sign(message)?)?;
        std::fs::write(dir.join("message"), message)?;
        let output = std::process::Command::new("openssl")
            .current_dir(&dir)
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
        assert!(
            output.status.success(),
            "independent access-token RSA verification failed"
        );
        Ok(())
    })();
    std::fs::remove_dir_all(dir)?;
    result
}
