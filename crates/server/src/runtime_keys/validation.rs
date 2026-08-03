use super::{
    RuntimeKey, RuntimeKeyAlgorithm, RuntimeKeyProvider, RuntimeKeySetError, RuntimeKeyStatus,
    RuntimeKeyUsage,
};

const MAX_RETIRING_KEYS_PER_USAGE: usize = 4;

pub(super) fn validate_runtime_key_set(keys: &[RuntimeKey]) -> Result<(), RuntimeKeySetError> {
    reject_duplicate_active_usages(keys)?;
    reject_excess_retiring_keys(keys)?;
    keys.iter().try_for_each(validate_runtime_key)
}

fn reject_duplicate_active_usages(keys: &[RuntimeKey]) -> Result<(), RuntimeKeySetError> {
    let mut seen = std::collections::BTreeSet::new();
    keys.iter()
        .filter(|key| key.status == RuntimeKeyStatus::Active)
        .map(|key| key.usage.as_db_str())
        .try_for_each(|usage| {
            if seen.insert(usage) {
                Ok(())
            } else {
                Err(RuntimeKeySetError::DuplicateActiveUsage(usage))
            }
        })
}

fn reject_excess_retiring_keys(keys: &[RuntimeKey]) -> Result<(), RuntimeKeySetError> {
    let mut counts = std::collections::BTreeMap::<&'static str, usize>::new();
    keys.iter()
        .filter(|key| key.status == RuntimeKeyStatus::Retiring)
        .map(|key| key.usage.as_db_str())
        .try_for_each(|usage| {
            let count = counts
                .entry(usage)
                .and_modify(|count| *count += 1)
                .or_insert(1);
            if *count <= MAX_RETIRING_KEYS_PER_USAGE {
                Ok(())
            } else {
                Err(RuntimeKeySetError::TooManyRetiringKeys {
                    usage,
                    count: *count,
                    max: MAX_RETIRING_KEYS_PER_USAGE,
                })
            }
        })
}

fn validate_runtime_key(key: &RuntimeKey) -> Result<(), RuntimeKeySetError> {
    validate_retiring_expiry_shape(key)?;
    validate_usage_algorithm(key)?;
    validate_public_jwk_matches_key(key)?;
    if key.key_handle.trim().is_empty() {
        return Err(invalid_key(key, "key_handle", "must be non-empty"));
    }
    if !crate::key_encryption::has_supported_key_handle_envelope(&key.key_handle) {
        return Err(invalid_key(
            key,
            "key_handle",
            "must use the supported encrypted runtime-key handle envelope",
        ));
    }
    if !key.provider_configuration.is_object() {
        return Err(invalid_key(
            key,
            "provider_configuration",
            "must be a JSON object",
        ));
    }
    validate_provider_configuration(key)?;
    Ok(())
}

fn validate_provider_configuration(key: &RuntimeKey) -> Result<(), RuntimeKeySetError> {
    let Some(configuration) = key.provider_configuration.as_object() else {
        return Err(invalid_key(
            key,
            "provider_configuration",
            "must be a JSON object",
        ));
    };

    match key.provider {
        RuntimeKeyProvider::DatabaseEncrypted => {
            if configuration.is_empty() {
                Ok(())
            } else {
                Err(invalid_key(
                    key,
                    "provider_configuration",
                    "must be empty for databaseEncrypted runtime keys",
                ))
            }
        }
        RuntimeKeyProvider::AwsKms => validate_aws_kms_provider_configuration(key, configuration),
    }
}

fn validate_aws_kms_provider_configuration(
    key: &RuntimeKey,
    configuration: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), RuntimeKeySetError> {
    if key.usage != RuntimeKeyUsage::OidcIdTokenSigning {
        return Err(invalid_key(
            key,
            "provider",
            "awsKms is supported only for OIDC_ID_TOKEN_SIGNING runtime keys",
        ));
    }
    if configuration.len() != 1 {
        return Err(invalid_key(
            key,
            "provider_configuration",
            "awsKms runtime keys must store only the region; key handles are encrypted separately",
        ));
    }
    let region = configuration
        .get("region")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if region.is_some() {
        Ok(())
    } else {
        Err(invalid_key(
            key,
            "provider_configuration.region",
            "must be a non-empty string for awsKms runtime keys",
        ))
    }
}

fn validate_retiring_expiry_shape(key: &RuntimeKey) -> Result<(), RuntimeKeySetError> {
    match (key.status, key.retiring_expires_at_epoch_secs) {
        (RuntimeKeyStatus::Retiring, Some(_)) => Ok(()),
        (RuntimeKeyStatus::Retiring, None) => Err(invalid_key(
            key,
            "retiring_expires_at",
            "must be present for RETIRING keys",
        )),
        (_, Some(_)) => Err(invalid_key(
            key,
            "retiring_expires_at",
            "must be absent unless the key is RETIRING",
        )),
        (_, None) => Ok(()),
    }
}

fn validate_usage_algorithm(key: &RuntimeKey) -> Result<(), RuntimeKeySetError> {
    let allowed = match key.usage {
        RuntimeKeyUsage::OidcIdTokenSigning => {
            matches!(key.algorithm, RuntimeKeyAlgorithm::Rs256)
        }
        RuntimeKeyUsage::OidcRequestObjectDecryption => {
            matches!(key.algorithm, RuntimeKeyAlgorithm::RsaOaepA256Gcm)
        }
        RuntimeKeyUsage::JwtAccessTokenSigning | RuntimeKeyUsage::JwtIntrospectionSigning => {
            matches!(key.algorithm, RuntimeKeyAlgorithm::EdDsa)
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(invalid_key(
            key,
            "algorithm",
            "is not allowed for this runtime key usage",
        ))
    }
}

fn validate_public_jwk_matches_key(key: &RuntimeKey) -> Result<(), RuntimeKeySetError> {
    if key.public_jwk.kid != key.kid {
        return Err(invalid_key(key, "public_jwk.kid", "must match kid"));
    }

    match key.algorithm {
        RuntimeKeyAlgorithm::Rs256 => validate_rsa_sig_jwk(key, key.algorithm.as_str()),
        RuntimeKeyAlgorithm::RsaOaepA256Gcm => validate_rsa_enc_jwk(key),
        RuntimeKeyAlgorithm::EdDsa => validate_eddsa_jwk(key),
    }
}

fn validate_rsa_sig_jwk(key: &RuntimeKey, alg: &'static str) -> Result<(), RuntimeKeySetError> {
    if key.public_jwk.kty != "RSA"
        || key.public_jwk.use_.as_deref() != Some("sig")
        || key.public_jwk.alg.as_deref() != Some(alg)
        || key.public_jwk.n.as_deref().is_none_or(str::is_empty)
        || key.public_jwk.e.as_deref().is_none_or(str::is_empty)
    {
        return Err(invalid_key(
            key,
            "public_jwk",
            "must be an RSA signature JWK for the configured algorithm",
        ));
    }
    Ok(())
}

fn validate_rsa_enc_jwk(key: &RuntimeKey) -> Result<(), RuntimeKeySetError> {
    if key.public_jwk.kty != "RSA"
        || key.public_jwk.use_.as_deref() != Some("enc")
        || key.public_jwk.alg.as_deref() != Some("RSA-OAEP")
        || key.public_jwk.n.as_deref().is_none_or(str::is_empty)
        || key.public_jwk.e.as_deref().is_none_or(str::is_empty)
    {
        return Err(invalid_key(
            key,
            "public_jwk",
            "must be an RSA-OAEP encryption JWK",
        ));
    }
    Ok(())
}

fn validate_eddsa_jwk(key: &RuntimeKey) -> Result<(), RuntimeKeySetError> {
    if key.public_jwk.kty != "OKP"
        || key.public_jwk.use_.as_deref() != Some("sig")
        || key.public_jwk.alg.as_deref() != Some("EdDSA")
        || key.public_jwk.crv.as_deref() != Some("Ed25519")
        || key.public_jwk.x.as_deref().is_none_or(str::is_empty)
    {
        return Err(invalid_key(
            key,
            "public_jwk",
            "must be an Ed25519 signature JWK",
        ));
    }
    Ok(())
}

fn invalid_key(key: &RuntimeKey, field: &'static str, reason: &'static str) -> RuntimeKeySetError {
    RuntimeKeySetError::InvalidKey {
        kid: key.kid.clone(),
        field,
        reason,
    }
}
