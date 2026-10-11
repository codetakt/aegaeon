use crate::jwk_types::Jwk;
use crate::runtime_keys::{
    RuntimeKey, RuntimeKeyAlgorithm, RuntimeKeyProvider, RuntimeKeySet, RuntimeKeyUsage,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use super::keys::{OidcAdditionalPublicJwk, OidcRequestObjectEncryptionKey, OidcSigningKey};
use super::OidcConfigError;

pub(super) fn oidc_key_material_from_runtime_keys(
    runtime_keys: &RuntimeKeySet,
) -> Result<(OidcSigningKey, Option<OidcRequestObjectEncryptionKey>), OidcConfigError> {
    let signing_key = runtime_keys
        .active_key(RuntimeKeyUsage::OidcIdTokenSigning)
        .ok_or(OidcConfigError::ManagedKeyMissing("OIDC ID Token signing"))?;
    let signing_key = managed_oidc_signing_key(signing_key)?;
    let signing_key = signing_key
        .with_runtime_retiring_public_jwks(retiring_oidc_signing_public_jwks(runtime_keys)?)?;

    let request_object_encryption_key = managed_request_object_keyring(runtime_keys)?;

    Ok((signing_key, request_object_encryption_key))
}

pub(super) async fn oidc_key_material_from_runtime_keys_async(
    runtime_keys: &RuntimeKeySet,
) -> Result<(OidcSigningKey, Option<OidcRequestObjectEncryptionKey>), OidcConfigError> {
    let signing_key = runtime_keys
        .active_key(RuntimeKeyUsage::OidcIdTokenSigning)
        .ok_or(OidcConfigError::ManagedKeyMissing("OIDC ID Token signing"))?;
    let signing_key = managed_oidc_signing_key_async(signing_key).await?;
    let signing_key = signing_key
        .with_runtime_retiring_public_jwks(retiring_oidc_signing_public_jwks(runtime_keys)?)?;

    let request_object_encryption_key = managed_request_object_keyring(runtime_keys)?;

    Ok((signing_key, request_object_encryption_key))
}

fn retiring_oidc_signing_public_jwks(
    runtime_keys: &RuntimeKeySet,
) -> Result<Vec<OidcAdditionalPublicJwk>, OidcConfigError> {
    runtime_keys
        .retiring_keys(RuntimeKeyUsage::OidcIdTokenSigning)
        .map(|key| {
            key.retiring_expires_at_epoch_secs
                .ok_or_else(|| {
                    OidcConfigError::AdditionalJwksInternalConsistency(format!(
                        "RETIRING runtime key `{}` is missing retiring_expires_at",
                        key.kid
                    ))
                })
                .map(|expires_at| {
                    OidcAdditionalPublicJwk::retiring(key.public_jwk.clone(), expires_at)
                })
        })
        .collect()
}

fn managed_oidc_signing_key(key: &RuntimeKey) -> Result<OidcSigningKey, OidcConfigError> {
    if key.algorithm != RuntimeKeyAlgorithm::Rs256 {
        return Err(OidcConfigError::ManagedKeyUnsupportedProvider(
            key.kid.clone(),
        ));
    }
    match key.provider {
        RuntimeKeyProvider::DatabaseEncrypted => {
            let der = decrypt_managed_pkcs8_der(key)?;
            let signing_key = OidcSigningKey::from_rsa_pkcs8_der(key.kid.clone(), &der)?;
            ensure_public_jwk_matches(&key.public_jwk, signing_key.public_jwk())?;
            Ok(signing_key)
        }
        RuntimeKeyProvider::AwsKms => managed_aws_kms_signing_key(key),
    }
}

async fn managed_oidc_signing_key_async(
    key: &RuntimeKey,
) -> Result<OidcSigningKey, OidcConfigError> {
    if key.algorithm != RuntimeKeyAlgorithm::Rs256 {
        return Err(OidcConfigError::ManagedKeyUnsupportedProvider(
            key.kid.clone(),
        ));
    }
    match key.provider {
        RuntimeKeyProvider::DatabaseEncrypted => {
            let der = decrypt_managed_pkcs8_der(key)?;
            let signing_key = OidcSigningKey::from_rsa_pkcs8_der(key.kid.clone(), &der)?;
            ensure_public_jwk_matches(&key.public_jwk, signing_key.public_jwk())?;
            Ok(signing_key)
        }
        RuntimeKeyProvider::AwsKms => managed_aws_kms_signing_key_async(key).await,
    }
}

#[cfg(feature = "kms-aws")]
fn managed_aws_kms_signing_key(key: &RuntimeKey) -> Result<OidcSigningKey, OidcConfigError> {
    let region = key
        .provider_configuration
        .get("region")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(OidcConfigError::AwsKmsRegionMissing)?;
    let key_id = decrypt_managed_key_handle(key)?;
    let signing_key = OidcSigningKey::from_aws_kms(region.to_string(), key_id, key.kid.clone())?;
    ensure_public_jwk_matches(&key.public_jwk, signing_key.public_jwk())?;
    Ok(signing_key)
}

#[cfg(feature = "kms-aws")]
async fn managed_aws_kms_signing_key_async(
    key: &RuntimeKey,
) -> Result<OidcSigningKey, OidcConfigError> {
    let region = key
        .provider_configuration
        .get("region")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(OidcConfigError::AwsKmsRegionMissing)?;
    let key_id = decrypt_managed_key_handle(key)?;
    let signing_key =
        OidcSigningKey::from_aws_kms_async(region.to_string(), key_id, key.kid.clone()).await?;
    ensure_public_jwk_matches(&key.public_jwk, signing_key.public_jwk())?;
    Ok(signing_key)
}

#[cfg(not(feature = "kms-aws"))]
fn managed_aws_kms_signing_key(_key: &RuntimeKey) -> Result<OidcSigningKey, OidcConfigError> {
    Err(OidcConfigError::AwsKmsFeatureDisabled)
}

#[cfg(not(feature = "kms-aws"))]
async fn managed_aws_kms_signing_key_async(
    _key: &RuntimeKey,
) -> Result<OidcSigningKey, OidcConfigError> {
    Err(OidcConfigError::AwsKmsFeatureDisabled)
}

fn managed_oidc_request_object_encryption_key(
    key: &RuntimeKey,
) -> Result<OidcRequestObjectEncryptionKey, OidcConfigError> {
    if key.provider != RuntimeKeyProvider::DatabaseEncrypted
        || key.algorithm != RuntimeKeyAlgorithm::RsaOaepA256Gcm
        || key.usage != RuntimeKeyUsage::OidcRequestObjectDecryption
    {
        return Err(OidcConfigError::ManagedKeyUnsupportedProvider(
            key.kid.clone(),
        ));
    }
    let der = decrypt_managed_pkcs8_der(key)?;
    let encryption_key = OidcRequestObjectEncryptionKey::from_rsa_pkcs8_der(key.kid.clone(), &der)?;
    ensure_public_jwk_matches(&key.public_jwk, encryption_key.public_jwk())?;
    Ok(encryption_key)
}

fn managed_request_object_keyring(
    runtime_keys: &RuntimeKeySet,
) -> Result<Option<OidcRequestObjectEncryptionKey>, OidcConfigError> {
    let usage = RuntimeKeyUsage::OidcRequestObjectDecryption;
    let Some(active) = runtime_keys.active_key(usage) else {
        // Retiring keys do not reactivate a disabled encryption capability.
        return Ok(None);
    };
    let now = crate::util::now_unix_epoch_secs_i64()
        .map_err(|_| OidcConfigError::RequestObjectKeySetUnavailable)?;
    let candidates = std::iter::once(active)
        .chain(runtime_keys.active_retiring_keys_at(usage, now))
        .collect::<Vec<_>>();
    let mut kids = std::collections::BTreeSet::new();
    for key in &candidates {
        if !kids.insert(key.kid.as_str()) {
            return Err(OidcConfigError::RequestObjectEncryptionKidConflicts(
                key.kid.clone(),
            ));
        }
    }
    for usage in [
        RuntimeKeyUsage::OidcIdTokenSigning,
        RuntimeKeyUsage::JwtAccessTokenSigning,
        RuntimeKeyUsage::JwtIntrospectionSigning,
    ] {
        for key in runtime_keys
            .active_key(usage)
            .into_iter()
            .chain(runtime_keys.active_retiring_keys_at(usage, now))
        {
            if kids.contains(key.kid.as_str()) {
                return Err(OidcConfigError::RequestObjectEncryptionKidConflicts(
                    key.kid.clone(),
                ));
            }
        }
    }
    let active = managed_oidc_request_object_encryption_key(active)?;
    let retiring = candidates
        .into_iter()
        .skip(1)
        .map(|key| {
            let deadline = key
                .retiring_expires_at_epoch_secs
                .ok_or(OidcConfigError::RequestObjectKeySetUnavailable)?;
            Ok((managed_oidc_request_object_encryption_key(key)?, deadline))
        })
        .collect::<Result<Vec<_>, OidcConfigError>>()?;
    Ok(Some(active.with_retiring(retiring)))
}

fn decrypt_managed_pkcs8_der(key: &RuntimeKey) -> Result<Vec<u8>, OidcConfigError> {
    let plaintext = decrypt_managed_key_handle(key)?;
    URL_SAFE_NO_PAD
        .decode(plaintext.trim())
        .map_err(|_| OidcConfigError::ManagedKeyHandleInvalidEncoding(key.kid.clone()))
}

fn decrypt_managed_key_handle(key: &RuntimeKey) -> Result<String, OidcConfigError> {
    let kek = crate::key_encryption::load_key_encryption_key()
        .map_err(|_| OidcConfigError::ManagedKeyHandleDecrypt(key.kid.clone()))?;
    crate::key_encryption::decrypt_key_handle(
        &key.key_handle,
        &kek,
        key.key_handle_encryption_context(),
    )
    .map_err(|_| OidcConfigError::ManagedKeyHandleDecrypt(key.kid.clone()))
}

fn ensure_public_jwk_matches(expected: &Jwk, actual: &Jwk) -> Result<(), OidcConfigError> {
    if expected.kty == actual.kty
        && expected.use_ == actual.use_
        && expected.kid == actual.kid
        && expected.alg == actual.alg
        && expected.n == actual.n
        && expected.e == actual.e
        && expected.x == actual.x
        && expected.y == actual.y
        && expected.crv == actual.crv
    {
        Ok(())
    } else {
        Err(OidcConfigError::ManagedPublicJwkMismatch(
            expected.kid.clone(),
        ))
    }
}
