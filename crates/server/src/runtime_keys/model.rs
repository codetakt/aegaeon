use crate::jwk_types::Jwk;
use serde_json::Value;

use super::{validation, RuntimeKeySetError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuntimeKeyUsage {
    OidcIdTokenSigning,
    OidcRequestObjectDecryption,
    JwtAccessTokenSigning,
    JwtIntrospectionSigning,
}

impl RuntimeKeyUsage {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::OidcIdTokenSigning => "OIDC_ID_TOKEN_SIGNING",
            Self::OidcRequestObjectDecryption => "OIDC_REQUEST_OBJECT_DECRYPTION",
            Self::JwtAccessTokenSigning => "JWT_ACCESS_TOKEN_SIGNING",
            Self::JwtIntrospectionSigning => "JWT_INTROSPECTION_SIGNING",
        }
    }

    pub(super) fn try_from_db(value: &str) -> Result<Self, RuntimeKeySetError> {
        match value {
            "OIDC_ID_TOKEN_SIGNING" => Ok(Self::OidcIdTokenSigning),
            "OIDC_REQUEST_OBJECT_DECRYPTION" => Ok(Self::OidcRequestObjectDecryption),
            "JWT_ACCESS_TOKEN_SIGNING" => Ok(Self::JwtAccessTokenSigning),
            "JWT_INTROSPECTION_SIGNING" => Ok(Self::JwtIntrospectionSigning),
            other => Err(RuntimeKeySetError::InvalidUsage(other.to_string())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeKeyAlgorithm {
    Rs256,
    RsaOaepA256Gcm,
    EdDsa,
}

impl RuntimeKeyAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::RsaOaepA256Gcm => "RSA-OAEP+A256GCM",
            Self::EdDsa => "EdDSA",
        }
    }

    pub(super) fn try_from_db(value: &str) -> Result<Self, RuntimeKeySetError> {
        match value.trim() {
            "RS256" => Ok(Self::Rs256),
            "RSA-OAEP+A256GCM" => Ok(Self::RsaOaepA256Gcm),
            "EdDSA" | "EDDSA" => Ok(Self::EdDsa),
            other => Err(RuntimeKeySetError::InvalidAlgorithm(other.to_string())),
        }
    }

    #[must_use]
    pub const fn signing_policy_name(self) -> Option<&'static str> {
        match self {
            Self::Rs256 => Some("RS256"),
            Self::EdDsa => Some("EdDSA"),
            Self::RsaOaepA256Gcm => None,
        }
    }
}

#[must_use]
pub fn canonical_runtime_signing_algorithm_name(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_uppercase().as_str() {
        "RS256" => Some("RS256"),
        "EDDSA" => Some("EdDSA"),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeKeyProvider {
    DatabaseEncrypted,
    AwsKms,
}

impl RuntimeKeyProvider {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::DatabaseEncrypted => "databaseEncrypted",
            Self::AwsKms => "awsKms",
        }
    }

    pub(super) fn try_from_db(value: &str) -> Result<Self, RuntimeKeySetError> {
        match value {
            "databaseEncrypted" => Ok(Self::DatabaseEncrypted),
            "awsKms" => Ok(Self::AwsKms),
            other => Err(RuntimeKeySetError::InvalidProvider(other.to_string())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeKeyStatus {
    Active,
    Next,
    Retiring,
    Revoked,
}

impl RuntimeKeyStatus {
    pub(super) fn try_from_db(value: &str) -> Result<Self, RuntimeKeySetError> {
        match value {
            "ACTIVE" => Ok(Self::Active),
            "NEXT" => Ok(Self::Next),
            "RETIRING" => Ok(Self::Retiring),
            "REVOKED" => Ok(Self::Revoked),
            other => Err(RuntimeKeySetError::InvalidStatus(other.to_string())),
        }
    }
}

#[derive(Clone)]
pub struct RuntimeKey {
    pub environment_id: uuid::Uuid,
    pub usage: RuntimeKeyUsage,
    pub algorithm: RuntimeKeyAlgorithm,
    pub provider: RuntimeKeyProvider,
    pub status: RuntimeKeyStatus,
    pub retiring_expires_at_epoch_secs: Option<i64>,
    pub kid: String,
    pub public_jwk: Jwk,
    pub key_handle: String,
    pub provider_configuration: Value,
}

impl RuntimeKey {
    #[must_use]
    pub fn key_handle_encryption_context(
        &self,
    ) -> crate::key_encryption::KeyHandleEncryptionContext<'_> {
        crate::key_encryption::KeyHandleEncryptionContext::new(
            self.environment_id,
            self.usage.as_db_str(),
            self.provider.as_db_str(),
            self.algorithm.as_str(),
            &self.kid,
        )
    }

    #[must_use]
    pub fn is_retiring_active_at(&self, now_epoch_secs: i64) -> bool {
        self.status == RuntimeKeyStatus::Retiring
            && self
                .retiring_expires_at_epoch_secs
                .is_some_and(|expires_at| expires_at > now_epoch_secs)
    }

    #[must_use]
    pub fn is_verification_key_active_at(&self, now_epoch_secs: i64) -> bool {
        self.status == RuntimeKeyStatus::Active || self.is_retiring_active_at(now_epoch_secs)
    }
}

impl std::fmt::Debug for RuntimeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeKey")
            .field("environment_id", &self.environment_id)
            .field("usage", &self.usage)
            .field("algorithm", &self.algorithm)
            .field("provider", &self.provider)
            .field("status", &self.status)
            .field(
                "retiring_expires_at_epoch_secs",
                &self.retiring_expires_at_epoch_secs,
            )
            .field("kid", &self.kid)
            .field("public_jwk", &self.public_jwk)
            .field("provider_configuration", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeKeySet {
    keys: Vec<RuntimeKey>,
}

impl RuntimeKeySet {
    pub fn try_new(keys: Vec<RuntimeKey>) -> Result<Self, RuntimeKeySetError> {
        let key_set = Self { keys };
        key_set.validate()?;
        Ok(key_set)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    #[must_use]
    pub fn active_key(&self, usage: RuntimeKeyUsage) -> Option<&RuntimeKey> {
        self.keys
            .iter()
            .find(|key| key.usage == usage && key.status == RuntimeKeyStatus::Active)
    }

    #[must_use = "consume the retiring-key iterator or remove the call"]
    pub fn retiring_keys(&self, usage: RuntimeKeyUsage) -> impl Iterator<Item = &RuntimeKey> {
        self.keys
            .iter()
            .filter(move |key| key.usage == usage && key.status == RuntimeKeyStatus::Retiring)
    }

    #[must_use = "consume the retiring-key iterator or remove the call"]
    pub fn active_retiring_keys_at(
        &self,
        usage: RuntimeKeyUsage,
        now_epoch_secs: i64,
    ) -> impl Iterator<Item = &RuntimeKey> {
        self.retiring_keys(usage)
            .filter(move |key| key.is_retiring_active_at(now_epoch_secs))
    }

    fn validate(&self) -> Result<(), RuntimeKeySetError> {
        validation::validate_runtime_key_set(&self.keys)
    }

    pub fn validate_allowed_signing_algorithms(
        &self,
        allowed: &[String],
    ) -> Result<(), RuntimeKeySetError> {
        let allowed = allowed
            .iter()
            .map(|value| {
                canonical_runtime_signing_algorithm_name(value)
                    .ok_or_else(|| RuntimeKeySetError::InvalidPolicySigningAlgorithm(value.clone()))
            })
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;

        self.keys
            .iter()
            .filter_map(|key| {
                key.algorithm
                    .signing_policy_name()
                    .map(|algorithm| (key.usage.as_db_str(), algorithm))
            })
            .try_for_each(|(usage, algorithm)| {
                if allowed.contains(algorithm) {
                    Ok(())
                } else {
                    Err(RuntimeKeySetError::PolicyDisallowedSigningAlgorithm { usage, algorithm })
                }
            })
    }
}
