use crate::jwk_types::Jwks;
use crate::management::types::PolicyDocument;
use crate::runtime_keys::RuntimeKeySet;
use url::Url;

use super::session::valid_logout_session_ttl_secs;

mod errors;
mod keys;
mod runtime_keys;
pub use errors::{OidcConfigError, OidcSigningError};
pub use keys::{OidcRequestObjectEncryptionKey, OidcSigningKey};
use runtime_keys::{
    oidc_key_material_from_runtime_keys, oidc_key_material_from_runtime_keys_async,
};

pub const MAX_ID_TOKEN_TTL_SECS: u64 = crate::config::MAX_ACCESS_TOKEN_TTL_SECS;
pub const MAX_BACKCHANNEL_LOGOUT_TIMEOUT_SECS: u64 = 60;

const fn valid_id_token_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_ID_TOKEN_TTL_SECS
}

#[must_use]
pub const fn valid_backchannel_logout_timeout_secs(value: u64) -> bool {
    value > 0 && value <= MAX_BACKCHANNEL_LOGOUT_TIMEOUT_SECS
}

fn validate_oidc_issuer(issuer: &str) -> Result<(), OidcConfigError> {
    let parsed =
        Url::parse(issuer).map_err(|_| OidcConfigError::IssuerInvalid(issuer.to_string()))?;

    if parsed.scheme() != "https" {
        return Err(OidcConfigError::IssuerNotHttps(issuer.to_string()));
    }
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(OidcConfigError::IssuerInvalid(issuer.to_string()));
    }

    Ok(())
}

/// Runtime configuration for enabling OIDC-specific behaviour.
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // OIDC runtime posture is intentionally modeled as explicit toggles.
pub struct OidcConfig {
    /// Public issuer URL (must be HTTPS in production)
    pub issuer: String,
    /// Lifetime for ID Tokens (seconds)
    pub id_token_ttl_secs: u64,
    /// Whether the discovery document should be exposed
    pub discovery_enabled: bool,
    /// Whether the `UserInfo` endpoint is available
    pub userinfo_enabled: bool,
    /// Whether RP-initiated logout is available
    pub logout_enabled: bool,
    /// Whether OP sends Back-Channel Logout notifications to registered RPs
    pub backchannel_logout_enabled: bool,
    /// Retention TTL for logged-out OIDC sessions
    pub logout_session_ttl_secs: u64,
    /// HTTP timeout in seconds when delivering back-channel logout requests
    pub backchannel_logout_timeout_secs: u64,
    /// Whether nonce is mandatory for `OpenID` requests
    pub require_nonce: bool,
    /// RS256 signing key for ID Tokens (and future OIDC JWTs)
    pub signing_key: OidcSigningKey,
    /// Optional RSA-OAEP/A256GCM decryption key for encrypted Request Objects (JWE)
    pub request_object_encryption_key: Option<OidcRequestObjectEncryptionKey>,
}

impl OidcConfig {
    pub fn from_management_snapshot(
        issuer: &str,
        policy: &PolicyDocument,
        runtime_keys: &RuntimeKeySet,
    ) -> Result<Option<Self>, OidcConfigError> {
        if !policy.oidc_enabled {
            return Ok(None);
        }
        validate_oidc_issuer(issuer)?;
        let id_token_ttl_secs = validate_policy_seconds(
            "id_token_time_to_live_seconds",
            u64::from(policy.id_token_time_to_live_seconds),
            valid_id_token_ttl_secs,
            "a value in 1..=86400 seconds",
        )?;
        let logout_session_ttl_secs = validate_policy_seconds(
            "oidc_logout_session_ttl_seconds",
            u64::from(policy.oidc_logout_session_ttl_seconds),
            valid_logout_session_ttl_secs,
            "a value in 1..=86400 seconds",
        )?;
        let backchannel_logout_timeout_secs = validate_policy_seconds(
            "oidc_backchannel_logout_timeout_seconds",
            u64::from(policy.oidc_backchannel_logout_timeout_seconds),
            valid_backchannel_logout_timeout_secs,
            "a value in 1..=60 seconds",
        )?;
        let (signing_key, request_object_encryption_key) =
            oidc_key_material_from_runtime_keys(runtime_keys)?;

        Ok(Some(Self {
            issuer: issuer.to_string(),
            id_token_ttl_secs,
            discovery_enabled: policy.oidc_enable_discovery,
            userinfo_enabled: policy.oidc_enable_userinfo,
            logout_enabled: policy.oidc_enable_logout,
            backchannel_logout_enabled: policy.oidc_enable_backchannel_logout,
            logout_session_ttl_secs,
            backchannel_logout_timeout_secs,
            require_nonce: policy.oidc_require_nonce,
            signing_key,
            request_object_encryption_key,
        }))
    }

    pub async fn from_management_snapshot_async(
        issuer: &str,
        policy: &PolicyDocument,
        runtime_keys: &RuntimeKeySet,
    ) -> Result<Option<Self>, OidcConfigError> {
        if !policy.oidc_enabled {
            return Ok(None);
        }
        validate_oidc_issuer(issuer)?;
        let id_token_ttl_secs = validate_policy_seconds(
            "id_token_time_to_live_seconds",
            u64::from(policy.id_token_time_to_live_seconds),
            valid_id_token_ttl_secs,
            "a value in 1..=86400 seconds",
        )?;
        let logout_session_ttl_secs = validate_policy_seconds(
            "oidc_logout_session_ttl_seconds",
            u64::from(policy.oidc_logout_session_ttl_seconds),
            valid_logout_session_ttl_secs,
            "a value in 1..=86400 seconds",
        )?;
        let backchannel_logout_timeout_secs = validate_policy_seconds(
            "oidc_backchannel_logout_timeout_seconds",
            u64::from(policy.oidc_backchannel_logout_timeout_seconds),
            valid_backchannel_logout_timeout_secs,
            "a value in 1..=60 seconds",
        )?;
        let (signing_key, request_object_encryption_key) =
            oidc_key_material_from_runtime_keys_async(runtime_keys).await?;

        Ok(Some(Self {
            issuer: issuer.to_string(),
            id_token_ttl_secs,
            discovery_enabled: policy.oidc_enable_discovery,
            userinfo_enabled: policy.oidc_enable_userinfo,
            logout_enabled: policy.oidc_enable_logout,
            backchannel_logout_enabled: policy.oidc_enable_backchannel_logout,
            logout_session_ttl_secs,
            backchannel_logout_timeout_secs,
            require_nonce: policy.oidc_require_nonce,
            signing_key,
            request_object_encryption_key,
        }))
    }

    #[must_use]
    pub fn jwks(&self) -> Jwks {
        let mut jwks = self.signing_key.jwks();
        if let Some(ref enc_key) = self.request_object_encryption_key {
            jwks.keys.push(enc_key.public_jwk().clone());
        }
        jwks
    }
}

fn validate_policy_seconds(
    field: &'static str,
    value: u64,
    is_valid: impl FnOnce(u64) -> bool,
    expectation: &'static str,
) -> Result<u64, OidcConfigError> {
    if is_valid(value) {
        Ok(value)
    } else {
        Err(OidcConfigError::InvalidNumericPolicy {
            field,
            value,
            expectation,
        })
    }
}

#[cfg(test)]
mod tests;
