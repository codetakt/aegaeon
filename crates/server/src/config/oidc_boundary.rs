use super::env_vars::env_key_is_present;
use super::ConfigError;

pub(super) const OIDC_STARTUP_POLICY_ENV_KEYS: &[&str] = &[
    "AEGAEON_OIDC_ENABLED",
    "AEGAEON_OIDC_ISSUER",
    "AEGAEON_OIDC_ID_TOKEN_TTL",
    "AEGAEON_OIDC_ENABLE_DISCOVERY",
    "AEGAEON_OIDC_ENABLE_USERINFO",
    "AEGAEON_OIDC_REQUIRE_NONCE",
    "AEGAEON_OIDC_ENABLE_LOGOUT",
    "AEGAEON_OIDC_ENABLE_BACKCHANNEL_LOGOUT",
    "AEGAEON_OIDC_BACKCHANNEL_LOGOUT_TIMEOUT_SECS",
    "AEGAEON_OIDC_LOGOUT_SESSION_TTL_SECS",
];

pub(super) const OIDC_STARTUP_KEY_MATERIAL_ENV_KEYS: &[&str] = &[
    "AEGAEON_OIDC_SIGNING_BACKEND",
    "AEGAEON_OIDC_SIGNING_KID",
    "AEGAEON_OIDC_SIGNING_KEY_PEM_FILE",
    "AEGAEON_OIDC_SIGNING_KEY_PEM",
    "AEGAEON_OIDC_SIGNING_AWS_REGION",
    "AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID",
    "AEGAEON_OIDC_JWKS_ADDITIONAL_FILE",
    "AEGAEON_OIDC_JWKS_ADDITIONAL",
    "AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KEY_PEM_FILE",
    "AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KEY_PEM",
    "AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KID",
];

pub(super) fn configured_oidc_startup_policy_env_keys() -> Result<Vec<&'static str>, ConfigError> {
    configured_env_keys(OIDC_STARTUP_POLICY_ENV_KEYS)
}

pub(super) fn configured_oidc_startup_key_material_env_keys(
) -> Result<Vec<&'static str>, ConfigError> {
    configured_env_keys(OIDC_STARTUP_KEY_MATERIAL_ENV_KEYS)
}

fn configured_env_keys(keys: &[&'static str]) -> Result<Vec<&'static str>, ConfigError> {
    keys.iter()
        .map(|key| env_key_is_present(key).map(|configured| (*key, configured)))
        .filter_map(|result| match result {
            Ok((key, true)) => Some(Ok(key)),
            Ok((_key, false)) => None,
            Err(err) => Some(Err(err)),
        })
        .collect()
}
