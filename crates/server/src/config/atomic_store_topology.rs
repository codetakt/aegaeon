use super::runtime_boundary::RedisStoreUrl;
use super::ConfigError;

pub(super) fn validate_authorization_code_grant_commit_store_topology() -> Result<(), ConfigError> {
    let auth_code = RedisStoreUrl::optional_from_env("AEGAEON_AUTH_CODE_REDIS_URL")?;
    let token_store = RedisStoreUrl::optional_from_env("AEGAEON_TOKEN_STORE_REDIS_URL")?;
    let par = RedisStoreUrl::optional_from_env("AEGAEON_PAR_REDIS_URL")?;
    let request_object_jti =
        RedisStoreUrl::optional_from_env("AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL")?;
    let oidc_logout_session =
        RedisStoreUrl::optional_from_env("AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL")?;
    if let (Some(auth_code), Some(token_store)) = (auth_code.as_ref(), token_store.as_ref()) {
        if !auth_code.references_same_endpoint(token_store) {
            return Err(ConfigError::InvalidValue {
                key: "AEGAEON_TOKEN_STORE_REDIS_URL".to_string(),
                value: "[redacted]".to_string(),
                reason: "authorization-code exchange commits consume the code and store issued tokens atomically; AEGAEON_AUTH_CODE_REDIS_URL and AEGAEON_TOKEN_STORE_REDIS_URL must reference the same Redis endpoint".to_string(),
            });
        }
    }
    if let (Some(auth_code), Some(par)) = (auth_code.as_ref(), par.as_ref()) {
        if !auth_code.references_same_endpoint(par) {
            return Err(ConfigError::InvalidValue {
                key: "AEGAEON_PAR_REDIS_URL".to_string(),
                value: "[redacted]".to_string(),
                reason: "authorization-code issuance commits store the code and consume PAR request_uri atomically; AEGAEON_PAR_REDIS_URL must reference the same Redis endpoint as AEGAEON_AUTH_CODE_REDIS_URL".to_string(),
            });
        }
    }
    if let (Some(auth_code), Some(request_object_jti)) =
        (auth_code.as_ref(), request_object_jti.as_ref())
    {
        if !auth_code.references_same_endpoint(request_object_jti) {
            return Err(ConfigError::InvalidValue {
                key: "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL".to_string(),
                value: "[redacted]".to_string(),
                reason: "authorization-code issuance commits store the code and consume direct Request Object jti atomically; AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL must reference the same Redis endpoint as AEGAEON_AUTH_CODE_REDIS_URL".to_string(),
            });
        }
    }
    if let (Some(token_store), Some(oidc_logout_session)) =
        (token_store.as_ref(), oidc_logout_session.as_ref())
    {
        if !token_store.references_same_endpoint(oidc_logout_session) {
            return Err(ConfigError::InvalidValue {
                key: "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL".to_string(),
                value: "[redacted]".to_string(),
                reason: "OIDC authorization-code exchange commits issue tokens and update logout-session fan-out atomically; AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL must reference the same Redis endpoint as AEGAEON_TOKEN_STORE_REDIS_URL".to_string(),
            });
        }
    }
    Ok(())
}
