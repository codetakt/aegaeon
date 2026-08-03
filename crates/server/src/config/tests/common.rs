use super::*;
use crate::management::types::{PolicyDocument, PolicySenderConstraint};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::panic;
use std::path::{Path, PathBuf};
use std::sync::MutexGuard;

const TEST_DATABASE_URL: &str = "postgres://aegaeon:test@127.0.0.1/aegaeon_test";

type ConfigTestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(err) => fail_test!("{}: {:?}", $context, err),
        }
    };
}

macro_rules! must_err {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(_) => fail_test!("{}", $context),
            Err(err) => err,
        }
    };
}

#[track_caller]
fn fail_assertion(message: String) -> ! {
    std::panic::panic_any(message)
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let previous = env::var_os(key);
        match value {
            Some(value) => env::set_var(key, value),
            None => env::remove_var(key),
        }
        Self { key, previous }
    }

    #[cfg(unix)]
    fn new_os_string(key: &'static str, value: Option<OsString>) -> Self {
        let previous = env::var_os(key);
        match value {
            Some(value) => env::set_var(key, value),
            None => env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            env::set_var(self.key, previous);
        } else {
            env::remove_var(self.key);
        }
    }
}

struct ConfigEnvLock {
    _server: MutexGuard<'static, ()>,
    _raw_json: MutexGuard<'static, ()>,
}

fn env_lock() -> ConfigEnvLock {
    let server = match crate::util::SERVER_TEST_ENV_GUARD.lock() {
        Ok(lock) => lock,
        Err(err) => fail_assertion(format!("config env guard poisoned: {err}")),
    };
    let raw_json = match crate::util::RAW_JSON_ENV_GUARD.lock() {
        Ok(lock) => lock,
        Err(err) => fail_assertion(format!("raw JSON env guard poisoned: {err}")),
    };
    ConfigEnvLock {
        _server: server,
        _raw_json: raw_json,
    }
}

fn env_guards(vars: &[(&'static str, Option<&'static str>)]) -> Vec<EnvVarGuard> {
    vars.iter()
        .map(|(key, value)| EnvVarGuard::new(key, *value))
        .collect()
}

fn required_database_url() -> EnvVarGuard {
    EnvVarGuard::new("AEGAEON_DATABASE_URL", Some(TEST_DATABASE_URL))
}

fn database_backed_runtime_env() -> Vec<EnvVarGuard> {
    let mut guards = env_guards(&[
        ("AEGAEON_CONFIG_AUTHORITY", None),
        ("AEGAEON_DB_ENABLED", None),
        ("AEGAEON_ADMIN_API_KEY", None),
        ("AEGAEON_DEPLOYMENT_MODE", None),
        (REMOVED_EPHEMERAL_RUNTIME_STATE_ENV, None),
        ("AEGAEON_CSRF_REDIS_URL", None),
        ("AEGAEON_RATE_LIMIT_REDIS_URL", None),
        ("AEGAEON_ENFORCE_SECURE_PROTO", None),
        ("AEGAEON_DATABASE_URL", Some(TEST_DATABASE_URL)),
        ("AEGAEON_RUNTIME_CLIENT_SYNC_INTERVAL_SECS", None),
        ("AEGAEON_RUNTIME_CONFIG_MONITOR_INTERVAL_SECS", None),
        ("AEGAEON_DCR_EVERPARSE_RUNTIME", None),
        ("AEGAEON_REQUEST_OBJECT_EVERPARSE_RUNTIME", None),
        ("AEGAEON_JOSE_HEADER_MAXLEN", None),
    ]);
    guards.extend(set_base_shared_runtime_store_env());
    guards.extend(clear_raw_json_backend_override_envs());
    guards
}

fn raw_json_backend_override_env_keys() -> Vec<&'static str> {
    let mut keys = vec![
        aegaeon_jose::raw_json::raw_json_backend_env_var(),
        "AEGAEON_RAW_JSON_BACKEND_GENERIC_OBJECT",
    ];
    keys.extend(
        aegaeon_jose::raw_json::ALL_RAW_JSON_SURFACES
            .iter()
            .copied()
            .map(aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface),
    );
    keys.sort_unstable();
    keys.dedup();
    keys
}

fn clear_raw_json_backend_override_envs() -> Vec<EnvVarGuard> {
    raw_json_backend_override_env_keys()
        .into_iter()
        .map(|key| EnvVarGuard::new(key, None))
        .collect()
}

fn clear_optional_shared_runtime_surfaces() -> Vec<EnvVarGuard> {
    env_guards(&[
        ("AEGAEON_ENABLE_DEVICE_AUTHZ", None),
        ("AEGAEON_ENABLE_JWT_ACCESS_TOKENS", None),
        ("AEGAEON_ENABLE_JWT_BEARER_GRANT", None),
        ("AEGAEON_ENABLE_JWT_INTROSPECTION", None),
        ("AEGAEON_ENABLE_PRIVATE_KEY_JWT", None),
        ("AEGAEON_FEDERATION_AUTHORITY_HINTS", None),
        ("AEGAEON_FEDERATION_ENTITY_EXP_SECS", None),
        ("AEGAEON_FEDERATION_OP_ENABLED", None),
        ("AEGAEON_OIDC_ENABLED", None),
        ("AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KEY_PEM", None),
        ("AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KEY_PEM_FILE", None),
        ("AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KID", None),
        ("AEGAEON_OIDC_SIGNING_BACKEND", None),
        ("AEGAEON_OIDC_SIGNING_KID", None),
        ("AEGAEON_OIDC_SIGNING_KEY_PEM", None),
        ("AEGAEON_OIDC_SIGNING_KEY_PEM_FILE", None),
        ("AEGAEON_OIDC_SIGNING_AWS_REGION", None),
        ("AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID", None),
        ("AEGAEON_OIDC_JWKS_ADDITIONAL", None),
        ("AEGAEON_OIDC_JWKS_ADDITIONAL_FILE", None),
    ])
}

fn clear_shared_runtime_store_env() -> Vec<EnvVarGuard> {
    env_guards(&[
        ("AEGAEON_AUTH_CODE_REDIS_URL", None),
        ("AEGAEON_AUTH_SESSION_REDIS_URL", None),
        ("AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL", None),
        ("AEGAEON_DEVICE_CODE_REDIS_URL", None),
        ("AEGAEON_DEVICE_CSRF_REDIS_URL", None),
        ("AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL", None),
        ("AEGAEON_DPOP_NONCE_REDIS_URL", None),
        ("AEGAEON_DPOP_REDIS_URL", None),
        ("AEGAEON_JWKS_REDIS_URL", None),
        ("AEGAEON_JWKS_SHARED_CACHE_PATH", None),
        ("AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL", None),
        ("AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL", None),
        ("AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL", None),
        ("AEGAEON_MANAGEMENT_SESSION_REDIS_URL", None),
        ("AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL", None),
        ("AEGAEON_PAR_REDIS_URL", None),
        ("AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL", None),
        ("AEGAEON_STEPUP_REDIS_URL", None),
        ("AEGAEON_TOKEN_STORE_REDIS_URL", None),
        ("AEGAEON_UPSTREAM_AUTH_REDIS_URL", None),
        ("AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL", None),
    ])
}

fn set_base_shared_runtime_store_env() -> Vec<EnvVarGuard> {
    const REDIS_URL: &str = "redis://127.0.0.1:6379/0";
    env_guards(&[
        ("AEGAEON_AUTH_CODE_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_AUTH_SESSION_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_DEVICE_CODE_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_DEVICE_CSRF_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_DPOP_NONCE_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_DPOP_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_JWKS_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL", Some(REDIS_URL)),
        (
            "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
            Some(REDIS_URL),
        ),
        ("AEGAEON_MANAGEMENT_SESSION_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_PAR_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_STEPUP_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_TOKEN_STORE_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_UPSTREAM_AUTH_REDIS_URL", Some(REDIS_URL)),
        ("AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL", Some(REDIS_URL)),
    ])
}

fn maximal_shared_runtime_store_config() -> ServerConfig {
    ServerConfig {
        dpop_strict: true,
        require_dpop_nonce: true,
        enable_private_key_jwt: true,
        enable_jwt_bearer_grant: true,
        enable_device_authz: true,
        ..ServerConfig::default()
    }
}

fn shared_runtime_store_inventory_keys(cfg: &ServerConfig) -> Result<BTreeSet<String>, String> {
    let keys = cfg
        .shared_runtime_store_requirements(true)
        .map_err(|err| format!("shared runtime-store requirements: {err:?}"))?
        .into_iter()
        .map(|requirement| requirement.primary_env)
        .map(str::to_owned)
        .collect();
    Ok(keys)
}

fn collect_runtime_source_redis_env_keys() -> Result<BTreeSet<String>, String> {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut rust_files = Vec::new();
    collect_rust_source_files(&src_dir, &mut rust_files)?;

    let key_sets = rust_files
        .into_iter()
        // Exclude inventory declarations; they must not satisfy the runtime-source scan.
        .filter(|path| {
            let relative = path.strip_prefix(&src_dir).unwrap_or(path.as_path());
            let Some(relative) = relative.to_str() else {
                return true;
            };
            !matches!(
                relative,
                "config.rs"
                    | "config/removed_env.rs"
                    | "config/runtime_boundary.rs"
                    | "config/tests.rs"
            )
                && !relative.starts_with("config/tests/")
        })
        .map(|path| {
            fs::read_to_string(&path)
                .map(|source| extract_aegaeon_redis_env_keys(&source))
                .map_err(|err| format!("read {}: {err}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let keys = key_sets
        .into_iter()
        .flatten()
        .filter(|key| !key.starts_with("AEGAEON_TEST_"))
        .collect();
    Ok(keys)
}

fn collect_rust_source_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|err| format!("read dir {}: {err}", dir.display()))? {
        let path = entry
            .map_err(|err| format!("read dir entry {}: {err}", dir.display()))?
            .path();
        if path.is_dir() {
            collect_rust_source_files(&path, files)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn extract_aegaeon_redis_env_keys(source: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let mut cursor = 0;
    while let Some(offset) = source[cursor..].find("AEGAEON_") {
        let start = cursor + offset;
        let end = source.as_bytes()[start..]
            .iter()
            .position(|byte| !is_env_key_byte(*byte))
            .map_or(source.len(), |position| start + position);
        let key = &source[start..end];
        if key.ends_with("REDIS_URL") {
            keys.insert(key.to_owned());
        }
        cursor = end;
    }
    keys
}

fn is_env_key_byte(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
}

fn management_policy_document() -> PolicyDocument {
    PolicyDocument {
        pkce_required: true,
        dcr_enabled: false,
        dcr_everparse_runtime_enabled: false,
        require_state_parameter: true,
        strict_authorize_redirect: true,
        require_client_auth_token: true,
        require_client_auth_par: true,
        require_client_auth_introspection: true,
        require_client_auth_revocation: true,
        sender_constraint: PolicySenderConstraint::Dpop,
        require_scope_subset: true,
        require_audience_match: true,
        retain_refresh_chain: true,
        enforce_refresh_sender_binding: true,
        dpop_strict: true,
        dpop_iat_window_seconds: 300,
        dpop_require_nonce: true,
        dpop_nonce_ttl_seconds: 300,
        require_pushed_authorization_requests: false,
        par_expires_in_seconds: 90,
        device_code_ttl_seconds: crate::config::DEFAULT_DEVICE_CODE_TTL_SECS as u32,
        device_code_poll_interval_seconds: crate::config::DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS
            as u32,
        activation_token_default_ttl_seconds: crate::config::DEFAULT_ACTIVATION_TOKEN_TTL_SECS
            as u32,
        password_reset_token_default_ttl_seconds:
            crate::config::DEFAULT_PASSWORD_RESET_TOKEN_TTL_SECS as u32,
        recovery_token_max_ttl_seconds: crate::config::MAX_RECOVERY_TOKEN_TTL_SECS as u32,
        client_secret_default_expiration_days:
            crate::config::DEFAULT_CLIENT_SECRET_EXPIRATION_DAYS as u32,
        client_secret_max_expiration_days: crate::config::MAX_CLIENT_SECRET_EXPIRATION_DAYS as u32,
        private_key_jwt_enabled: false,
        client_jwt_allowed_algs: vec!["RS256".to_string()],
        client_jwt_require_kid: false,
        jwt_leeway_seconds: 60,
        pkjwt_jti_window_seconds: 300,
        jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN as u32,
        jwks_allow_kid_reuse: false,
        jwks_circuit_open_fails: 3,
        jwks_circuit_reset_seconds: 30,
        jwks_cache_ttl_seconds: 300,
        jwks_cache_gc_interval_seconds: 600,
        jwks_local_cache_max_entries: 4096,
        jwks_http_timeout_seconds: 5,
        jwks_refresh_skew_seconds: 10,
        jwks_shared_state_max_age_seconds: 86_400,
        jwks_max_body_bytes: 64 * 1024,
        jwks_http_retries: 2,
        jwt_bearer_allow_client_subject: false,
        jwt_bearer_jti_window_seconds: 300,
        request_object_jti_ttl_seconds: 600,
        request_object_everparse_runtime_enabled: false,
        jwt_access_tokens_enabled: false,
        jwt_introspection_enabled: false,
        jwt_introspection_exp_seconds: 60,
        authorization_details_types_supported: Vec::new(),
        acr_values_supported: Vec::new(),
        default_acr: None,
        local_password_acr: None,
        dcr_require_pkce_for_public: false,
        dcr_require_pkce_for_confidential: false,
        dcr_require_sender_constrained: false,
        dcr_allowed_sender_methods: vec!["dpop".to_string()],
        ssa_jwt_pem: None,
        ssa_expected_iss: None,
        ssa_expected_aud: None,
        ssa_leeway_seconds: 120,
        oidc_enabled: false,
        oidc_enable_discovery: true,
        oidc_enable_userinfo: true,
        oidc_enable_logout: false,
        oidc_enable_backchannel_logout: false,
        oidc_logout_session_ttl_seconds: 600,
        oidc_backchannel_logout_timeout_seconds: 2,
        oidc_require_nonce: false,
        mtls_enabled: false,
        mtls_base_url: None,
        mtls_alias_par_enabled: false,
        federation_outbound_allowed_domains: Vec::new(),
        upstream_outbound_allowed_domains: Vec::new(),
        federation_entity_cache_ttl_seconds:
            crate::federation::DEFAULT_FEDERATION_ENTITY_CACHE_TTL_SECS as u32,
        federation_trust_chain_cache_ttl_seconds:
            crate::federation::DEFAULT_FEDERATION_TRUST_CHAIN_CACHE_TTL_SECS as u32,
        federation_cache_max_entries: crate::federation::DEFAULT_FEDERATION_CACHE_MAX_ENTRIES
            as u32,
        crypto_profile: "verified".to_string(),
        allowed_signing_algorithms: vec!["RS256".to_string(), "EdDSA".to_string()],
        allowed_grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        access_token_time_to_live_seconds: 3600,
        id_token_time_to_live_seconds: 3600,
        refresh_token_time_to_live_seconds: 2_592_000,
        authorization_code_time_to_live_seconds: 300,
        auth_session_ttl_seconds: 28_800,
        auth_max_sessions: 10_000,
        stepup_challenge_ttl_seconds: 300,
        upstream_auth_ttl_seconds: 300,
        upstream_logout_relay_ttl_seconds: 300,
        upstream_discovery_cache_ttl_seconds:
            crate::upstream::DEFAULT_UPSTREAM_METADATA_CACHE_TTL_SECS as u32,
        upstream_discovery_cache_max_entries: crate::upstream::DEFAULT_UPSTREAM_METADATA_CACHE_MAX_ENTRIES
            as u32,
        upstream_jwks_cache_ttl_seconds: crate::upstream::DEFAULT_UPSTREAM_METADATA_CACHE_TTL_SECS
            as u32,
        upstream_jwks_cache_max_entries: crate::upstream::DEFAULT_UPSTREAM_METADATA_CACHE_MAX_ENTRIES
            as u32,
        cleanup_interval_seconds: 60,
        runtime_config_monitor_interval_seconds: 30,
    }
}
