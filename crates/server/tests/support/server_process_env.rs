const DATABASE_URL_KEY: &str = "AEGAEON_DATABASE_URL";
const TEST_REDIS_URL_KEY: &str = "AEGAEON_TEST_REDIS_URL";
const SHARED_RUNTIME_STORE_ENV_KEYS: &[&str] = &[
    "AEGAEON_AUTH_CODE_REDIS_URL",
    "AEGAEON_AUTH_SESSION_REDIS_URL",
    "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
    "AEGAEON_DEVICE_CODE_REDIS_URL",
    "AEGAEON_DEVICE_CSRF_REDIS_URL",
    "AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL",
    "AEGAEON_DPOP_NONCE_REDIS_URL",
    "AEGAEON_DPOP_REDIS_URL",
    "AEGAEON_JWKS_REDIS_URL",
    "AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL",
    "AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL",
    "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
    "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
    "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
    "AEGAEON_PAR_REDIS_URL",
    "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
    "AEGAEON_STEPUP_REDIS_URL",
    "AEGAEON_TOKEN_STORE_REDIS_URL",
    "AEGAEON_UPSTREAM_AUTH_REDIS_URL",
    "AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL",
];

pub fn database_url_configured() -> bool {
    std::env::var(DATABASE_URL_KEY)
        .ok()
        .is_some_and(|value| database_url_value_configured(&value))
}

pub fn database_url_configured_with(extra_env: &[(&str, &str)]) -> bool {
    extra_env
        .iter()
        .any(|(key, value)| *key == DATABASE_URL_KEY && database_url_value_configured(value))
        || database_url_configured()
}

fn skip_without_database_url_with_env(test_name: &str, extra_env: &[(&str, &str)]) -> bool {
    if database_url_configured_with(extra_env) {
        return false;
    }
    eprintln!(
        "skipping {test_name}: valid postgres:// or postgresql:// AEGAEON_DATABASE_URL is required; non-loopback hosts require sslmode=require, sslmode=verify-ca, or sslmode=verify-full"
    );
    true
}

#[allow(dead_code)]
pub fn skip_without_server_process_runtime(test_name: &str) -> bool {
    skip_without_server_process_runtime_with_env(test_name, &[])
}

pub fn skip_without_server_process_runtime_with_env(
    test_name: &str,
    extra_env: &[(&str, &str)],
) -> bool {
    if skip_without_database_url_with_env(test_name, extra_env) {
        return true;
    }
    if shared_runtime_store_configured_with(extra_env) {
        return false;
    }
    eprintln!(
        "skipping {test_name}: valid rediss:// or loopback redis:// AEGAEON_TEST_REDIS_URL, or complete AEGAEON_*_REDIS_URL runtime-store env is required"
    );
    true
}

pub fn shared_runtime_store_env(extra_env: &[(&str, &str)]) -> Vec<(&'static str, String)> {
    shared_runtime_store_url(extra_env).map_or_else(Vec::new, |url| {
        SHARED_RUNTIME_STORE_ENV_KEYS
            .iter()
            .map(|key| (*key, url.clone()))
            .collect()
    })
}

fn database_url_value_configured(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    url::Url::parse(trimmed).is_ok_and(|url| {
        let Some(host) = url.host_str().filter(|host| !host.trim().is_empty()) else {
            return false;
        };
        if !matches!(url.scheme(), "postgres" | "postgresql") || url.fragment().is_some() {
            return false;
        }
        if is_loopback_host(host) {
            return true;
        }
        let modes = url
            .query_pairs()
            .filter(|(name, _)| name.eq_ignore_ascii_case("sslmode"))
            .map(|(_, value)| value.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        matches!(
            modes.as_slice(),
            [mode] if matches!(mode.as_str(), "require" | "verify-ca" | "verify-full")
        )
    })
}

fn shared_runtime_store_configured_with(extra_env: &[(&str, &str)]) -> bool {
    shared_runtime_store_url(extra_env).is_some()
        || complete_shared_runtime_store_env_configured_with(extra_env)
}

fn shared_runtime_store_url(extra_env: &[(&str, &str)]) -> Option<String> {
    redis_url_from_extra_env(extra_env, TEST_REDIS_URL_KEY).or_else(|| {
        std::env::var(TEST_REDIS_URL_KEY)
            .ok()
            .filter(|value| redis_url_value_configured(value))
    })
}

fn redis_url_from_extra_env(extra_env: &[(&str, &str)], key: &str) -> Option<String> {
    extra_env
        .iter()
        .find_map(|(env_key, value)| (*env_key == key).then_some(*value))
        .filter(|value| redis_url_value_configured(value))
        .map(str::to_owned)
}

fn complete_shared_runtime_store_env_configured_with(extra_env: &[(&str, &str)]) -> bool {
    SHARED_RUNTIME_STORE_ENV_KEYS
        .iter()
        .all(|key| redis_url_from_extra_env(extra_env, key).is_some() || redis_env_configured(key))
}

fn redis_env_configured(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .is_some_and(|value| redis_url_value_configured(&value))
}

fn redis_url_value_configured(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    url::Url::parse(trimmed).is_ok_and(|url| {
        let Some(host) = url.host_str().filter(|host| !host.trim().is_empty()) else {
            return false;
        };
        matches!(url.scheme(), "rediss") || (url.scheme() == "redis" && is_loopback_host(host))
    })
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}
