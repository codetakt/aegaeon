use super::ConfigError;

const REMOVED_DATABASE_MODE_ENV: &str = "AEGAEON_DB_ENABLED";
const REMOVED_CONFIG_AUTHORITY_ENV: &str = "AEGAEON_CONFIG_AUTHORITY";
const REMOVED_RUNTIME_CONFIG_MONITOR_INTERVAL_ENV: &str =
    "AEGAEON_RUNTIME_CONFIG_MONITOR_INTERVAL_SECS";
const REMOVED_RUNTIME_CLIENT_SYNC_INTERVAL_ENV: &str = "AEGAEON_RUNTIME_CLIENT_SYNC_INTERVAL_SECS";
const REMOVED_ADMIN_API_KEY_ENV: &str = "AEGAEON_ADMIN_API_KEY";
const REMOVED_SHARED_CSRF_REDIS_URL_ENV: &str = "AEGAEON_CSRF_REDIS_URL";
const REMOVED_SHARED_RATE_LIMIT_REDIS_URL_ENV: &str = "AEGAEON_RATE_LIMIT_REDIS_URL";
const REMOVED_DCR_EVERPARSE_RUNTIME_ENV: &str = "AEGAEON_DCR_EVERPARSE_RUNTIME";
const REMOVED_REQUEST_OBJECT_EVERPARSE_RUNTIME_ENV: &str =
    "AEGAEON_REQUEST_OBJECT_EVERPARSE_RUNTIME";
const REMOVED_JOSE_HEADER_MAXLEN_ENV: &str = "AEGAEON_JOSE_HEADER_MAXLEN";
const REMOVED_EXPOSE_METRICS_ON_MAIN_ENV: &str = "AEGAEON_EXPOSE_METRICS_ON_MAIN";
const REMOVED_FEDERATION_LIST_RATE_LIMIT_REDIS_URL_ENV: &str =
    "AEGAEON_FEDERATION_LIST_RATE_LIMIT_REDIS_URL";
const REMOVED_FEDERATION_OP_ENV_KEYS: &[&str] = &[
    "AEGAEON_FEDERATION_OP_ENABLED",
    "AEGAEON_FEDERATION_ENTITY_EXP_SECS",
    "AEGAEON_FEDERATION_AUTHORITY_HINTS",
];
const REMOVED_JWKS_STALE_SERVING_ENV_KEYS: &[&str] = &[
    "AEGAEON_JWKS_REQUIRE_PIN_ON_STALE",
    "AEGAEON_JWKS_STALE_IF_ERROR_SECS",
    "AEGAEON_JWKS_STALE_MAX_GENERATIONS",
    "AEGAEON_JWKS_STALE_MEMORY_MAX_SECS",
    "AEGAEON_JWKS_STALE_PREFERENCE",
    "AEGAEON_JWKS_STALE_SHARED_MAX_SECS",
];
const REMOVED_JWKS_ON_DISK_CACHE_ENV_KEYS: &[&str] = &["AEGAEON_JWKS_SHARED_CACHE_PATH"];

pub(super) fn reject_removed_database_runtime_envs() -> Result<(), ConfigError> {
    [
        (
            REMOVED_DATABASE_MODE_ENV,
            "the database mode toggle was removed; PostgreSQL is mandatory",
        ),
        (
            REMOVED_CONFIG_AUTHORITY_ENV,
            "the configuration authority selector was removed; the server always uses the PostgreSQL-backed management runtime",
        ),
        (
            REMOVED_RUNTIME_CONFIG_MONITOR_INTERVAL_ENV,
            "runtime configuration monitor interval is managed by the active database policy",
        ),
        (
            REMOVED_RUNTIME_CLIENT_SYNC_INTERVAL_ENV,
            "runtime client sync interval is managed by the active database policy",
        ),
        (
            REMOVED_ADMIN_API_KEY_ENV,
            "the legacy /admin API key environment variable was removed; use PostgreSQL-backed management sessions and managed API keys",
        ),
        (
            REMOVED_SHARED_CSRF_REDIS_URL_ENV,
            "shared CSRF Redis fallback was removed; configure each CSRF surface Redis URL explicitly",
        ),
        (
            REMOVED_SHARED_RATE_LIMIT_REDIS_URL_ENV,
            "shared rate-limit Redis fallback was removed; configure each rate-limit surface Redis URL explicitly",
        ),
        (
            REMOVED_DCR_EVERPARSE_RUNTIME_ENV,
            "DCR EverParse runtime self-check policy is managed by the active database policy",
        ),
        (
            REMOVED_REQUEST_OBJECT_EVERPARSE_RUNTIME_ENV,
            "Request Object EverParse runtime self-check policy is managed by the active database policy",
        ),
        (
            REMOVED_JOSE_HEADER_MAXLEN_ENV,
            "JOSE protected header length is managed by the active database policy",
        ),
        (
            REMOVED_EXPOSE_METRICS_ON_MAIN_ENV,
            "main-server metrics exposure was removed; use the authenticated management metrics endpoint",
        ),
        (
            REMOVED_FEDERATION_LIST_RATE_LIMIT_REDIS_URL_ENV,
            "public OpenID Federation OP list endpoint was removed from the supported runtime",
        ),
    ]
    .into_iter()
    .try_for_each(|(key, reason)| reject_removed_env(key, reason))?;

    REMOVED_JWKS_STALE_SERVING_ENV_KEYS
        .iter()
        .try_for_each(|key| {
            reject_removed_env(
                key,
                "JWKS stale serving was removed from the supported runtime; no startup or database policy exists for this setting",
            )
        })?;

    REMOVED_FEDERATION_OP_ENV_KEYS
        .iter()
        .try_for_each(|key| {
            reject_removed_env(
                key,
                "public OpenID Federation OP publication was removed from the supported server runtime; no startup or database policy exists for this setting",
            )
        })?;

    REMOVED_JWKS_ON_DISK_CACHE_ENV_KEYS
        .iter()
        .try_for_each(|key| {
            reject_removed_env(
                key,
                "the on-disk JWKS body cache was removed; use AEGAEON_JWKS_REDIS_URL for shared JWKS runtime state",
            )
        })
}

fn reject_removed_env(key: &'static str, reason: &'static str) -> Result<(), ConfigError> {
    match std::env::var(key) {
        Ok(value) => Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value,
            reason: reason.to_string(),
        }),
        Err(std::env::VarError::NotPresent) => Ok(()),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicode {
            key: key.to_string(),
        }),
    }
}
