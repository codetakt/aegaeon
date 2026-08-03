use super::{try_env_num_with, try_env_optional_string, ConfigError};
use url::Url;

#[derive(Clone, Debug)]
pub struct DatabaseConfig {
    pub url: PostgresDatabaseUrl,
    pub max_connections: u32,
    pub acquire_timeout_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgresDatabaseUrl(String);

impl PostgresDatabaseUrl {
    fn from_env_value(key: &str, url: String) -> Result<Self, ConfigError> {
        validate_required_database_url(key, url).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(test)]
    pub fn for_local_harness() -> Self {
        Self("postgres://aegaeon:test@127.0.0.1/aegaeon_test".to_string())
    }
}

#[cfg(test)]
impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: PostgresDatabaseUrl::for_local_harness(),
            max_connections: 10,
            acquire_timeout_secs: 5,
        }
    }
}

impl DatabaseConfig {
    pub fn try_from_env() -> Result<Self, ConfigError> {
        let url = required_database_url_from_env()?;
        Ok(Self {
            url,
            max_connections: try_env_num_with(
                "AEGAEON_DB_MAX_CONNECTIONS",
                10u32,
                |value| value > 0,
                "a positive connection count",
            )?,
            acquire_timeout_secs: try_env_num_with(
                "AEGAEON_DB_ACQUIRE_TIMEOUT_SECS",
                5u64,
                |value| value > 0,
                "a positive number of seconds",
            )?,
        })
    }

    #[must_use]
    pub fn url(&self) -> &str {
        self.url.as_str()
    }
}

fn required_database_url_from_env() -> Result<PostgresDatabaseUrl, ConfigError> {
    match try_env_optional_string("AEGAEON_DATABASE_URL")? {
        Some(url) => PostgresDatabaseUrl::from_env_value("AEGAEON_DATABASE_URL", url),
        None => Err(ConfigError::InvalidValue {
            key: "AEGAEON_DATABASE_URL".to_string(),
            value: "<unset>".to_string(),
            reason: "PostgreSQL is required; set AEGAEON_DATABASE_URL".to_string(),
        }),
    }
}

fn validate_required_database_url(key: &str, url: String) -> Result<String, ConfigError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: url,
            reason: "PostgreSQL is required; database URL must not be empty".to_string(),
        });
    }

    let parsed = Url::parse(trimmed).map_err(|_| ConfigError::InvalidValue {
        key: key.to_string(),
        value: "<redacted>".to_string(),
        reason:
            "PostgreSQL is required; database URL must be a valid postgres:// or postgresql:// URL"
                .to_string(),
    })?;

    if !matches!(parsed.scheme(), "postgres" | "postgresql") {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: parsed.scheme().to_string(),
            reason:
                "PostgreSQL is required; database URL scheme must be postgres:// or postgresql://"
                    .to_string(),
        });
    }

    reject_database_url_fragment(key, &parsed)?;
    validate_database_url_transport_policy(key, &parsed)?;

    Ok(trimmed.to_string())
}

fn reject_database_url_fragment(key: &str, parsed: &Url) -> Result<(), ConfigError> {
    if parsed.fragment().is_none() {
        return Ok(());
    }
    Err(ConfigError::InvalidValue {
        key: key.to_string(),
        value: "<redacted>".to_string(),
        reason: "PostgreSQL database URL must not include a fragment".to_string(),
    })
}

fn validate_database_url_transport_policy(key: &str, parsed: &Url) -> Result<(), ConfigError> {
    let Some(host) = parsed.host_str().filter(|host| !host.trim().is_empty()) else {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: "<redacted>".to_string(),
            reason: "PostgreSQL database URL must include an explicit host".to_string(),
        });
    };

    if crate::util::is_loopback_host(host) {
        return Ok(());
    }

    match postgres_sslmode(parsed) {
        Ok(Some(mode)) if postgres_sslmode_is_strong(&mode) => Ok(()),
        Ok(Some(mode)) => Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: mode,
            reason: "non-loopback PostgreSQL database URLs must use sslmode=require, sslmode=verify-ca, or sslmode=verify-full".to_string(),
        }),
        Ok(None) => Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: "<redacted>".to_string(),
            reason: "non-loopback PostgreSQL database URLs must include sslmode=require, sslmode=verify-ca, or sslmode=verify-full".to_string(),
        }),
        Err(reason) => Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: "<redacted>".to_string(),
            reason,
        }),
    }
}

fn postgres_sslmode(parsed: &Url) -> Result<Option<String>, String> {
    let mut modes = parsed
        .query_pairs()
        .filter(|(name, _)| name.eq_ignore_ascii_case("sslmode"))
        .map(|(_, value)| value.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    match modes.len() {
        0 => Ok(None),
        1 => Ok(modes.pop()),
        _ => Err("PostgreSQL database URL must include at most one sslmode parameter".to_string()),
    }
}

fn postgres_sslmode_is_strong(mode: &str) -> bool {
    matches!(mode, "require" | "verify-ca" | "verify-full")
}
