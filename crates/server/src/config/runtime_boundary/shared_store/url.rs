use crate::config::{try_env_optional_string, ConfigError};
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedisStoreUrl {
    raw: String,
    endpoint: RedisStoreEndpointIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RedisStoreEndpointIdentity {
    scheme: String,
    host: String,
    port: u16,
    database: u32,
}

impl RedisStoreUrl {
    pub fn from_env_value(key: &str, value: String) -> Result<Self, ConfigError> {
        let raw = validate_shared_redis_store_url(key, value)?;
        let endpoint = RedisStoreEndpointIdentity::from_raw(key, &raw)?;
        Ok(Self { raw, endpoint })
    }

    pub fn optional_from_env(key: &str) -> Result<Option<Self>, ConfigError> {
        try_env_optional_string(key)?
            .map(|value| Self::from_env_value(key, value))
            .transpose()
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    #[must_use]
    pub(crate) fn references_same_endpoint(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint
    }
}

#[must_use]
pub(crate) fn redis_store_urls_reference_same_endpoint(left: &str, right: &str) -> bool {
    let left = RedisStoreEndpointIdentity::from_raw("redis_store_url", left);
    let right = RedisStoreEndpointIdentity::from_raw("redis_store_url", right);
    matches!((left, right), (Ok(left), Ok(right)) if left == right)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRuntimeStoreUrl {
    env_key: String,
    url: RedisStoreUrl,
}

impl SharedRuntimeStoreUrl {
    pub(super) fn new(env_key: &str, url: RedisStoreUrl) -> Self {
        Self {
            env_key: env_key.to_string(),
            url,
        }
    }

    #[must_use]
    pub fn env_key(&self) -> &str {
        &self.env_key
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    #[must_use]
    pub fn into_parts(self) -> (String, RedisStoreUrl) {
        (self.env_key, self.url)
    }
}

fn validate_shared_redis_store_url(key: &str, value: String) -> Result<String, ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value,
            reason: "shared Redis store URL must not be empty".to_string(),
        });
    }

    let parsed = Url::parse(trimmed).map_err(|_| ConfigError::InvalidValue {
        key: key.to_string(),
        value: "<redacted>".to_string(),
        reason: "shared Redis store URL must be a valid rediss:// URL or loopback redis:// URL"
            .to_string(),
    })?;

    if !matches!(parsed.scheme(), "redis" | "rediss") {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: parsed.scheme().to_string(),
            reason: "shared Redis store URL scheme must be rediss:// or loopback redis://"
                .to_string(),
        });
    }

    let Some(host) = parsed.host_str().filter(|host| !host.trim().is_empty()) else {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: "<redacted>".to_string(),
            reason: "shared Redis store URL must include a host".to_string(),
        });
    };

    reject_redis_query_or_fragment(key, &parsed)?;

    if parsed.scheme() == "redis" && !crate::util::is_loopback_host(host) {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: "redis://<non-loopback>".to_string(),
            reason: "plain redis:// shared store URLs are limited to loopback development endpoints; use rediss:// for non-loopback shared Redis".to_string(),
        });
    }

    Ok(trimmed.to_string())
}

impl RedisStoreEndpointIdentity {
    fn from_raw(key: &str, value: &str) -> Result<Self, ConfigError> {
        let parsed = Url::parse(value).map_err(|_| ConfigError::InvalidValue {
            key: key.to_string(),
            value: "<redacted>".to_string(),
            reason: "shared Redis store URL must be a valid rediss:// URL or loopback redis:// URL"
                .to_string(),
        })?;
        if !matches!(parsed.scheme(), "redis" | "rediss") {
            return Err(ConfigError::InvalidValue {
                key: key.to_string(),
                value: parsed.scheme().to_string(),
                reason: "shared Redis store URL scheme must be rediss:// or loopback redis://"
                    .to_string(),
            });
        }
        let Some(host) = parsed.host_str().filter(|host| !host.trim().is_empty()) else {
            return Err(ConfigError::InvalidValue {
                key: key.to_string(),
                value: "<redacted>".to_string(),
                reason: "shared Redis store URL must include a host".to_string(),
            });
        };
        reject_redis_query_or_fragment(key, &parsed)?;
        if parsed.scheme() == "redis" && !crate::util::is_loopback_host(host) {
            return Err(ConfigError::InvalidValue {
                key: key.to_string(),
                value: "redis://<non-loopback>".to_string(),
                reason: "plain redis:// shared store URLs are limited to loopback development endpoints; use rediss:// for non-loopback shared Redis".to_string(),
            });
        }
        Ok(Self {
            scheme: parsed.scheme().to_ascii_lowercase(),
            host: host.to_ascii_lowercase(),
            port: parsed.port().unwrap_or(6379),
            database: redis_database_index(key, &parsed)?,
        })
    }
}

fn reject_redis_query_or_fragment(key: &str, parsed: &Url) -> Result<(), ConfigError> {
    if parsed.query().is_none() && parsed.fragment().is_none() {
        return Ok(());
    }
    Err(ConfigError::InvalidValue {
        key: key.to_string(),
        value: "<redacted>".to_string(),
        reason: "shared Redis store URL must not include query or fragment components".to_string(),
    })
}

fn redis_database_index(key: &str, parsed: &Url) -> Result<u32, ConfigError> {
    let path = parsed.path();
    if path.is_empty() || path == "/" {
        return Ok(0);
    }
    let Some(database) = path.strip_prefix('/') else {
        return Err(redis_database_path_error(key));
    };
    if database.contains('/') {
        return Err(redis_database_path_error(key));
    }
    database
        .parse::<u32>()
        .map_err(|_| redis_database_path_error(key))
}

fn redis_database_path_error(key: &str) -> ConfigError {
    ConfigError::InvalidValue {
        key: key.to_string(),
        value: "<redacted>".to_string(),
        reason: "shared Redis store URL path must be empty or a numeric database path such as /0"
            .to_string(),
    }
}

#[cfg(test)]
mod tests;
