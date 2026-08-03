use super::ConfigError;
use ipnet::IpNet;
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn try_env_flag(key: &str, default: bool) -> Result<bool, ConfigError> {
    match env::var(key) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(ConfigError::InvalidBoolean {
                key: key.to_string(),
                value,
            }),
        },
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicode {
            key: key.to_string(),
        }),
    }
}

pub(crate) fn try_required_env_flag(
    key: &'static str,
    required: bool,
    reason: &'static str,
) -> Result<bool, ConfigError> {
    let value = try_env_flag(key, required)?;
    if value == required {
        return Ok(value);
    }

    Err(ConfigError::InvalidValue {
        key: key.to_string(),
        value: env::var(key).unwrap_or_else(|_| "<non-unicode>".to_string()),
        reason: reason.to_string(),
    })
}

pub fn env_flag(key: &str, default: bool) -> Result<bool, ConfigError> {
    try_env_flag(key, default)
}

pub fn try_env_num<T>(key: &str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(key) {
        Ok(value) => value
            .trim()
            .parse::<T>()
            .map_err(|err| ConfigError::InvalidNumber {
                key: key.to_string(),
                value,
                reason: err.to_string(),
            }),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicode {
            key: key.to_string(),
        }),
    }
}

pub fn env_num<T>(key: &str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    try_env_num(key, default)
}

pub fn try_env_num_with<T>(
    key: &str,
    default: T,
    is_valid: impl FnOnce(T) -> bool,
    expectation: &str,
) -> Result<T, ConfigError>
where
    T: Copy + std::fmt::Display + std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = try_env_num(key, default)?;
    if !is_valid(value) {
        return Err(ConfigError::InvalidNumberRange {
            key: key.to_string(),
            value: value.to_string(),
            expectation: expectation.to_string(),
        });
    }
    Ok(value)
}

pub fn env_num_with<T>(
    key: &str,
    default: T,
    is_valid: impl FnOnce(T) -> bool,
    expectation: &str,
) -> Result<T, ConfigError>
where
    T: Copy + std::fmt::Display + std::str::FromStr,
    T::Err: std::fmt::Display,
{
    try_env_num_with(key, default, is_valid, expectation)
}

pub fn try_env_optional_string(key: &str) -> Result<Option<String>, ConfigError> {
    match env::var(key) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicode {
            key: key.to_string(),
        }),
    }
}

pub fn validate_public_base_url_value(key: &str, base_url: &str) -> Result<(), ConfigError> {
    let parsed = url::Url::parse(base_url).map_err(|_| ConfigError::InvalidValue {
        key: key.to_string(),
        value: base_url.to_string(),
        reason: "must be an absolute URL".to_string(),
    })?;
    let Some(host) = parsed.host_str() else {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: base_url.to_string(),
            reason: "must include a host".to_string(),
        });
    };
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: base_url.to_string(),
            reason: "must not include userinfo, query, or fragment".to_string(),
        });
    }
    if parsed.scheme() == "http" && crate::util::is_loopback_host(host) {
        return Ok(());
    }
    if crate::ssrf::validate_url_host_not_non_routable_literal(&parsed).is_err() {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: base_url.to_string(),
            reason: "must not target non-routable hosts except loopback http in local development"
                .to_string(),
        });
    }
    match parsed.scheme() {
        "https" => Ok(()),
        _ => Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: base_url.to_string(),
            reason: "must use https except for loopback http in local development".to_string(),
        }),
    }
}

pub fn try_env_csv_list(key: &str) -> Result<Vec<String>, ConfigError> {
    Ok(try_env_optional_string(key)?.map_or_else(Vec::new, |raw| {
        raw.split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    }))
}

pub(super) fn env_key_is_present(key: &str) -> Result<bool, ConfigError> {
    match env::var(key) {
        Ok(_) => Ok(true),
        Err(env::VarError::NotPresent) => Ok(false),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicode {
            key: key.to_string(),
        }),
    }
}

pub(super) fn try_env_ipnet_list(key: &str) -> Result<Option<Vec<IpNet>>, ConfigError> {
    let Some(value) = try_env_optional_string(key)? else {
        return Ok(None);
    };
    let entries = value
        .split(',')
        .try_fold(Vec::new(), |mut entries, entry| {
            if let Some(parsed) = try_parse_ipnet_entry(key, entry)? {
                entries.push(parsed);
            }
            Ok::<_, ConfigError>(entries)
        })?;
    Ok(Some(entries))
}

fn try_parse_ipnet_entry(key: &str, item: &str) -> Result<Option<IpNet>, ConfigError> {
    let trimmed = item.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Ok(Some(net));
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(Some(IpNet::from(ip)));
    }
    Err(ConfigError::InvalidIpNet {
        key: key.to_string(),
        entry: trimmed.to_string(),
    })
}

pub(super) fn default_trusted_proxies() -> Vec<IpNet> {
    vec![
        IpNet::from(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        IpNet::from(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ]
}
