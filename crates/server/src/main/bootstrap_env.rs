use anyhow::Result;
use url::Url;

const RUNTIME_ISSUER_HOST_ENV: &str = "AEGAEON_RUNTIME_ISSUER_HOST";
const REMOVED_PUBLIC_BASE_URL_ENV: &str = "BASE_URL";

#[cfg(test)]
pub(super) fn env_flag(key: &str, default: bool) -> Result<bool> {
    match std::env::var(key) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(anyhow::anyhow!(
                "{key} must be a boolean: expected 1/0, true/false, yes/no, or on/off (got {value:?})"
            )),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(anyhow::anyhow!("{key} must be valid Unicode"))
        }
    }
}

#[cfg(test)]
pub(super) fn env_num<T>(key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    env_num_impl(key, default)
}

#[cfg(test)]
fn env_num_impl<T>(key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(value) => value
            .trim()
            .parse()
            .map_err(|err| anyhow::anyhow!("{key} has invalid numeric value {value:?}: {err}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(anyhow::anyhow!("{key} must be valid Unicode"))
        }
    }
}

#[cfg(test)]
pub(super) fn env_optional_trimmed(key: &str) -> Result<Option<String>> {
    match std::env::var(key) {
        Ok(value) => {
            let trimmed = value.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(anyhow::anyhow!("{key} must be valid Unicode"))
        }
    }
}

#[cfg(test)]
pub(super) fn env_optional_non_empty(key: &str) -> Result<Option<String>> {
    match std::env::var(key) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(anyhow::anyhow!("{key} must not be empty when set"))
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(anyhow::anyhow!("{key} must be valid Unicode"))
        }
    }
}

pub(super) fn runtime_issuer_host_from_env() -> Result<String> {
    reject_removed_public_base_url_env()?;
    let issuer_host = match std::env::var("AEGAEON_RUNTIME_ISSUER_HOST") {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(anyhow::anyhow!(
                    "{RUNTIME_ISSUER_HOST_ENV} must not be empty"
                ));
            } else {
                trimmed.to_string()
            }
        }
        Err(std::env::VarError::NotPresent) => {
            return Err(anyhow::anyhow!(
                "{RUNTIME_ISSUER_HOST_ENV} is required to select the active management-database runtime environment"
            ));
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(anyhow::anyhow!(
                "{RUNTIME_ISSUER_HOST_ENV} must be valid Unicode"
            ));
        }
    };
    normalize_runtime_issuer_host(&issuer_host).ok_or_else(|| {
        anyhow::anyhow!(
            "{RUNTIME_ISSUER_HOST_ENV} must be a canonical issuer host without scheme, path, query, fragment, or userinfo"
        )
    })
}

fn reject_removed_public_base_url_env() -> Result<()> {
    match std::env::var("BASE_URL") {
        Ok(value) => Err(anyhow::anyhow!(
            "{REMOVED_PUBLIC_BASE_URL_ENV} no longer configures the server runtime; set {RUNTIME_ISSUER_HOST_ENV} and manage the public issuer URL in the database (got {value:?})"
        )),
        Err(std::env::VarError::NotPresent) => Ok(()),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow::anyhow!(
            "{REMOVED_PUBLIC_BASE_URL_ENV} must be valid Unicode"
        )),
    }
}

fn normalize_runtime_issuer_host(issuer_host: &str) -> Option<String> {
    let trimmed = issuer_host.trim();
    if trimmed.is_empty()
        || trimmed.contains("://")
        || trimmed.contains('/')
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return None;
    }

    let parsed = Url::parse(&format!("https://{trimmed}")).ok()?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return None;
    }
    canonical_url_host_port(&parsed)
}

fn canonical_url_host_port(url: &Url) -> Option<String> {
    let host = match url.host()? {
        url::Host::Domain(host) => host.to_ascii_lowercase(),
        url::Host::Ipv4(host) => host.to_string(),
        url::Host::Ipv6(host) => format!("[{host}]"),
    };
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}
