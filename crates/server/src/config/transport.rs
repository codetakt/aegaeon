use ipnet::IpNet;
use std::env;

use super::env_vars::{default_trusted_proxies, try_env_ipnet_list};
use super::{try_env_flag, try_env_num_with, ConfigError};
use crate::policy::{SecurityPolicy, SenderConstraint};

#[derive(Clone, Debug)]
pub struct TransportSecurityConfig {
    pub trusted_proxies: Vec<IpNet>,
    pub require_tls_proxy: bool,
    pub max_proxy_hops: u8,
    pub require_proxy_mtls: bool,
    pub log_forwarded_values: bool,
}

impl Default for TransportSecurityConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: default_trusted_proxies(),
            require_tls_proxy: false,
            max_proxy_hops: 1,
            require_proxy_mtls: false,
            log_forwarded_values: false,
        }
    }
}

impl TransportSecurityConfig {
    pub fn try_from_env() -> Result<Self, ConfigError> {
        reject_removed_secure_proto_env()?;
        let trusted_proxies = match try_env_ipnet_list("AEGAEON_TRUSTED_PROXIES")? {
            Some(list) if !list.is_empty() => list,
            _ => default_trusted_proxies(),
        };

        let require_tls_proxy = try_env_flag("AEGAEON_REQUIRE_TLS_PROXY", false)?;

        let require_proxy_mtls = try_env_flag("AEGAEON_REQUIRE_MTLS_FROM_PROXY", false)?;
        let require_tls_proxy = require_tls_proxy || require_proxy_mtls;

        Ok(Self {
            trusted_proxies,
            require_tls_proxy,
            max_proxy_hops: try_env_num_with(
                "AEGAEON_ALLOW_PROXY_CHAIN_LENGTH",
                1u8,
                |value| value >= 1,
                "a value in 1..=255",
            )?,
            require_proxy_mtls,
            log_forwarded_values: try_env_flag("AEGAEON_FORWARD_HEADER_LOG_VALUES", false)?,
        })
    }

    pub fn apply_security_policy(&mut self, policy: &SecurityPolicy) {
        if policy.enforce_trusted_proxy() || policy.sender_constrained == SenderConstraint::Mtls {
            self.require_tls_proxy = true;
        }
        if policy.sender_constrained == SenderConstraint::Mtls {
            self.require_proxy_mtls = true;
        }
        if self.trusted_proxies.is_empty() && self.require_tls_proxy {
            self.trusted_proxies = default_trusted_proxies();
        }
    }
}

fn reject_removed_secure_proto_env() -> Result<(), ConfigError> {
    match env::var("AEGAEON_ENFORCE_SECURE_PROTO") {
        Ok(value) => Err(ConfigError::InvalidValue {
            key: "AEGAEON_ENFORCE_SECURE_PROTO".to_string(),
            value,
            reason: "this legacy TLS-proxy fallback was removed; use AEGAEON_REQUIRE_TLS_PROXY"
                .to_string(),
        }),
        Err(env::VarError::NotPresent) => Ok(()),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicode {
            key: "AEGAEON_ENFORCE_SECURE_PROTO".to_string(),
        }),
    }
}
