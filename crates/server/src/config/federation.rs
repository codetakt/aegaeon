use super::ConfigError;

#[derive(Clone, Copy, Debug)]
pub struct UpstreamRuntimeConfig<'a> {
    auth_ttl_secs: u64,
    logout_relay_ttl_secs: u64,
    outbound_allowed_domains: &'a [String],
}

impl<'a> UpstreamRuntimeConfig<'a> {
    pub(super) const fn new(
        auth_ttl_secs: u64,
        logout_relay_ttl_secs: u64,
        outbound_allowed_domains: &'a [String],
    ) -> Self {
        Self {
            auth_ttl_secs,
            logout_relay_ttl_secs,
            outbound_allowed_domains,
        }
    }

    #[must_use]
    pub const fn auth_ttl_secs(self) -> u64 {
        self.auth_ttl_secs
    }

    #[must_use]
    pub const fn logout_relay_ttl_secs(self) -> u64 {
        self.logout_relay_ttl_secs
    }

    #[must_use]
    pub const fn outbound_allowed_domains(self) -> &'a [String] {
        self.outbound_allowed_domains
    }
}

pub(super) fn normalize_federation_outbound_allowed_domains(
    domains: &[String],
) -> Result<Vec<String>, ConfigError> {
    crate::federation::normalize_federation_outbound_allowed_domains(domains).map_err(|error| {
        ConfigError::InvalidValue {
            key: "federation_outbound_allowed_domains".to_string(),
            value: domains.join(","),
            reason: error.to_string(),
        }
    })
}
