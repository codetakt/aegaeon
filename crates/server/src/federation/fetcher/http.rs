use super::super::{
    verify_entity_configuration, verify_entity_statement, EntityStatement, FederationError, JwkSet,
};
use super::transport::FederationHttpClient;
use super::types::{
    FederationFetchFuture, FederationFetcher, FetchedEntityConfiguration,
    FetchedSubordinateStatement,
};
use super::url_policy::{
    entity_configuration_url, host_matches_allowlist,
    normalize_federation_outbound_allowed_domains, subordinate_statement_url, validate_entity_url,
};

/// HTTP-based [`FederationFetcher`] using async `reqwest`.
///
/// Hardened against SSRF (C-3, P8-SSRF-1, P8-SSRF-2):
/// - HTTPS-only (reqwest `.https_only(true)`)
/// - 10s request timeout, 5s connect timeout
/// - Custom redirect policy: max 3 redirects, each validated against domain
///   allowlist and private IP ranges (P8-SSRF-2)
/// - Pre-flight DNS resolution rejects non-routable IPs: loopback, RFC 1918,
///   link-local, CGNAT, documentation, benchmarking, reserved (P8-SSRF-1)
/// - Response size limit (256 KB)
/// - Optional domain allowlist
pub struct HttpFederationFetcher {
    transport: FederationHttpClient,
    allowed_domains: Option<Vec<String>>,
}

impl HttpFederationFetcher {
    /// Create a fetcher with SSRF-safe HTTP client settings.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError::Fetch`] if the HTTP client cannot be built.
    pub fn try_new() -> Result<Self, FederationError> {
        Self::try_build(None)
    }

    fn try_build(allowed_domains: Option<Vec<String>>) -> Result<Self, FederationError> {
        let transport = FederationHttpClient::try_new(allowed_domains.clone())?;
        Ok(Self {
            transport,
            allowed_domains,
        })
    }

    /// Create a fetcher with domain allowlist.
    ///
    /// When set, only `entity_ids` whose host matches one of the allowed domains will be fetched.
    /// Redirect targets are also validated against the allowlist and private IP ranges.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError::Fetch`] if the HTTP client cannot be built.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the public constructor consistently accepts owned configuration"
    )]
    pub fn try_with_allowed_domains(domains: Vec<String>) -> Result<Self, FederationError> {
        Self::try_build(Some(normalize_federation_outbound_allowed_domains(
            &domains,
        )?))
    }

    /// Create a fetcher using an operator-managed domain allowlist when present.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError::Fetch`] if the HTTP client cannot be built, or
    /// [`FederationError::Validation`] when the allowlist contains invalid domains.
    pub fn try_with_optional_allowed_domains(domains: &[String]) -> Result<Self, FederationError> {
        let domains = normalize_federation_outbound_allowed_domains(domains)?;
        if domains.is_empty() {
            Self::try_new()
        } else {
            Self::try_build(Some(domains))
        }
    }

    /// Validate that the `entity_id`'s host is in the domain allowlist (if set).
    pub(in crate::federation) fn validate_domain(
        &self,
        entity_id: &str,
    ) -> Result<(), FederationError> {
        if let Some(ref allowed) = self.allowed_domains {
            let parsed = validate_entity_url(entity_id)?;
            let host = parsed.host_str().unwrap_or("");
            if !host_matches_allowlist(host, allowed) {
                return Err(FederationError::Validation(format!(
                    "entity_id host '{host}' is not in the allowed domain list"
                )));
            }
        }
        Ok(())
    }

    fn validate_fetch_url_domain(&self, url: &str) -> Result<(), FederationError> {
        let Some(ref allowed) = self.allowed_domains else {
            return Ok(());
        };
        let parsed = url::Url::parse(url)
            .map_err(|_| FederationError::Validation("invalid federation fetch URL".into()))?;
        let host = parsed.host_str().unwrap_or("");
        if host_matches_allowlist(host, allowed) {
            Ok(())
        } else {
            Err(FederationError::Validation(format!(
                "federation fetch endpoint host '{host}' is not in the allowed domain list"
            )))
        }
    }

    /// Fetch an entity configuration JWS without parsing it.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when allowlist validation, URL construction, or fetching fails.
    pub async fn fetch_entity_configuration_jws(
        &self,
        entity_id: &str,
    ) -> Result<String, FederationError> {
        self.validate_domain(entity_id)?;
        let url = entity_configuration_url(entity_id)?;
        self.transport.fetch_text(&url).await
    }
}

impl FederationFetcher for HttpFederationFetcher {
    fn fetch_entity_configuration<'a>(
        &'a self,
        entity_id: &'a str,
    ) -> FederationFetchFuture<'a, EntityStatement> {
        Box::pin(async move {
            let jws = self.fetch_entity_configuration_jws(entity_id).await?;
            verify_entity_configuration(&jws)
        })
    }

    fn fetch_entity_configuration_with_jws<'a>(
        &'a self,
        entity_id: &'a str,
    ) -> FederationFetchFuture<'a, FetchedEntityConfiguration> {
        Box::pin(async move {
            let jws = self.fetch_entity_configuration_jws(entity_id).await?;
            let statement = verify_entity_configuration(&jws)?;
            Ok(FetchedEntityConfiguration::with_jws(statement, jws))
        })
    }

    fn fetch_subordinate_statement<'a>(
        &'a self,
        authority_entity_id: &'a str,
        authority_config: &'a EntityStatement,
        subordinate_entity_id: &'a str,
        issuer_jwks: &'a JwkSet,
    ) -> FederationFetchFuture<'a, EntityStatement> {
        Box::pin(async move {
            self.validate_domain(authority_entity_id)?;
            let url = subordinate_statement_url(
                authority_entity_id,
                authority_config,
                subordinate_entity_id,
            )?;
            self.validate_fetch_url_domain(&url)?;
            let jws = self.transport.fetch_text(&url).await?;
            verify_entity_statement(&jws, issuer_jwks)
        })
    }

    fn fetch_subordinate_statement_with_jws<'a>(
        &'a self,
        authority_entity_id: &'a str,
        authority_config: &'a EntityStatement,
        subordinate_entity_id: &'a str,
        issuer_jwks: &'a JwkSet,
    ) -> FederationFetchFuture<'a, FetchedSubordinateStatement> {
        Box::pin(async move {
            self.validate_domain(authority_entity_id)?;
            let url = subordinate_statement_url(
                authority_entity_id,
                authority_config,
                subordinate_entity_id,
            )?;
            self.validate_fetch_url_domain(&url)?;
            let jws = self.transport.fetch_text(&url).await?;
            let statement = verify_entity_statement(&jws, issuer_jwks)?;
            Ok(FetchedSubordinateStatement::with_jws(statement, jws))
        })
    }
}
