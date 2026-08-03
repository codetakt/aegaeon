use super::super::FederationError;

/// Maximum entity statement response size (256 KB).
const MAX_ENTITY_STATEMENT_SIZE: usize = 256 * 1024;

pub(in crate::federation) fn ensure_fetch_status_success(
    status: reqwest::StatusCode,
) -> Result<(), FederationError> {
    if status.is_success() {
        return Ok(());
    }
    Err(FederationError::Fetch(format!(
        "entity statement endpoint returned HTTP {}",
        status.as_u16()
    )))
}

pub(super) struct FederationHttpClient {
    client: reqwest::Client,
}

impl FederationHttpClient {
    pub(super) fn try_new(allowed_domains: Option<Vec<String>>) -> Result<Self, FederationError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .dns_resolver(std::sync::Arc::new(crate::ssrf::NonRoutableDnsResolver))
            .redirect(crate::ssrf::build_redirect_policy(allowed_domains))
            .https_only(true)
            .build()
            .map_err(|err| {
                FederationError::Fetch(format!("failed to build federation HTTP client: {err}"))
            })?;
        Ok(Self { client })
    }

    /// Fetch a URL and return the body, enforcing the size limit.
    ///
    /// Performs pre-flight DNS resolution and private IP validation (P8-SSRF-1)
    /// before making the HTTP request.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when SSRF validation, HTTP transport, response decoding, or the
    /// configured size limit check fails.
    pub(super) async fn fetch_text(&self, url: &str) -> Result<String, FederationError> {
        crate::ssrf::validate_url_not_private(url).map_err(|e| match e {
            crate::ssrf::SsrfError::DnsResolutionFailed(msg) => FederationError::Fetch(msg),
            crate::ssrf::SsrfError::NonRoutableIp(msg)
            | crate::ssrf::SsrfError::InvalidUrl(msg) => FederationError::Validation(msg),
        })?;

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| FederationError::Fetch(e.to_string()))?;
        ensure_fetch_status_success(response.status())?;

        let bytes = crate::outbound_http::read_response_body_limited(
            response,
            MAX_ENTITY_STATEMENT_SIZE,
        )
        .await
        .map_err(|err| match err {
            crate::outbound_http::BoundedBodyError::TooLarge { observed, .. } => {
                FederationError::Validation(format!(
                    "entity statement response too large: {observed} bytes (max {MAX_ENTITY_STATEMENT_SIZE})"
                ))
            }
            other => FederationError::Fetch(other.to_string()),
        })?;

        String::from_utf8(bytes)
            .map_err(|e| FederationError::Fetch(format!("response is not valid UTF-8: {e}")))
    }
}
