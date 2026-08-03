use super::super::{normalize_issuer, UPSTREAM_MAX_BODY_BYTES};
use super::{validate_upstream_metadata_endpoint, validate_upstream_outbound_url};
use reqwest::Client;

use crate::oidc::OidcDiscovery;
use crate::upstream::NonAuthoritativeMetadataCache;
use crate::{oauth_profile, util};

async fn fetch_upstream_discovery(
    client: &Client,
    issuer: &str,
    allowed_domains: &[String],
) -> Result<OidcDiscovery, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    validate_upstream_outbound_url(&url, "upstream discovery endpoint", allowed_domains)?;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|_| "failed to fetch upstream discovery".to_string())?;
    if !response.status().is_success() {
        return Err(format!("upstream discovery returned {}", response.status()));
    }
    let body = crate::outbound_http::read_response_body_limited(response, UPSTREAM_MAX_BODY_BYTES)
        .await
        .map_err(|err| match err {
            crate::outbound_http::BoundedBodyError::TooLarge { .. } => {
                "upstream discovery response too large".to_string()
            }
            other => format!("failed to read upstream discovery: {other}"),
        })?;
    parse_upstream_discovery_body(&body)
}

pub(in crate::web) fn parse_upstream_discovery_body(body: &[u8]) -> Result<OidcDiscovery, String> {
    util::deserialize_json_without_duplicate_object_keys::<OidcDiscovery>(body).map_err(|err| {
        match err {
            util::JsonAdmissionError::DuplicateKey => {
                "upstream discovery response contains duplicate object keys".to_string()
            }
            util::JsonAdmissionError::InvalidJson | util::JsonAdmissionError::TrailingBytes => {
                "upstream discovery response invalid".to_string()
            }
        }
    })
}

pub(in crate::web) async fn fetch_upstream_discovery_cached(
    client: &Client,
    issuer: &str,
    cache: &NonAuthoritativeMetadataCache<OidcDiscovery>,
    allowed_domains: &[String],
) -> Result<OidcDiscovery, String> {
    if let Some(cached) = cache.try_get(issuer)? {
        return Ok(cached);
    }
    let discovery = fetch_upstream_discovery(client, issuer, allowed_domains).await?;
    cache.try_insert(issuer, discovery.clone())?;
    Ok(discovery)
}

pub(in crate::web) fn validate_upstream_discovery(
    discovery: &OidcDiscovery,
    issuer: &str,
    profile: &oauth_profile::ResolvedProfile,
    upstream_auth_method: &str,
    allowed_domains: &[String],
) -> Result<(), String> {
    let normalized_issuer = normalize_issuer(&discovery.issuer)
        .ok_or_else(|| "upstream discovery issuer invalid".to_string())?;
    if normalized_issuer != issuer {
        return Err("upstream discovery issuer mismatch".to_string());
    }
    validate_upstream_metadata_endpoint(
        &discovery.authorization_endpoint,
        "authorization_endpoint",
        allowed_domains,
    )?;
    validate_upstream_metadata_endpoint(
        &discovery.token_endpoint,
        "token_endpoint",
        allowed_domains,
    )?;
    validate_upstream_metadata_endpoint(&discovery.jwks_uri, "jwks_uri", allowed_domains)?;
    if let Some(endpoint) = discovery.end_session_endpoint.as_deref() {
        validate_upstream_metadata_endpoint(endpoint, "end_session_endpoint", allowed_domains)?;
    }

    let response_type_supported = discovery
        .response_types_supported
        .iter()
        .any(|value| oauth_profile::normalize_response_type(value).as_str() == "code");
    if !response_type_supported {
        return Err("upstream discovery does not support response_type=code".to_string());
    }
    if let Some(grant_types) = discovery.grant_types_supported.as_ref() {
        let supported = grant_types
            .iter()
            .any(|value| value.eq_ignore_ascii_case("authorization_code"));
        if !supported {
            return Err("upstream discovery missing authorization_code grant".to_string());
        }
    }
    // Validate that the upstream IdP supports the connection's auth method.
    // Per RFC 8414 Section 2, the default when absent is ["client_secret_basic"].
    if let Some(methods) = discovery.token_endpoint_auth_methods_supported.as_ref() {
        if !methods
            .iter()
            .any(|value| value.eq_ignore_ascii_case(upstream_auth_method))
        {
            return Err(format!(
                "upstream discovery does not support {upstream_auth_method} auth"
            ));
        }
    } else if !upstream_auth_method.eq_ignore_ascii_case("client_secret_basic") {
        // Absent means only client_secret_basic (RFC 8414 default).
        return Err(format!(
            "upstream discovery does not support {upstream_auth_method} auth (default is client_secret_basic)"
        ));
    }
    if profile.require_iss_parameter
        && discovery.authorization_response_iss_parameter_supported != Some(true)
    {
        return Err("upstream discovery does not support iss parameter".to_string());
    }
    if profile.require_pkce
        && !discovery
            .code_challenge_methods_supported
            .as_ref()
            .is_some_and(|values| values.iter().any(|value| value == "S256"))
    {
        return Err("upstream discovery does not support PKCE S256".to_string());
    }
    Ok(())
}
