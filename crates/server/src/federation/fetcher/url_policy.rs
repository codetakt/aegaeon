use super::super::{EntityStatement, FederationError};
use serde_json::Value;

const MAX_OUTBOUND_ALLOWED_DOMAINS: usize = 256;

/// Validate that an `entity_id` is a well-formed HTTPS URL.
///
/// Defense-in-depth against SSRF (C-3): rejects non-HTTPS schemes,
/// non-parseable URLs, and optionally enforces a domain allowlist.
///
/// # Errors
///
/// Returns [`FederationError`] when `entity_id` is not a parseable HTTPS URL with a host.
pub fn validate_entity_url(entity_id: &str) -> Result<url::Url, FederationError> {
    let parsed = url::Url::parse(entity_id)
        .map_err(|_| FederationError::Validation("invalid entity_id URL".into()))?;
    if parsed.scheme() != "https" {
        return Err(FederationError::Validation(
            "entity_id must use https scheme".into(),
        ));
    }
    if parsed.host_str().is_none() {
        return Err(FederationError::Validation(
            "entity_id URL must have a host".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FederationError::Validation(
            "entity_id URL must not include userinfo".into(),
        ));
    }
    if parsed.query().is_some() {
        return Err(FederationError::Validation(
            "entity_id URL must not include query".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(FederationError::Validation(
            "entity_id URL must not include fragment".into(),
        ));
    }
    crate::federation::profile::validate_identifier(entity_id)?;
    if crate::ssrf::validate_url_host_not_non_routable_literal(&parsed).is_err() {
        return Err(FederationError::Validation(
            "entity_id URL must not target non-routable hosts".into(),
        ));
    }
    Ok(parsed)
}

/// Construct the `.well-known/openid-federation` URL for an entity.
///
/// Validates that `entity_id` is a well-formed HTTPS URL (C-3 SSRF).
///
/// # Errors
///
/// Returns [`FederationError`] when `entity_id` is not a valid HTTPS entity identifier.
pub fn entity_configuration_url(entity_id: &str) -> Result<String, FederationError> {
    let mut parsed = validate_entity_url(entity_id)?;
    let base_path = parsed.path().trim_end_matches('/');
    parsed.set_path(&format!("{base_path}/.well-known/openid-federation"));
    Ok(parsed.into())
}

/// Construct the subordinate statement fetch URL.
///
/// Requires an advertised `metadata.federation_entity.federation_fetch_endpoint`
/// and appends the `sub` query parameter. There is no inferred fetch endpoint.
///
/// The `sub_entity_id` is percent-encoded in the query parameter to prevent
/// injection attacks (C-3 SSRF).
///
/// # Errors
///
/// Returns [`FederationError`] when the authority entity ID or configured fetch endpoint is not a
/// valid HTTPS URL.
pub fn subordinate_statement_url(
    authority_entity_id: &str,
    authority_config: &EntityStatement,
    sub_entity_id: &str,
) -> Result<String, FederationError> {
    validate_entity_url(authority_entity_id)?;
    let endpoint = configured_federation_fetch_endpoint(authority_config)?;
    Ok(subordinate_statement_url_from_endpoint(
        endpoint,
        sub_entity_id,
    ))
}

fn configured_federation_fetch_endpoint(
    authority_config: &EntityStatement,
) -> Result<url::Url, FederationError> {
    let endpoint = authority_config
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("federation_entity"))
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("federation_fetch_endpoint"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            FederationError::Validation("missing advertised federation_fetch_endpoint".into())
        })?;
    let parsed = crate::federation::profile::validate_endpoint(endpoint)?;
    validate_configured_fetch_endpoint_url(&parsed)?;
    Ok(parsed)
}

fn validate_configured_fetch_endpoint_url(parsed: &url::Url) -> Result<(), FederationError> {
    if parsed.scheme() != "https" {
        return Err(FederationError::Validation(
            "federation_fetch_endpoint must use https scheme".into(),
        ));
    }
    if parsed.host_str().is_none() {
        return Err(FederationError::Validation(
            "federation_fetch_endpoint URL must have a host".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FederationError::Validation(
            "federation_fetch_endpoint URL must not include userinfo".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(FederationError::Validation(
            "federation_fetch_endpoint URL must not include fragment".into(),
        ));
    }
    if parsed.query_pairs().any(|(name, _)| name == "sub") {
        return Err(FederationError::Validation(
            "federation_fetch_endpoint URL must not predefine the sub query parameter".into(),
        ));
    }
    if crate::ssrf::validate_url_host_not_non_routable_literal(parsed).is_err() {
        return Err(FederationError::Validation(
            "federation_fetch_endpoint URL must not target non-routable hosts".into(),
        ));
    }
    Ok(())
}

fn subordinate_statement_url_from_endpoint(mut parsed: url::Url, sub_entity_id: &str) -> String {
    parsed.query_pairs_mut().append_pair("sub", sub_entity_id);
    parsed.into()
}

/// Check whether a host matches a domain allowlist.
///
/// Returns `true` if the host is exactly one of the allowed domains or is a
/// subdomain of one (e.g. host `sub.example.com` matches allowed `example.com`).
pub(in crate::federation) fn host_matches_allowlist(host: &str, allowed: &[String]) -> bool {
    crate::ssrf::host_matches_domain_allowlist(host, allowed)
}

fn normalize_federation_outbound_allowed_domain(domain: &str) -> Result<String, FederationError> {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.contains("://")
        || normalized
            .chars()
            .any(|character| matches!(character, '/' | '?' | '#' | '@' | ':'))
    {
        return Err(FederationError::Validation(
            "federation outbound allowed domains must be plain DNS domains".to_string(),
        ));
    }

    let labels = normalized.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels
            .last()
            .is_some_and(|label| label.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(FederationError::Validation(
            "federation outbound allowed domains must include a non-numeric public suffix"
                .to_string(),
        ));
    }

    let labels_valid = labels.iter().all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    });
    if labels_valid {
        Ok(normalized)
    } else {
        Err(FederationError::Validation(
            "federation outbound allowed domains must be DNS labels".to_string(),
        ))
    }
}

/// Normalize a Federation outbound domain allowlist.
///
/// Values are plain DNS domains. Matching is exact-domain or subdomain based; URL syntax,
/// wildcards, ports, userinfo, and path/query/fragment input are rejected.
///
/// # Errors
///
/// Returns [`FederationError`] when the list is too large or contains an invalid domain.
pub fn normalize_federation_outbound_allowed_domains(
    domains: &[String],
) -> Result<Vec<String>, FederationError> {
    if domains.len() > MAX_OUTBOUND_ALLOWED_DOMAINS {
        return Err(FederationError::Validation(format!(
            "federation outbound allowed domain list exceeds {MAX_OUTBOUND_ALLOWED_DOMAINS} entries"
        )));
    }

    domains
        .iter()
        .try_fold(Vec::new(), |mut normalized, domain| {
            let domain = normalize_federation_outbound_allowed_domain(domain)?;
            if !normalized.iter().any(|existing| existing == &domain) {
                normalized.push(domain);
            }
            Ok(normalized)
        })
}

#[cfg(test)]
mod tests {
    use super::subordinate_statement_url;
    use crate::federation::{EntityStatement, FederationError};
    use serde_json::{json, Value};
    use std::collections::HashMap;

    fn authority_config(
        entity_id: &str,
        metadata: Option<HashMap<String, Value>>,
    ) -> EntityStatement {
        EntityStatement {
            iss: entity_id.to_string(),
            sub: entity_id.to_string(),
            iat: 1_700_000_000,
            exp: 4_102_444_800,
            jwks: None,
            metadata,
            metadata_policy: None,
            constraints: None,
            trust_marks: None,
            authority_hints: None,
            source_endpoint: None,
            metadata_policy_crit: None,
        }
    }

    #[test]
    fn subordinate_statement_url_requires_advertised_fetch_endpoint() {
        let authority = authority_config("https://ta.example", None);
        assert!(
            subordinate_statement_url("https://ta.example", &authority, "https://rp.example")
                .is_err()
        );
    }

    #[test]
    fn subordinate_statement_url_uses_configured_federation_fetch_endpoint() {
        let authority = authority_config(
            "https://ta.example",
            Some(HashMap::from([(
                "federation_entity".to_string(),
                json!({
                    "federation_fetch_endpoint": "https://fetch.ta.example/custom/fetch?tenant=validation"
                }),
            )])),
        );

        let url = subordinate_statement_url("https://ta.example", &authority, "https://rp.example")
            .expect("configured subordinate statement URL should be valid");

        let parsed = url::Url::parse(&url).expect("generated URL should parse");
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("fetch.ta.example"));
        assert_eq!(parsed.path(), "/custom/fetch");
        let pairs = parsed.query_pairs().collect::<Vec<_>>();
        assert!(pairs
            .iter()
            .any(|(key, value)| key == "tenant" && value == "validation"));
        assert!(pairs
            .iter()
            .any(|(key, value)| key == "sub" && value == "https://rp.example"));
    }

    #[test]
    fn subordinate_statement_url_rejects_configured_endpoint_with_predefined_sub() {
        let authority = authority_config(
            "https://ta.example",
            Some(HashMap::from([(
                "federation_entity".to_string(),
                json!({
                    "federation_fetch_endpoint": "https://fetch.ta.example/custom/fetch?sub=https://evil.example"
                }),
            )])),
        );

        let err = subordinate_statement_url("https://ta.example", &authority, "https://rp.example")
            .expect_err("configured endpoint must not predefine sub");

        assert!(matches!(
            err,
            FederationError::Validation(message)
                if message.contains("must not predefine the sub query parameter")
        ));
    }
}
