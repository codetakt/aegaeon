use serde::{Deserialize, Serialize};

/// RFC 9728 - OAuth 2.0 Protected Resource Metadata
///
/// Describes capabilities and requirements of a protected resource so that
/// clients and authorization servers can discover how to interact with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// REQUIRED.  The protected resource's resource identifier (Section 1.2).
    pub resource: String,

    /// OPTIONAL.  JSON array of OAuth 2.0 authorization server issuer
    /// identifiers for servers that can authorize access to this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,

    /// OPTIONAL.  URL of the resource's JWK Set document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// RECOMMENDED.  JSON array of scope values that can be used in
    /// authorization requests when targeting this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// OPTIONAL.  Bearer token presentation methods supported by the resource.
    /// Values: "header", "body", "query".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_methods_supported: Option<Vec<String>>,

    /// OPTIONAL.  JWS signing algorithms the resource supports for signed
    /// responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL.  Human-readable name for the protected resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,

    /// OPTIONAL.  URL of developer documentation for this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,

    /// OPTIONAL.  URL of the resource operator's privacy policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_policy_uri: Option<String>,

    /// OPTIONAL.  URL of the resource operator's terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_tos_uri: Option<String>,

    /// OPTIONAL.  Indicates mutual-TLS certificate-bound access token support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<bool>,

    /// OPTIONAL.  Supported `authorization_details` type values (RFC 9396).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,

    /// OPTIONAL.  JWS algorithms supported for `DPoP` proof validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL.  Whether DPoP-bound access tokens are required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens_required: Option<bool>,
}

impl ProtectedResourceMetadata {
    /// Build resource metadata reflecting this AS's own /resource endpoint.
    #[must_use]
    pub fn for_issuer(issuer: &str) -> Self {
        Self::for_issuer_with_mtls(issuer, false)
    }

    /// Build resource metadata from the management configuration policy snapshot.
    #[must_use]
    pub fn for_issuer_with_mtls(issuer: &str, mtls_enabled: bool) -> Self {
        let resource_url = crate::resource_audience::protected_resource(issuer);

        Self {
            resource: resource_url,
            authorization_servers: Some(vec![issuer.to_string()]),
            jwks_uri: None,
            scopes_supported: Some(vec!["read".to_string()]),
            bearer_methods_supported: Some(vec!["header".to_string()]),
            resource_signing_alg_values_supported: None,
            resource_name: Some("Aegaeon Protected Resource".to_string()),
            resource_documentation: Some(format!("{issuer}/docs")),
            resource_policy_uri: None,
            resource_tos_uri: None,
            tls_client_certificate_bound_access_tokens: Some(mtls_enabled),
            authorization_details_types_supported: None,
            // DPoP verification is hardcoded to EdDSA (Ed25519) via ffi::verify_dpop.
            dpop_signing_alg_values_supported: Some(vec!["EdDSA".to_string()]),
            dpop_bound_access_tokens_required: None,
        }
    }
}
