use crate::metadata::MtlsEndpointAliases;
use axum::{response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

mod construction;

/// `OpenID` Provider Configuration per `OpenID` Connect Discovery 1.0
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    /// REQUIRED. Issuer identifier
    pub issuer: String,

    /// REQUIRED. Authorization endpoint
    pub authorization_endpoint: String,

    /// REQUIRED. Token endpoint
    pub token_endpoint: String,

    /// RECOMMENDED. `UserInfo` endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,

    /// REQUIRED. JWKS URI
    pub jwks_uri: String,

    /// RECOMMENDED. Registration endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    /// OPTIONAL. RP-Initiated Logout endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,

    /// RECOMMENDED. Scopes supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// REQUIRED. Response types supported
    pub response_types_supported: Vec<String>,

    /// OPTIONAL. Response modes supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,

    /// OPTIONAL. Grant types supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,

    /// OPTIONAL. ACR values supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values_supported: Option<Vec<String>>,

    /// REQUIRED. Subject types supported
    pub subject_types_supported: Vec<String>,

    /// REQUIRED. ID token signing algorithms supported
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// OPTIONAL. ID token encryption algorithms supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. ID token encryption encoding supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,

    /// OPTIONAL. `UserInfo` signing algorithms supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. `UserInfo` encryption algorithms supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. `UserInfo` encryption encoding supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,

    /// OPTIONAL. Request object signing algorithms supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. Request object encryption algorithms supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. Request object encryption encoding supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,

    /// OPTIONAL. Token endpoint auth methods supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// OPTIONAL. Token endpoint auth signing algorithms supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. Display values supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_values_supported: Option<Vec<String>>,

    /// OPTIONAL. Claim types supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_types_supported: Option<Vec<String>>,

    /// RECOMMENDED. Claims supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,

    /// OPTIONAL. Service documentation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,

    /// OPTIONAL. Claims locales supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_locales_supported: Option<Vec<String>>,

    /// OPTIONAL. UI locales supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,

    /// OPTIONAL. Claims parameter supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_parameter_supported: Option<bool>,

    /// OPTIONAL. Request parameter supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_parameter_supported: Option<bool>,

    /// OPTIONAL. Request URI parameter supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_parameter_supported: Option<bool>,

    /// OPTIONAL. Require request URI registration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_request_uri_registration: Option<bool>,

    /// OPTIONAL. OP policy URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<String>,

    /// OPTIONAL. OP terms of service URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<String>,

    // OAuth 2.0 extensions
    /// OPTIONAL. Revocation endpoint (RFC 7009)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// OPTIONAL. Revocation endpoint auth methods supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// OPTIONAL. Revocation endpoint auth signing algorithms supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. Introspection endpoint (RFC 7662)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,

    /// OPTIONAL. Introspection endpoint auth methods supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// OPTIONAL. Introspection endpoint auth signing algorithms supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. Code challenge methods supported (RFC 7636 - PKCE)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,

    // RFC 9126 - PAR
    /// OPTIONAL. Pushed authorization request endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,

    /// OPTIONAL. Require pushed authorization requests
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,

    /// OPTIONAL. Device Authorization Endpoint (RFC 8628 / OAuth metadata extension)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,

    // RFC 9449 - DPoP
    /// OPTIONAL. `DPoP` signing algorithms supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    // RFC 9700 - Security BCP
    /// OPTIONAL. Authorization response issuer parameter supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,

    /// OPTIONAL. TLS client certificate bound access tokens (RFC 8705)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<bool>,

    /// OPTIONAL. mTLS endpoint aliases (RFC 8705)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,

    /// Custom: Access token formats supported (RFC 9068 opt-in signaling).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aegaeon_access_token_formats_supported: Option<Vec<String>>,
}

/// Handler for /.well-known/openid-configuration endpoint
#[must_use]
pub fn discovery_handler(config: OidcDiscovery) -> impl IntoResponse {
    Json(config)
}

/// Handler for /.well-known/oauth-authorization-server endpoint
#[must_use]
pub fn oauth_discovery_handler(config: OidcDiscovery) -> impl IntoResponse {
    // Return same config but could filter OIDC-specific fields
    Json(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::MetadataRuntimeConfig;

    type TestResult = Result<(), String>;

    #[test]
    fn discovery_includes_jar_signing_algs() -> TestResult {
        let doc = OidcDiscovery::new_with_runtime_config(
            "https://as.example.com",
            "https://as.example.com",
            &MetadataRuntimeConfig::default(),
        );
        let algs = doc
            .request_object_signing_alg_values_supported
            .ok_or_else(|| "request object signing algorithms should be populated".to_string())?;
        assert_eq!(algs, vec!["RS256", "PS256"]);
        // JAR support flags
        assert_eq!(doc.request_parameter_supported, Some(true));
        assert_eq!(doc.request_uri_parameter_supported, Some(true));
        Ok(())
    }

    #[test]
    fn discovery_runtime_constructor_uses_mtls_snapshot() -> TestResult {
        let runtime = MetadataRuntimeConfig {
            mtls_enabled: true,
            mtls_base_url: Some("https://mtls.as.example.com".to_string()),
            mtls_alias_par: true,
            ..Default::default()
        };

        let doc = OidcDiscovery::new_with_runtime_config(
            "https://as.example.com",
            "https://as.example.com",
            &runtime,
        );

        assert_eq!(doc.tls_client_certificate_bound_access_tokens, Some(true));
        let aliases = doc
            .mtls_endpoint_aliases
            .ok_or_else(|| "mTLS aliases should use runtime snapshot".to_string())?;
        assert_eq!(
            aliases.token_endpoint.as_deref(),
            Some("https://mtls.as.example.com/token")
        );
        assert_eq!(
            aliases.pushed_authorization_request_endpoint.as_deref(),
            Some("https://mtls.as.example.com/par")
        );
        Ok(())
    }

    #[test]
    fn discovery_grant_types_follow_runtime_snapshot() -> TestResult {
        let runtime = MetadataRuntimeConfig {
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            ],
            enable_device_authz: true,
            ..Default::default()
        };

        let doc = OidcDiscovery::new_with_runtime_config(
            "https://as.example.com",
            "https://as.example.com",
            &runtime,
        );
        let grants = doc
            .grant_types_supported
            .ok_or_else(|| "grant types should be populated".to_string())?;

        assert_eq!(
            grants,
            vec![
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ]
        );
        assert_eq!(
            doc.device_authorization_endpoint.as_deref(),
            Some("https://as.example.com/device_authorization")
        );
        Ok(())
    }

    #[test]
    fn discovery_omits_device_authorization_endpoint_when_disabled() {
        let doc = OidcDiscovery::new_with_runtime_config(
            "https://as.example.com",
            "https://as.example.com",
            &MetadataRuntimeConfig::default(),
        );

        assert!(doc.device_authorization_endpoint.is_none());
    }
}
