use serde::{Deserialize, Serialize};

use crate::config::{validate_public_base_url_value, ConfigError};

mod secure;

/// RFC 8414 - OAuth 2.0 Authorization Server Metadata
/// With RFC 9126 PAR extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// The authorization server's issuer identifier
    pub issuer: String,

    /// URL of the authorization endpoint
    pub authorization_endpoint: String,

    /// URL of the token endpoint
    pub token_endpoint: String,

    /// URL of the JWK Set document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// URL of the registration endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    /// Supported scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// Supported response types
    pub response_types_supported: Vec<String>,

    /// Supported response modes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,

    /// Supported grant types
    #[serde(default = "default_grant_types")]
    pub grant_types_supported: Vec<String>,

    /// Supported token endpoint auth methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// Supported token endpoint auth signing algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// Custom: Require kid in `private_key_jwt` client assertions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_jwt_kid_required: Option<bool>,

    /// Service documentation URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,

    /// Supported UI locales
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,

    /// OP policy URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<String>,

    /// OP terms of service URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<String>,

    /// URL of the revocation endpoint (RFC 7009)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// Supported revocation endpoint auth methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// Supported revocation endpoint auth signing algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// URL of the introspection endpoint (RFC 7662)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,

    /// Supported introspection endpoint auth methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// Supported introspection endpoint auth signing algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// Supported PKCE code challenge methods (RFC 7636)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,

    /// RFC 9396 Rich Authorization Requests: supported `authorization_details` types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,

    /// RFC 9470 Step-Up: supported ACR values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values_supported: Option<Vec<String>>,

    // ===== RFC 9126 PAR Extensions =====
    /// URL of the PAR endpoint enforcing client redirect and scope policies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,

    /// Indicates whether the AS requires PAR
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,

    // ===== RFC 9449 DPoP Extensions =====
    /// `DPoP` signing algorithms supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    /// RFC 9068 §4: Access token signing algorithms supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_signing_alg_values_supported: Option<Vec<String>>,

    /// Custom: Access token formats supported (RFC 9068 opt-in signaling).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aegaeon_access_token_formats_supported: Option<Vec<String>>,

    // ===== RFC 9701 JWT Introspection Response =====
    /// Signing algorithms supported for JWT introspection responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_signing_alg_values_supported: Option<Vec<String>>,

    // ===== Additional Security Extensions =====
    /// Indicates if the issuer parameter is supported in authorization responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,

    /// TLS client certificate bound access tokens support
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<bool>,

    /// RFC 8628 - Device Authorization Endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,

    /// RFC 8705 - mTLS endpoint aliases
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,
}

/// RFC 8705 mTLS endpoint aliases object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsEndpointAliases {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    // Extension: PAR (RFC 9126). Not defined in RFC 8705, but allowed as an extension key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
}

/// Validate the public Authorization Server issuer/base URL used in RFC 8414 metadata.
///
/// HTTPS is required except for loopback HTTP, which is retained for local developer workflows.
/// Query strings, fragments, and userinfo are rejected because they do not compose safely with
/// endpoint URL construction.
pub fn validate_public_base_url(base_url: &str) -> Result<(), ConfigError> {
    validate_public_base_url_value("issuer_url", base_url)
}

fn default_grant_types() -> Vec<String> {
    vec!["authorization_code".to_string()]
}

impl Default for AuthorizationServerMetadata {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            jwks_uri: None,
            registration_endpoint: None,
            scopes_supported: None,
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: None,
            grant_types_supported: default_grant_types(),
            token_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: None,
            client_jwt_kid_required: None,
            service_documentation: None,
            ui_locales_supported: None,
            op_policy_uri: None,
            op_tos_uri: None,
            revocation_endpoint: None,
            revocation_endpoint_auth_methods_supported: None,
            revocation_endpoint_auth_signing_alg_values_supported: None,
            introspection_endpoint: None,
            introspection_endpoint_auth_methods_supported: None,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            code_challenge_methods_supported: None,
            authorization_details_types_supported: None,
            acr_values_supported: None,
            pushed_authorization_request_endpoint: None,
            require_pushed_authorization_requests: None,
            dpop_signing_alg_values_supported: None,
            access_token_signing_alg_values_supported: None,
            aegaeon_access_token_formats_supported: None,
            introspection_signing_alg_values_supported: None,
            authorization_response_iss_parameter_supported: None,
            tls_client_certificate_bound_access_tokens: None,
            device_authorization_endpoint: None,
            mtls_endpoint_aliases: None,
        }
    }
}

impl AuthorizationServerMetadata {
    /// Create metadata with PAR support enabled. Requests are validated
    /// against registered client redirect URIs and scope policies.
    #[must_use]
    pub fn with_par_support(mut self, par_endpoint: String, required: bool) -> Self {
        self.pushed_authorization_request_endpoint = Some(par_endpoint);
        self.require_pushed_authorization_requests = Some(required);
        self
    }

    /// Create metadata with `DPoP` support
    #[must_use]
    pub fn with_dpop_support(mut self, algorithms: Vec<String>) -> Self {
        self.dpop_signing_alg_values_supported = Some(algorithms);
        self
    }

    /// Enable PKCE support (RFC 9700 compliant - S256 only, no plain)
    #[must_use]
    pub fn with_pkce_support(mut self) -> Self {
        self.code_challenge_methods_supported = Some(vec!["S256".to_string()]);
        self
    }

    /// Enable issuer identification in responses
    #[must_use]
    pub fn with_issuer_identification(mut self) -> Self {
        self.authorization_response_iss_parameter_supported = Some(true);
        self
    }

    /// Validate metadata against RFC 9700 security requirements.
    ///
    /// # Errors
    ///
    /// Returns a list of compliance failures when the advertised metadata conflicts with RFC 9700
    /// secure-default expectations.
    pub fn validate_security_compliance(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // No implicit flow
        if self
            .response_types_supported
            .iter()
            .any(|rt| rt.contains("token") || rt.contains("id_token"))
        {
            errors.push("Implicit flow must not be supported per RFC 9700".to_string());
        }

        // No password grant
        if self.grant_types_supported.iter().any(|g| g == "password") {
            errors.push("Password grant must not be supported per RFC 9700".to_string());
        }

        // PKCE must be supported
        if let Some(ref methods) = self.code_challenge_methods_supported {
            if methods.is_empty() {
                errors.push("PKCE S256 method must be supported".to_string());
            }
            if methods.contains(&"plain".to_string()) {
                errors.push("Plain PKCE method must not be supported per RFC 9700".to_string());
            }
        } else {
            errors.push("PKCE support must be advertised".to_string());
        }

        // iss parameter should be supported
        if self.authorization_response_iss_parameter_supported != Some(true) {
            errors.push(
                "Authorization response iss parameter must be supported per RFC 9700".to_string(),
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
