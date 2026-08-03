use crate::config::{validate_public_base_url_value, ConfigError};
use crate::policy::validate_supported_grant_types;

use super::super::client_auth::advertised_client_auth_methods;
use super::super::runtime_config::MetadataRuntimeConfig;
use super::{validate_public_base_url, AuthorizationServerMetadata, MtlsEndpointAliases};

fn string_values(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn oauth_scopes_supported() -> Vec<String> {
    string_values(&["openid", "profile", "email", "offline_access"])
}

fn oauth_grant_types_supported(runtime: &MetadataRuntimeConfig) -> Vec<String> {
    runtime.grant_types_supported.clone()
}

fn device_authorization_endpoint(
    base_url: &str,
    runtime: &MetadataRuntimeConfig,
) -> Option<String> {
    runtime
        .enable_device_authz
        .then(|| format!("{base_url}/device_authorization"))
}

fn registration_endpoint(base_url: &str, runtime: &MetadataRuntimeConfig) -> Option<String> {
    runtime.dcr_enabled.then(|| format!("{base_url}/register"))
}

fn mtls_endpoint_aliases(
    runtime: &MetadataRuntimeConfig,
    mtls_base: &str,
) -> Option<MtlsEndpointAliases> {
    runtime.mtls_enabled.then(|| MtlsEndpointAliases {
        token_endpoint: Some(format!("{mtls_base}/token")),
        revocation_endpoint: Some(format!("{mtls_base}/revoke")),
        introspection_endpoint: Some(format!("{mtls_base}/introspect")),
        pushed_authorization_request_endpoint: runtime
            .mtls_alias_par
            .then(|| format!("{mtls_base}/par")),
    })
}

impl AuthorizationServerMetadata {
    /// Fallible constructor from an explicit management runtime policy snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when `base_url` is not a safe public issuer/base URL.
    pub fn try_new_secure_with_runtime_config(
        base_url: &str,
        runtime: &MetadataRuntimeConfig,
    ) -> Result<Self, ConfigError> {
        validate_public_base_url(base_url)?;
        if let Some(mtls_base) = runtime.mtls_base_url.as_deref() {
            validate_public_base_url_value("mtls_base_url", mtls_base)?;
        }
        validate_supported_grant_types(&runtime.grant_types_supported).map_err(|error| {
            ConfigError::InvalidValue {
                key: "grant_types_supported".to_string(),
                value: runtime.grant_types_supported.join(","),
                reason: error.to_string(),
            }
        })?;
        Ok(Self::build_secure_with_runtime_config(base_url, runtime))
    }

    fn build_secure_with_runtime_config(base_url: &str, runtime: &MetadataRuntimeConfig) -> Self {
        let mtls_base = runtime.mtls_base_url.as_deref().unwrap_or(base_url);
        let client_jwt_algs = if runtime.enable_private_key_jwt {
            runtime.client_jwt_algs.clone()
        } else {
            Vec::new()
        };
        let endpoint_auth_methods = advertised_client_auth_methods(!client_jwt_algs.is_empty());
        let client_jwt_alg_metadata =
            (!client_jwt_algs.is_empty()).then_some(client_jwt_algs.clone());
        let authorization_details_types = runtime.authorization_details_types_supported.clone();

        Self {
            issuer: base_url.to_string(),
            authorization_endpoint: format!("{base_url}/authorize"),
            token_endpoint: format!("{base_url}/token"),
            jwks_uri: Some(format!("{base_url}/jwks")),
            registration_endpoint: registration_endpoint(base_url, runtime),
            scopes_supported: Some(oauth_scopes_supported()),
            // OAuth 2.1 compliant - authorization code only, no implicit
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: Some(vec!["query".to_string(), "form_post".to_string()]),
            // OAuth 2.1 compliant grant types - NO implicit, NO password
            grant_types_supported: oauth_grant_types_supported(runtime),
            token_endpoint_auth_methods_supported: Some(endpoint_auth_methods.clone()),
            token_endpoint_auth_signing_alg_values_supported: client_jwt_alg_metadata.clone(),
            service_documentation: Some(format!("{base_url}/docs")),
            ui_locales_supported: Some(vec!["en-US".to_string()]),
            op_policy_uri: Some(format!("{base_url}/policy")),
            op_tos_uri: Some(format!("{base_url}/terms")),
            revocation_endpoint: Some(format!("{base_url}/revoke")),
            revocation_endpoint_auth_methods_supported: Some(endpoint_auth_methods.clone()),
            revocation_endpoint_auth_signing_alg_values_supported: client_jwt_alg_metadata.clone(),
            introspection_endpoint: Some(format!("{base_url}/introspect")),
            introspection_endpoint_auth_methods_supported: Some(endpoint_auth_methods),
            introspection_endpoint_auth_signing_alg_values_supported: client_jwt_alg_metadata,
            // PKCE required - S256 only per RFC 9700
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
            authorization_details_types_supported: (!authorization_details_types.is_empty())
                .then_some(authorization_details_types),
            // PAR support is always advertised; whether it is mandatory is a runtime policy.
            pushed_authorization_request_endpoint: Some(format!("{base_url}/par")),
            require_pushed_authorization_requests: Some(
                runtime.require_pushed_authorization_requests,
            ),
            // DPoP verification is hardcoded to EdDSA (Ed25519) via ffi::verify_dpop.
            dpop_signing_alg_values_supported: Some(vec!["EdDSA".to_string()]),
            acr_values_supported: None,
            // RFC 9068 §4: JWT access token signing alg (populated below if enabled)
            access_token_signing_alg_values_supported: None,
            aegaeon_access_token_formats_supported: None,
            // RFC 9701: JWT introspection signing algs (populated at runtime if enabled)
            introspection_signing_alg_values_supported: None,
            // Security BCP
            authorization_response_iss_parameter_supported: Some(true),
            tls_client_certificate_bound_access_tokens: Some(runtime.mtls_enabled),
            client_jwt_kid_required: None,
            device_authorization_endpoint: device_authorization_endpoint(base_url, runtime),
            mtls_endpoint_aliases: mtls_endpoint_aliases(runtime, mtls_base),
        }
    }
}
