use super::OidcDiscovery;
use crate::metadata::{
    advertised_client_auth_methods, advertised_request_object_signing_algs, MetadataRuntimeConfig,
    MtlsEndpointAliases,
};

fn string_values(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn oidc_scopes_supported() -> Vec<String> {
    string_values(&["openid", "profile", "email", "offline_access"])
}

fn oidc_display_values_supported() -> Vec<String> {
    string_values(&["page", "popup", "touch", "wap"])
}

fn oidc_claims_supported() -> Vec<String> {
    string_values(&[
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "nbf",
        "auth_time",
        "nonce",
        "acr",
        "sid",
        "at_hash",
        "c_hash",
        "name",
        "email",
        "email_verified",
        "updated_at",
    ])
}

fn oidc_grant_types_supported(runtime: &MetadataRuntimeConfig) -> Vec<String> {
    runtime.grant_types_supported.clone()
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

fn registration_endpoint(base_url: &str, runtime: &MetadataRuntimeConfig) -> Option<String> {
    runtime.dcr_enabled.then(|| format!("{base_url}/register"))
}

fn device_authorization_endpoint(
    base_url: &str,
    runtime: &MetadataRuntimeConfig,
) -> Option<String> {
    runtime
        .enable_device_authz
        .then(|| format!("{base_url}/device_authorization"))
}

impl OidcDiscovery {
    #[must_use]
    pub fn new_with_runtime_config(
        issuer: &str,
        base_url: &str,
        runtime: &MetadataRuntimeConfig,
    ) -> Self {
        let mtls_base = runtime.mtls_base_url.as_deref().unwrap_or(base_url);

        let client_jwt_algs = if runtime.enable_private_key_jwt {
            runtime.client_jwt_algs.clone()
        } else {
            Vec::new()
        };
        let endpoint_auth_methods = advertised_client_auth_methods(!client_jwt_algs.is_empty());
        let request_object_algs = advertised_request_object_signing_algs(runtime.crypto_profile);

        Self {
            issuer: issuer.to_string(),
            authorization_endpoint: format!("{base_url}/authorize"),
            token_endpoint: format!("{base_url}/token"),
            userinfo_endpoint: Some(format!("{base_url}/userinfo")),
            jwks_uri: format!("{base_url}/jwks"),
            registration_endpoint: registration_endpoint(base_url, runtime),
            end_session_endpoint: None,
            scopes_supported: Some(oidc_scopes_supported()),
            // OAuth 2.1 + OIDC code flow only (no implicit/hybrid).
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: Some(vec!["query".to_string(), "form_post".to_string()]),
            grant_types_supported: Some(oidc_grant_types_supported(runtime)),
            acr_values_supported: None,
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
            id_token_encryption_alg_values_supported: None,
            id_token_encryption_enc_values_supported: None,
            userinfo_signing_alg_values_supported: None,
            userinfo_encryption_alg_values_supported: None,
            userinfo_encryption_enc_values_supported: None,
            request_object_signing_alg_values_supported: Some(request_object_algs),
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            token_endpoint_auth_methods_supported: Some(endpoint_auth_methods.clone()),
            token_endpoint_auth_signing_alg_values_supported: (!client_jwt_algs.is_empty())
                .then_some(client_jwt_algs.clone()),
            display_values_supported: Some(oidc_display_values_supported()),
            claim_types_supported: Some(vec!["normal".to_string()]),
            claims_supported: Some(oidc_claims_supported()),
            service_documentation: None,
            claims_locales_supported: None,
            ui_locales_supported: None,
            claims_parameter_supported: Some(false),
            request_parameter_supported: Some(true),
            request_uri_parameter_supported: Some(true),
            require_request_uri_registration: Some(false),
            op_policy_uri: None,
            op_tos_uri: None,

            // OAuth 2.0 extensions
            revocation_endpoint: Some(format!("{base_url}/revoke")),
            revocation_endpoint_auth_methods_supported: Some(endpoint_auth_methods.clone()),
            revocation_endpoint_auth_signing_alg_values_supported: (!client_jwt_algs.is_empty())
                .then_some(client_jwt_algs.clone()),
            introspection_endpoint: Some(format!("{base_url}/introspect")),
            introspection_endpoint_auth_methods_supported: Some(endpoint_auth_methods),
            introspection_endpoint_auth_signing_alg_values_supported: (!client_jwt_algs.is_empty())
                .then_some(client_jwt_algs),
            // RFC 9700 BCP: S256 only (plain is deprecated)
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),

            // PAR
            pushed_authorization_request_endpoint: Some(format!("{base_url}/par")),
            require_pushed_authorization_requests: Some(
                runtime.require_pushed_authorization_requests,
            ),
            device_authorization_endpoint: device_authorization_endpoint(base_url, runtime),

            // EdDSA only — ffi::verify_dpop hardcodes Ed25519 (HACL*/EverCrypt).
            dpop_signing_alg_values_supported: Some(vec!["EdDSA".to_string()]),

            // RFC 9700 BCP
            authorization_response_iss_parameter_supported: Some(true),
            tls_client_certificate_bound_access_tokens: runtime.mtls_enabled.then_some(true),
            mtls_endpoint_aliases: mtls_endpoint_aliases(runtime, mtls_base),
            aegaeon_access_token_formats_supported: None,
        }
    }
}
