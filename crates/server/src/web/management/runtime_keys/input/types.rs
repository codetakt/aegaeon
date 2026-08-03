#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::web::management) enum RuntimeKeyUsageInput {
    OidcIdTokenSigning,
    OidcRequestObjectDecryption,
    JwtAccessTokenSigning,
    JwtIntrospectionSigning,
}

impl RuntimeKeyUsageInput {
    pub(in crate::web::management) const fn as_db_str(self) -> &'static str {
        match self {
            Self::OidcIdTokenSigning => "OIDC_ID_TOKEN_SIGNING",
            Self::OidcRequestObjectDecryption => "OIDC_REQUEST_OBJECT_DECRYPTION",
            Self::JwtAccessTokenSigning => "JWT_ACCESS_TOKEN_SIGNING",
            Self::JwtIntrospectionSigning => "JWT_INTROSPECTION_SIGNING",
        }
    }

    pub(super) const fn default_algorithm(self) -> &'static str {
        match self {
            Self::OidcIdTokenSigning => "RS256",
            Self::OidcRequestObjectDecryption => "RSA-OAEP+A256GCM",
            Self::JwtAccessTokenSigning | Self::JwtIntrospectionSigning => "EdDSA",
        }
    }

    pub(super) const fn supported_algorithms(self) -> &'static [&'static str] {
        match self {
            Self::OidcIdTokenSigning => &["RS256"],
            Self::OidcRequestObjectDecryption => &["RSA-OAEP+A256GCM"],
            Self::JwtAccessTokenSigning | Self::JwtIntrospectionSigning => &["EdDSA"],
        }
    }
}

#[derive(Debug)]
pub(in crate::web::management) struct RuntimeKeyCreateInput {
    pub(in crate::web::management) usage: RuntimeKeyUsageInput,
    pub(in crate::web::management) kid: String,
    pub(in crate::web::management) algorithm: String,
    pub(in crate::web::management) provider: String,
    pub(in crate::web::management) initial_status: &'static str,
    pub(in crate::web::management) public_jwk: serde_json::Value,
    pub(in crate::web::management) encrypted_key_handle: String,
    pub(in crate::web::management) provider_configuration: serde_json::Value,
    pub(in crate::web::management) comment: Option<String>,
}
