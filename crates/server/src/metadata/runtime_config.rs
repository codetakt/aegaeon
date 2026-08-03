use aegaeon_jose::algorithms::CryptoProfile;

use crate::policy::default_grant_types;

#[derive(Debug, Clone)]
pub struct MetadataRuntimeConfig {
    pub crypto_profile: CryptoProfile,
    pub mtls_enabled: bool,
    pub mtls_base_url: Option<String>,
    pub mtls_alias_par: bool,
    pub dcr_enabled: bool,
    pub enable_private_key_jwt: bool,
    pub client_jwt_algs: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub enable_device_authz: bool,
    pub require_pushed_authorization_requests: bool,
    pub authorization_details_types_supported: Vec<String>,
}

impl Default for MetadataRuntimeConfig {
    fn default() -> Self {
        Self {
            crypto_profile: CryptoProfile::Verified,
            mtls_enabled: false,
            mtls_base_url: None,
            mtls_alias_par: false,
            dcr_enabled: false,
            enable_private_key_jwt: false,
            client_jwt_algs: Vec::new(),
            grant_types_supported: default_grant_types(),
            enable_device_authz: false,
            require_pushed_authorization_requests: false,
            authorization_details_types_supported: Vec::new(),
        }
    }
}
