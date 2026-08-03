use crate::config::{ConfigError, ServerConfig};

#[derive(Clone, Copy, Debug)]
pub(in crate::config) struct SharedRuntimeStoreRequirement {
    pub(in crate::config) surface: &'static str,
    pub(in crate::config) primary_env: &'static str,
}

impl SharedRuntimeStoreRequirement {
    const fn new(surface: &'static str, primary_env: &'static str) -> Self {
        Self {
            surface,
            primary_env,
        }
    }

    pub(in crate::config) fn describe(self) -> String {
        format!("{} ({})", self.surface, self.primary_env)
    }
}

impl ServerConfig {
    pub(in crate::config) fn shared_runtime_store_requirements(
        &self,
        oidc_enabled: bool,
    ) -> Result<Vec<SharedRuntimeStoreRequirement>, ConfigError> {
        let mut requirements = base_shared_runtime_store_requirements();
        requirements.extend(self.dpop_shared_runtime_store_requirements());
        requirements.extend(self.client_assertion_shared_runtime_store_requirements());
        requirements.extend(oidc_shared_runtime_store_requirements(oidc_enabled));
        requirements.extend(upstream_shared_runtime_store_requirements());

        Ok(requirements)
    }

    fn dpop_shared_runtime_store_requirements(&self) -> Vec<SharedRuntimeStoreRequirement> {
        if self.require_dpop_nonce {
            vec![SharedRuntimeStoreRequirement::new(
                "DPoP nonce store",
                "AEGAEON_DPOP_NONCE_REDIS_URL",
            )]
        } else {
            Vec::new()
        }
    }

    fn client_assertion_shared_runtime_store_requirements(
        &self,
    ) -> Vec<SharedRuntimeStoreRequirement> {
        let grants = self.grant_runtime();
        if !(grants.private_key_jwt_enabled() || grants.jwt_bearer_enabled()) {
            return Vec::new();
        }
        vec![SharedRuntimeStoreRequirement::new(
            "client assertion replay store",
            "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
        )]
    }
}

fn oidc_shared_runtime_store_requirements(
    oidc_enabled: bool,
) -> Vec<SharedRuntimeStoreRequirement> {
    if !oidc_enabled {
        return Vec::new();
    }
    vec![SharedRuntimeStoreRequirement::new(
        "OIDC logout/session store",
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
    )]
}

fn base_shared_runtime_store_requirements() -> Vec<SharedRuntimeStoreRequirement> {
    vec![
        SharedRuntimeStoreRequirement::new("PAR request_uri store", "AEGAEON_PAR_REDIS_URL"),
        SharedRuntimeStoreRequirement::new(
            "authorization-code/state/nonce store",
            "AEGAEON_AUTH_CODE_REDIS_URL",
        ),
        SharedRuntimeStoreRequirement::new(
            "token/revocation store",
            "AEGAEON_TOKEN_STORE_REDIS_URL",
        ),
        SharedRuntimeStoreRequirement::new("DPoP replay store", "AEGAEON_DPOP_REDIS_URL"),
        SharedRuntimeStoreRequirement::new("JWKS runtime state", "AEGAEON_JWKS_REDIS_URL"),
        SharedRuntimeStoreRequirement::new(
            "request-object jti replay store",
            "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
        ),
        SharedRuntimeStoreRequirement::new(
            "browser auth-session store",
            "AEGAEON_AUTH_SESSION_REDIS_URL",
        ),
        SharedRuntimeStoreRequirement::new("device-code store", "AEGAEON_DEVICE_CODE_REDIS_URL"),
        SharedRuntimeStoreRequirement::new("device CSRF store", "AEGAEON_DEVICE_CSRF_REDIS_URL"),
        SharedRuntimeStoreRequirement::new(
            "device verification rate limiter",
            "AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL",
        ),
        SharedRuntimeStoreRequirement::new(
            "local auth CSRF store",
            "AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL",
        ),
        SharedRuntimeStoreRequirement::new(
            "local login rate limiter",
            "AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL",
        ),
        SharedRuntimeStoreRequirement::new("step-up challenge store", "AEGAEON_STEPUP_REDIS_URL"),
        SharedRuntimeStoreRequirement::new(
            "management session store",
            "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
        ),
        SharedRuntimeStoreRequirement::new(
            "management login rate limiter",
            "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
        ),
    ]
}

fn upstream_shared_runtime_store_requirements() -> Vec<SharedRuntimeStoreRequirement> {
    vec![
        SharedRuntimeStoreRequirement::new(
            "upstream auth state store",
            "AEGAEON_UPSTREAM_AUTH_REDIS_URL",
        ),
        SharedRuntimeStoreRequirement::new(
            "upstream logout relay store",
            "AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL",
        ),
    ]
}
