use super::ServerConfig;

#[derive(Clone, Copy, Debug)]
pub struct GrantRuntimeConfig {
    private_key_jwt_enabled: bool,
    jwt_bearer_enabled: bool,
    token_exchange_enabled: bool,
    device_authorization_enabled: bool,
}

impl GrantRuntimeConfig {
    #[must_use]
    pub const fn private_key_jwt_enabled(self) -> bool {
        self.private_key_jwt_enabled
    }

    #[must_use]
    pub const fn jwt_bearer_enabled(self) -> bool {
        self.jwt_bearer_enabled
    }

    #[must_use]
    pub const fn token_exchange_enabled(self) -> bool {
        self.token_exchange_enabled
    }

    #[must_use]
    pub const fn device_authorization_enabled(self) -> bool {
        self.device_authorization_enabled
    }
}

#[derive(Clone, Copy, Debug)]
pub struct JwtRuntimeConfig {
    access_tokens_enabled: bool,
    introspection_enabled: bool,
    introspection_exp_secs: u64,
    leeway_secs: u64,
}

impl JwtRuntimeConfig {
    #[must_use]
    pub const fn access_tokens_enabled(self) -> bool {
        self.access_tokens_enabled
    }

    #[must_use]
    pub const fn introspection_enabled(self) -> bool {
        self.introspection_enabled
    }

    #[must_use]
    pub const fn introspection_exp_secs(self) -> u64 {
        self.introspection_exp_secs
    }

    #[must_use]
    pub const fn leeway_secs(self) -> u64 {
        self.leeway_secs
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TokenRuntimeConfig {
    access_token_ttl_secs: u64,
    refresh_token_ttl_secs: u64,
    authorization_code_ttl_secs: u64,
    jwt: JwtRuntimeConfig,
}

impl TokenRuntimeConfig {
    #[must_use]
    pub const fn access_token_ttl_secs(self) -> u64 {
        self.access_token_ttl_secs
    }

    #[must_use]
    pub const fn refresh_token_ttl_secs(self) -> u64 {
        self.refresh_token_ttl_secs
    }

    #[must_use]
    pub const fn authorization_code_ttl_secs(self) -> u64 {
        self.authorization_code_ttl_secs
    }

    #[must_use]
    pub const fn jwt(self) -> JwtRuntimeConfig {
        self.jwt
    }
}

impl ServerConfig {
    #[must_use]
    pub const fn grant_runtime(&self) -> GrantRuntimeConfig {
        GrantRuntimeConfig {
            private_key_jwt_enabled: self.enable_private_key_jwt,
            jwt_bearer_enabled: self.enable_jwt_bearer_grant,
            token_exchange_enabled: self.enable_token_exchange,
            device_authorization_enabled: self.enable_device_authz,
        }
    }

    #[must_use]
    pub const fn jwt_runtime(&self) -> JwtRuntimeConfig {
        JwtRuntimeConfig {
            access_tokens_enabled: self.enable_jwt_access_tokens,
            introspection_enabled: self.enable_jwt_introspection,
            introspection_exp_secs: self.jwt_introspection_exp_secs,
            leeway_secs: self.jwt_leeway_secs,
        }
    }

    #[must_use]
    pub const fn token_runtime(&self) -> TokenRuntimeConfig {
        TokenRuntimeConfig {
            access_token_ttl_secs: self.access_token_ttl_secs,
            refresh_token_ttl_secs: self.refresh_token_ttl_secs,
            authorization_code_ttl_secs: self.authorization_code_ttl_secs,
            jwt: self.jwt_runtime(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ServerConfig;

    #[test]
    fn runtime_views_project_flat_config_fields() {
        let cfg = ServerConfig {
            enable_private_key_jwt: true,
            enable_jwt_bearer_grant: true,
            enable_token_exchange: true,
            enable_device_authz: true,
            enable_jwt_access_tokens: true,
            enable_jwt_introspection: true,
            jwt_introspection_exp_secs: 17,
            jwt_leeway_secs: 19,
            access_token_ttl_secs: 23,
            refresh_token_ttl_secs: 29,
            authorization_code_ttl_secs: 31,
            ..ServerConfig::default()
        };

        let grants = cfg.grant_runtime();
        assert!(grants.private_key_jwt_enabled());
        assert!(grants.jwt_bearer_enabled());
        assert!(grants.token_exchange_enabled());
        assert!(grants.device_authorization_enabled());

        let token = cfg.token_runtime();
        assert_eq!(token.access_token_ttl_secs(), 23);
        assert_eq!(token.refresh_token_ttl_secs(), 29);
        assert_eq!(token.authorization_code_ttl_secs(), 31);

        let jwt = token.jwt();
        assert!(jwt.access_tokens_enabled());
        assert!(jwt.introspection_enabled());
        assert_eq!(jwt.introspection_exp_secs(), 17);
        assert_eq!(jwt.leeway_secs(), 19);
    }
}
