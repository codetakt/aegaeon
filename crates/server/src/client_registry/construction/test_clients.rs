use std::env;

use crate::config::{test_runtime_helpers_allowed_by_build, RuntimeStateNamespace};

use super::super::jwks_runtime_state::JwksRuntimeState;
use super::super::{
    env_flag, jwt_replay_store_from_env, test_clients_allowed_by_build,
    ClientAssertionRuntimePolicy, ClientRegistry, ClientRegistryInitError, JwksRuntimePolicy,
    RegisteredClient,
};

struct SeededClientEnvironment {
    redirect_uris: Vec<String>,
    test_client_jwks_pem: Option<String>,
    primary_backchannel_logout_uri: Option<String>,
    primary_backchannel_logout_session_required: bool,
    secondary_backchannel_logout_uri: Option<String>,
    secondary_backchannel_logout_session_required: bool,
}

impl SeededClientEnvironment {
    fn from_env() -> Self {
        Self {
            redirect_uris: test_redirect_uris_from_env(),
            test_client_jwks_pem: env::var("AEGAEON_TEST_CLIENT_JAR_PEM").ok(),
            primary_backchannel_logout_uri: trimmed_env(
                "AEGAEON_TEST_CLIENT_BACKCHANNEL_LOGOUT_URI",
            ),
            primary_backchannel_logout_session_required: env_flag(
                "AEGAEON_TEST_CLIENT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED",
                false,
            ),
            secondary_backchannel_logout_uri: trimmed_env(
                "AEGAEON_TEST_CLIENT2_BACKCHANNEL_LOGOUT_URI",
            ),
            secondary_backchannel_logout_session_required: env_flag(
                "AEGAEON_TEST_CLIENT2_BACKCHANNEL_LOGOUT_SESSION_REQUIRED",
                false,
            ),
        }
    }
}

impl ClientRegistry {
    pub fn try_with_test_clients_with_runtime_policy(
        client_assertion_policy: ClientAssertionRuntimePolicy,
        jwks_policy: JwksRuntimePolicy,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ClientRegistryInitError> {
        test_clients_allowed_by_build(test_runtime_helpers_allowed_by_build())?;
        let jwks_state = JwksRuntimeState::try_from_env(runtime_state_namespace)?;
        let jwt_replay_store = jwt_replay_store_from_env(runtime_state_namespace)?;
        let reg = Self::with_replay_store_policy_and_jwks_state(
            jwt_replay_store,
            client_assertion_policy,
            jwks_policy,
            jwks_state,
        );
        Ok(reg.seed_test_clients())
    }

    fn seed_test_clients(self) -> Self {
        let reg = self;
        let seeded = SeededClientEnvironment::from_env();

        reg.register(primary_test_client(&seeded));
        if let Some(client) = private_key_jwt_test_client(&seeded) {
            reg.register(client);
        }
        for client in mandatory_seeded_clients(&seeded) {
            reg.register(client);
        }
        register_optional_seeded_clients(&reg, &seeded);
        reg
    }
}

fn test_redirect_uris_from_env() -> Vec<String> {
    let mut uris = match env::var("AEGAEON_TEST_CLIENT_REDIRECT_URIS") {
        Ok(raw) => parse_redirect_uri_list(&raw),
        Err(_) => Vec::new(),
    };
    if uris.is_empty() {
        uris.push(default_callback_uri());
    }
    uris
}

fn parse_redirect_uri_list(raw: &str) -> Vec<String> {
    raw.split(|c: char| c.is_whitespace() || c == ',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
        .collect()
}

fn trimmed_env(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn default_callback_uri() -> String {
    "https://example.com/callback".to_string()
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn standard_oidc_scopes() -> Vec<String> {
    strings(&[
        "read",
        "write",
        "openid",
        "profile",
        "email",
        "address",
        "phone",
        "offline_access",
    ])
}

fn authorization_code_grants() -> Vec<String> {
    strings(&["authorization_code", "refresh_token"])
}

fn auth_code_client(
    client_id: &str,
    client_secret: Option<&str>,
    token_endpoint_auth_method: &str,
    redirect_uris: &[String],
) -> RegisteredClient {
    RegisteredClient {
        client_id: client_id.to_string(),
        client_secret: client_secret.map(str::to_string),
        redirect_uris: redirect_uris.to_vec(),
        post_logout_redirect_uris: redirect_uris.to_vec(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: token_endpoint_auth_method.to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: standard_oidc_scopes(),
        allowed_grant_types: authorization_code_grants(),
        registration_access_token: None,
        client_id_issued_at: None,
    }
}

fn primary_test_client(env: &SeededClientEnvironment) -> RegisteredClient {
    RegisteredClient {
        backchannel_logout_uri: env.primary_backchannel_logout_uri.clone(),
        backchannel_logout_session_required: env.primary_backchannel_logout_session_required,
        jwks_pem: env.test_client_jwks_pem.clone(),
        ..auth_code_client(
            "test-client",
            Some("test-secret"),
            "client_secret_basic",
            &env.redirect_uris,
        )
    }
}

fn private_key_jwt_test_client(env: &SeededClientEnvironment) -> Option<RegisteredClient> {
    env.test_client_jwks_pem
        .clone()
        .map(|jwks_pem| RegisteredClient {
            jwks_pem: Some(jwks_pem),
            ..auth_code_client(
                "test-client-pkjwt",
                None,
                "private_key_jwt",
                &env.redirect_uris,
            )
        })
}

fn mandatory_seeded_clients(env: &SeededClientEnvironment) -> Vec<RegisteredClient> {
    vec![
        secondary_test_client(env),
        client_secret_post_test_client(env),
        client_credentials_only_test_client(env),
        public_pkce_test_client(env),
    ]
}

fn secondary_test_client(env: &SeededClientEnvironment) -> RegisteredClient {
    RegisteredClient {
        backchannel_logout_uri: env.secondary_backchannel_logout_uri.clone(),
        backchannel_logout_session_required: env.secondary_backchannel_logout_session_required,
        ..auth_code_client(
            "test-client2",
            Some("test-secret2"),
            "client_secret_basic",
            &env.redirect_uris,
        )
    }
}

fn client_secret_post_test_client(env: &SeededClientEnvironment) -> RegisteredClient {
    auth_code_client(
        "test-client-post",
        Some("test-secret-post"),
        "client_secret_post",
        &env.redirect_uris,
    )
}

fn client_credentials_only_test_client(env: &SeededClientEnvironment) -> RegisteredClient {
    RegisteredClient {
        client_id: "cc-only-client".to_string(),
        client_secret: Some("cc-secret".to_string()),
        redirect_uris: env.redirect_uris.clone(),
        post_logout_redirect_uris: env.redirect_uris.clone(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: strings(&["read", "write"]),
        allowed_grant_types: strings(&["client_credentials"]),
        registration_access_token: None,
        client_id_issued_at: None,
    }
}

fn public_pkce_test_client(env: &SeededClientEnvironment) -> RegisteredClient {
    auth_code_client("public-client", None, "none", &env.redirect_uris)
}

fn register_optional_seeded_clients(reg: &ClientRegistry, env: &SeededClientEnvironment) {
    if env_flag("AEGAEON_TEST_ENABLE_JWT_BEARER_GRANT_CLIENT", false) {
        reg.register(jwt_bearer_grant_test_client());
    }
    if env_flag("AEGAEON_TEST_ENABLE_TOKEN_EXCHANGE_CLIENT", false) {
        reg.register(token_exchange_test_client(env));
    }
    if env_flag("AEGAEON_TEST_ENABLE_DEVICE_CODE_CLIENT", false) {
        reg.register(device_code_test_client(env));
    }
}

fn jwt_bearer_grant_test_client() -> RegisteredClient {
    RegisteredClient {
        client_id: "jwt-bearer-client".to_string(),
        client_secret: Some("jwt-bearer-secret".to_string()),
        redirect_uris: vec![default_callback_uri()],
        post_logout_redirect_uris: vec![default_callback_uri()],
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        jwks_pem: trimmed_env("AEGAEON_TEST_JWT_BEARER_GRANT_PUB_PEM"),
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: strings(&["read", "write"]),
        allowed_grant_types: strings(&["urn:ietf:params:oauth:grant-type:jwt-bearer"]),
        registration_access_token: None,
        client_id_issued_at: None,
    }
}

fn token_exchange_test_client(env: &SeededClientEnvironment) -> RegisteredClient {
    RegisteredClient {
        client_id: "token-exchange-client".to_string(),
        client_secret: Some("token-exchange-secret".to_string()),
        redirect_uris: env.redirect_uris.clone(),
        post_logout_redirect_uris: env.redirect_uris.clone(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: strings(&["read", "write", "offline_access"]),
        allowed_grant_types: strings(&[
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ]),
        registration_access_token: None,
        client_id_issued_at: None,
    }
}

fn device_code_test_client(env: &SeededClientEnvironment) -> RegisteredClient {
    RegisteredClient {
        client_id: "device-code-client".to_string(),
        client_secret: Some("device-code-secret".to_string()),
        redirect_uris: env.redirect_uris.clone(),
        post_logout_redirect_uris: env.redirect_uris.clone(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: strings(&["read", "write"]),
        allowed_grant_types: strings(&["urn:ietf:params:oauth:grant-type:device_code"]),
        registration_access_token: None,
        client_id_issued_at: None,
    }
}
