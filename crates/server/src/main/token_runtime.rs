use std::sync::Arc;

use aegaeon_server::authcode::{TokenIssuer, TokenStore, TokenValidator};
use aegaeon_server::config::{RuntimeStateNamespace, ServerConfig};
use aegaeon_server::kms::KeyManager;
use aegaeon_server::oidc::{OidcConfig, OidcSessionStore};
use anyhow::Result;

pub(super) struct TokenRuntime {
    pub(super) issuer: Arc<TokenIssuer>,
    pub(super) validator: Arc<TokenValidator>,
    pub(super) store: Arc<TokenStore>,
}

pub(super) fn token_runtime_from_shared_env(
    cfg: &ServerConfig,
    key_manager: Arc<dyn KeyManager>,
    oidc: Option<&OidcConfig>,
    oidc_sessions: Option<OidcSessionStore>,
    issuer: &str,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<TokenRuntime> {
    let token_runtime = cfg.token_runtime();
    let jwt_runtime = token_runtime.jwt();
    let token_issuer = Arc::new(
        TokenIssuer::try_from_shared_store_env_with_ttls(
            key_manager.clone(),
            token_runtime.access_token_ttl_secs(),
            token_runtime.refresh_token_ttl_secs(),
            token_runtime.authorization_code_ttl_secs(),
            runtime_state_namespace,
        )?
        .with_oidc(oidc.cloned())
        .with_oidc_sessions(oidc_sessions)
        .with_issuer(issuer.to_string())
        .with_jwt_access_tokens_enabled(jwt_runtime.access_tokens_enabled()),
    );
    let token_store = Arc::new(token_issuer.token_store.clone());
    let token_validator = Arc::new(
        TokenValidator::with_policy(
            token_store.as_ref().clone(),
            key_manager,
            cfg.security_policy,
        )
        .with_jwt_access_tokens_enabled(jwt_runtime.access_tokens_enabled())
        .with_jwt_leeway_secs(jwt_runtime.leeway_secs())
        .with_issuer(Some(issuer.to_string())),
    );

    Ok(TokenRuntime {
        issuer: token_issuer,
        validator: token_validator,
        store: token_store,
    })
}
