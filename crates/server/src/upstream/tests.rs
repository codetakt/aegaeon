use super::*;
use crate::oidc::{Audience, IdToken, IdTokenClaims};
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var(key).ok();
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.previous.as_deref() {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

fn must_ok<T, E>(result: Result<T, E>) -> T
where
    E: std::fmt::Debug,
{
    match result {
        Ok(value) => value,
        Err(err) => fail_assertion(format!("expected Ok(..), got Err({err:?})")),
    }
}

fn must_some<T>(value: Option<T>) -> T {
    match value {
        Some(value) => value,
        None => fail_assertion("expected Some(..)".to_string()),
    }
}

fn must_err<T, E>(result: Result<T, E>) -> E
where
    E: std::fmt::Debug,
{
    match result {
        Ok(_) => fail_assertion("expected Err(..), got Ok(..)".to_string()),
        Err(err) => err,
    }
}

#[track_caller]
fn fail_assertion(message: String) -> ! {
    std::panic::panic_any(message)
}

fn make_upstream_auth_request(state: &str, ttl: Duration) -> UpstreamAuthRequest {
    let now = SystemTime::now();
    UpstreamAuthRequest {
        state: state.to_string(),
        nonce: "nonce".to_string(),
        code_verifier: Some("verifier".to_string()),
        acr: Some("urn:example:acr".to_string()),
        issuer: "https://issuer.example".to_string(),
        client_id: "client".to_string(),
        client_secret: Some("transient-secret-not-stored".to_string()),
        client_auth_method: "client_secret_basic".to_string(),
        context: UpstreamConnectionContext::new(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        ),
        token_endpoint: "https://issuer.example/token".to_string(),
        jwks_uri: "https://issuer.example/jwks".to_string(),
        redirect_uri: "https://rp.example/callback".to_string(),
        return_to: Some("https://rp.example/return".to_string()),
        max_age: Some(60),
        require_iss_parameter: true,
        jit_provisioning_policy: None,
        attribute_mappings: Vec::new(),
        claim_release_policy: None,
        logout_policy: None,
        issued_at: now,
        expires_at: now + ttl,
    }
}

mod attribute_mapping;
mod claim_release;
mod jit_policy;
mod logout_policy;
mod metadata_cache;
mod redis_store;
mod secret_envelope;
