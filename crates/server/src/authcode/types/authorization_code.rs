use super::{generate_secure_random, system_time_after_secs};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::SystemTime;

use crate::config::DEFAULT_AUTHORIZATION_CODE_TTL_SECS;
use crate::end_user_profiles::OidcProfileClaims;
use crate::upstream::UpstreamClaimReleasePolicy;

/// Authorization Code with security properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: Option<String>,
    /// RFC 8707 Resource Indicators: requested target resource (single value).
    pub resource: Option<String>,
    /// RFC 9396 Rich Authorization Requests (`authorization_details`).
    pub authorization_details: Option<Value>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    /// OIDC `auth_time` (seconds since Unix epoch) for the authorization.
    pub auth_time_epoch_secs: i64,
    /// Authentication Context Class Reference satisfied for this authorization.
    pub acr: Option<String>,
    /// Browser/auth-session that approved this authorization, used to scope OIDC `sid`.
    pub auth_session_id: Option<String>,
    /// Local profile snapshot captured at authorize time for later ID Token claim issuance.
    pub local_profile: Option<OidcProfileClaims>,
    /// Broker-managed custom-claim release policy snapshot captured at authorize time.
    pub claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub code_challenge: Option<String>, // RFC 7636 PKCE
    pub code_challenge_method: Option<String>,
    pub expires_at: SystemTime,
    pub used: bool, // Single-use enforcement
}

#[derive(Debug, Clone)]
pub struct AuthorizationCodeInput {
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: Option<String>,
    pub resource: Option<String>,
    pub authorization_details: Option<Value>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub auth_time_epoch_secs: i64,
    pub acr: Option<String>,
    pub auth_session_id: Option<String>,
    pub local_profile: Option<OidcProfileClaims>,
    pub claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

impl AuthorizationCodeInput {
    #[must_use]
    pub fn new(client_id: String, user_id: String, redirect_uri: Option<String>) -> Self {
        Self {
            client_id,
            user_id,
            redirect_uri,
            resource: None,
            authorization_details: None,
            scope: None,
            state: None,
            nonce: None,
            auth_time_epoch_secs: 0,
            acr: None,
            auth_session_id: None,
            local_profile: None,
            claim_release_policy: None,
            code_challenge: None,
            code_challenge_method: None,
        }
    }
}

impl AuthorizationCode {
    #[must_use]
    pub fn new(input: AuthorizationCodeInput) -> Self {
        Self::new_with_ttl(input, DEFAULT_AUTHORIZATION_CODE_TTL_SECS)
    }

    #[must_use]
    pub fn new_with_ttl(input: AuthorizationCodeInput, ttl_secs: u64) -> Self {
        let now = SystemTime::now();
        Self {
            code: generate_secure_random(32),
            client_id: input.client_id,
            user_id: input.user_id,
            redirect_uri: input.redirect_uri,
            resource: input.resource,
            authorization_details: input.authorization_details,
            scope: input.scope,
            state: input.state,
            nonce: input.nonce,
            auth_time_epoch_secs: input.auth_time_epoch_secs,
            acr: input.acr,
            auth_session_id: input.auth_session_id,
            local_profile: input.local_profile,
            claim_release_policy: input.claim_release_policy,
            code_challenge: input.code_challenge,
            code_challenge_method: input.code_challenge_method,
            expires_at: system_time_after_secs(now, ttl_secs).unwrap_or(now),
            used: false,
        }
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    pub fn mark_used(&mut self) {
        self.used = true;
    }
}
