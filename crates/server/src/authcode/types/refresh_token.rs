use super::{generate_secure_random, system_time_after_secs, SenderBinding};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, SystemTime};

use crate::upstream::UpstreamClaimReleasePolicy;

/// Refresh Token with rotation tracking (RFC 9700)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: Option<String>,
    /// RFC 8707 Resource Indicators: the resource(s) associated with the grant (single value).
    pub resource: Option<String>,
    /// Sender binding (DPoP/mTLS) captured at issuance time.
    pub sender_binding: Option<SenderBinding>,
    /// RFC 9396 Rich Authorization Requests (`authorization_details`).
    pub authorization_details: Option<Value>,
    /// OIDC `auth_time` (seconds since Unix epoch) for the grant.
    pub auth_time_epoch_secs: i64,
    /// Authentication Context Class Reference satisfied for this grant.
    pub acr: Option<String>,
    pub claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub expires_at: SystemTime,
    pub rotated: bool,
    pub rotation_count: u32,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenInput {
    pub client_id: String,
    pub user_id: String,
    pub scope: Option<String>,
    pub resource: Option<String>,
    pub authorization_details: Option<Value>,
    pub auth_time_epoch_secs: i64,
    pub acr: Option<String>,
}

impl RefreshTokenInput {
    #[must_use]
    pub fn new(client_id: String, user_id: String) -> Self {
        Self {
            client_id,
            user_id,
            scope: None,
            resource: None,
            authorization_details: None,
            auth_time_epoch_secs: 0,
            acr: None,
        }
    }
}

impl RefreshToken {
    /// Default refresh token lifetime (24 hours).
    const DEFAULT_TTL_SECS: u64 = 86400;

    #[must_use]
    pub fn new(input: RefreshTokenInput) -> Self {
        Self::with_ttl(input, Self::DEFAULT_TTL_SECS)
    }

    #[must_use]
    pub fn with_ttl(input: RefreshTokenInput, ttl_secs: u64) -> Self {
        let now = SystemTime::now();
        Self {
            token: generate_secure_random(32),
            client_id: input.client_id,
            user_id: input.user_id,
            scope: input.scope,
            resource: input.resource,
            sender_binding: None,
            authorization_details: input.authorization_details,
            auth_time_epoch_secs: input.auth_time_epoch_secs,
            acr: input.acr,
            claim_release_policy: None,
            expires_at: system_time_after_secs(now, ttl_secs).unwrap_or(now),
            rotated: false,
            rotation_count: 0,
        }
    }

    #[must_use]
    pub fn rotate(&mut self) -> RefreshToken {
        self.rotated = true;
        // Preserve the remaining lifetime from the original expiry.
        let remaining = self
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::from_secs(Self::DEFAULT_TTL_SECS));
        let mut new_token = RefreshToken::with_ttl(
            RefreshTokenInput {
                scope: self.scope.clone(),
                resource: self.resource.clone(),
                authorization_details: self.authorization_details.clone(),
                auth_time_epoch_secs: self.auth_time_epoch_secs,
                acr: self.acr.clone(),
                ..RefreshTokenInput::new(self.client_id.clone(), self.user_id.clone())
            },
            remaining.as_secs(),
        );
        new_token.sender_binding.clone_from(&self.sender_binding);
        new_token
            .claim_release_policy
            .clone_from(&self.claim_release_policy);
        new_token.rotation_count = self.rotation_count.saturating_add(1);
        new_token
    }
}
