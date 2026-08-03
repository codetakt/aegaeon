use super::{generate_secure_random, system_time_after_secs};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::SystemTime;

use crate::upstream::UpstreamClaimReleasePolicy;

/// Bearer Access Token per RFC 6750
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub token_type: String, // Always "Bearer"
    pub client_id: String,
    pub user_id: String,
    pub scope: Option<String>,
    pub expires_in: u64,
    pub created_at: SystemTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
}

/// Binding between an access token and its sender (DPoP/mTLS)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SenderBinding {
    DPoP { jkt: String },
    Mtls { fingerprint: String },
}

/// RFC 9068 §3.1: Confirmation method claim (`cnf`) for JWT access tokens.
///
/// `DPoP` uses `jkt` (JWK Thumbprint), mTLS uses `x5t#S256` (X.509 SHA-256 thumbprint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum CnfClaim {
    /// `DPoP`: `"cnf": {"jkt": "<thumbprint>"}`
    Jkt(String),
    /// mTLS: `"cnf": {"x5t#S256": "<thumbprint>"}`
    X5tS256(String),
}

/// Metadata tracked for bearer token enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BearerTokenMeta {
    pub token_id: String,
    pub client_id: String,
    pub user_id: String,
    pub granted_scopes: Vec<String>,
    pub audience: String,
    pub sender_binding: Option<SenderBinding>,
    /// RFC 9396 Rich Authorization Requests (`authorization_details`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Value>,
    /// OIDC `auth_time` (seconds since Unix epoch) for the authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time_epoch_secs: Option<i64>,
    /// Authentication Context Class Reference satisfied for this token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_parent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BearerTokenMetaInput {
    pub token_id: String,
    pub client_id: String,
    pub user_id: String,
    pub granted_scopes: Vec<String>,
    pub audience: String,
    pub sender_binding: Option<SenderBinding>,
    pub authorization_details: Option<Value>,
    pub auth_time_epoch_secs: Option<i64>,
    pub acr: Option<String>,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub refresh_parent: Option<String>,
}

impl BearerTokenMeta {
    #[must_use]
    pub fn new(input: BearerTokenMetaInput) -> Self {
        Self {
            token_id: input.token_id,
            client_id: input.client_id,
            user_id: input.user_id,
            granted_scopes: input.granted_scopes,
            audience: input.audience,
            sender_binding: input.sender_binding,
            authorization_details: input.authorization_details,
            auth_time_epoch_secs: input.auth_time_epoch_secs,
            acr: input.acr,
            claim_release_policy: None,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            refresh_parent: input.refresh_parent,
        }
    }
}

impl AccessToken {
    #[must_use]
    pub fn new(client_id: String, user_id: String, scope: Option<String>, expires_in: u64) -> Self {
        Self {
            token: generate_secure_random(32),
            token_type: "Bearer".to_string(),
            client_id,
            user_id,
            scope,
            expires_in,
            created_at: SystemTime::now(),
            cnf: None,
        }
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        match system_time_after_secs(self.created_at, self.expires_in) {
            Some(expiry) => SystemTime::now() >= expiry,
            None => true,
        }
    }
}
