use super::{TokenStore, TokenStoreStorageError};
use crate::authcode::types::AccessToken;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc as StdArc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) const TOKEN_STORE_REDIS_LOCK_TTL_MS: u64 = 30_000;
pub(super) const TOKEN_STORE_REDIS_LOCK_RETRIES: usize = 100;
pub(super) const TOKEN_STORE_REDIS_LOCK_RETRY_DELAY_MS: u64 = 20;
pub(super) const MAX_REFRESH_FAMILY_REVOCATION_REFRESH_VISITS: usize = 4096;
pub(super) const MAX_REFRESH_FAMILY_REVOCATION_CHILD_TOKENS: usize = 16_384;

#[derive(Clone)]
pub(super) struct RedisTokenStoreKeyspace {
    prefix: StdArc<str>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RedisRevokedTokenRecord {
    pub(super) token: String,
    pub(super) expires_at: SystemTime,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RedisRefreshChildrenRecord {
    pub(super) refresh_token: String,
    pub(super) access_tokens: HashSet<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RedisRefreshSuccessorRecord {
    pub(super) previous_refresh: String,
    pub(super) successor_refresh: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RedisRefreshPredecessorRecord {
    pub(super) refresh_token: String,
    pub(super) predecessor_refresh: String,
}

#[derive(Default)]
pub(super) struct RedisTokenMutation {
    pub(super) delete_keys: HashSet<String>,
    pub(super) delete_access_tokens: HashSet<String>,
    pub(super) delete_refresh_tokens: HashSet<String>,
    pub(super) delete_bearer_tokens: HashSet<String>,
    pub(super) delete_revoked_tokens: HashSet<String>,
    pub(super) revoked_until: HashMap<String, SystemTime>,
}

impl RedisTokenMutation {
    pub(super) fn is_empty(&self) -> bool {
        self.delete_keys.is_empty()
            && self.delete_access_tokens.is_empty()
            && self.delete_refresh_tokens.is_empty()
            && self.delete_bearer_tokens.is_empty()
            && self.delete_revoked_tokens.is_empty()
            && self.revoked_until.is_empty()
    }

    pub(super) fn delete_key(&mut self, key: String) {
        self.delete_keys.insert(key);
    }

    pub(super) fn delete_access_token(&mut self, token: impl Into<String>) {
        self.delete_access_tokens.insert(token.into());
    }

    pub(super) fn delete_refresh_token(&mut self, token: impl Into<String>) {
        self.delete_refresh_tokens.insert(token.into());
    }

    pub(super) fn delete_bearer_token(&mut self, token: impl Into<String>) {
        self.delete_bearer_tokens.insert(token.into());
    }

    pub(super) fn delete_revoked_token(&mut self, token: impl Into<String>) {
        self.delete_revoked_tokens.insert(token.into());
    }

    pub(super) fn revoke_until(
        &mut self,
        token: impl Into<String>,
        expires_at: SystemTime,
        now: SystemTime,
    ) {
        if expires_at <= now {
            return;
        }
        self.revoked_until
            .entry(token.into())
            .and_modify(|current| {
                if *current < expires_at {
                    *current = expires_at;
                }
            })
            .or_insert(expires_at);
    }

    pub(super) fn revoke_access_until(
        &mut self,
        token: impl Into<String>,
        access_token: &AccessToken,
        now: SystemTime,
    ) {
        if let Some(expires_at) = TokenStore::access_token_revocation_expires_at(access_token, now)
        {
            self.revoke_until(token, expires_at, now);
        }
    }
}

pub(super) fn token_store_key_digest(value: &str) -> String {
    let mut hasher = aegaeon_crypto::hash::Sha256Hasher::new();
    hasher.update(b"aegaeon:token-store:v3");
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

impl RedisTokenStoreKeyspace {
    pub(super) fn new(prefix: impl Into<StdArc<str>>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    #[cfg(test)]
    pub(super) fn pattern(&self, kind: &str) -> String {
        format!("{}:{kind}:*", self.prefix)
    }

    #[cfg(test)]
    pub(super) fn all_pattern(&self) -> String {
        format!("{}:*", self.prefix)
    }

    pub(super) fn access_key(&self, token: &str) -> String {
        self.key("access", token)
    }

    pub(super) fn refresh_key(&self, token: &str) -> String {
        self.key("refresh", token)
    }

    pub(super) fn bearer_key(&self, token: &str) -> String {
        self.key("bearer", token)
    }

    pub(super) fn revoked_key(&self, token: &str) -> String {
        self.key("revoked", token)
    }

    pub(super) fn refresh_children_key(&self, refresh: &str) -> String {
        self.key("refresh-children", refresh)
    }

    pub(super) fn refresh_successor_key(&self, refresh: &str) -> String {
        self.key("refresh-successor", refresh)
    }

    pub(super) fn refresh_predecessor_key(&self, refresh: &str) -> String {
        self.key("refresh-predecessor", refresh)
    }

    pub(super) fn subject_access_key(&self, subject: &str) -> String {
        self.key("subject-access", subject)
    }

    pub(super) fn subject_refresh_key(&self, subject: &str) -> String {
        self.key("subject-refresh", subject)
    }

    pub(super) fn subject_bearer_key(&self, subject: &str) -> String {
        self.key("subject-bearer", subject)
    }

    pub(super) fn expiry_access_key(&self) -> String {
        format!("{}:expiry:access", self.prefix)
    }

    pub(super) fn expiry_refresh_key(&self) -> String {
        format!("{}:expiry:refresh", self.prefix)
    }

    pub(super) fn expiry_bearer_key(&self) -> String {
        format!("{}:expiry:bearer", self.prefix)
    }

    pub(super) fn expiry_revoked_key(&self) -> String {
        format!("{}:expiry:revoked", self.prefix)
    }

    pub(super) fn version_key(&self) -> String {
        format!("{}:version", self.prefix)
    }

    pub(super) fn lock_key(&self) -> String {
        format!("{}:lock", self.prefix)
    }

    fn key(&self, kind: &str, value: &str) -> String {
        format!("{}:{kind}:{}", self.prefix, token_store_key_digest(value))
    }
}

pub(super) fn system_time_epoch_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(super) fn access_token_expires_at(token: &AccessToken) -> SystemTime {
    token
        .created_at
        .checked_add(Duration::from_secs(token.expires_in))
        .unwrap_or(UNIX_EPOCH)
}

pub(super) fn decode_redis_json<T: serde::de::DeserializeOwned>(
    payload: &str,
) -> Result<T, TokenStoreStorageError> {
    serde_json::from_str(payload).map_err(|err| TokenStoreStorageError::Codec(err.to_string()))
}

pub(super) fn encode_redis_json<T: Serialize>(value: &T) -> Result<String, TokenStoreStorageError> {
    serde_json::to_string(value).map_err(|err| TokenStoreStorageError::Codec(err.to_string()))
}
