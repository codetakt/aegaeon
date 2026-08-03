use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
#[cfg(test)]
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
#[cfg(test)]
use std::time::SystemTime;

/// Immutable snapshot of the token store
#[derive(Clone, Debug, Default)]
pub struct TokenSnapshot {
    pub access_tokens: HashMap<String, AccessToken>,
    pub refresh_tokens: HashMap<String, RefreshToken>,
    pub revoked_tokens: HashSet<String>,
    pub bearer_meta: HashMap<String, BearerTokenMeta>,
    pub version: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[cfg(test)]
pub(super) struct TokenStoreState {
    pub(super) access_tokens: HashMap<String, AccessToken>,
    pub(super) refresh_tokens: HashMap<String, RefreshToken>,
    pub(super) revoked_tokens: HashMap<String, SystemTime>,
    pub(super) refresh_children: HashMap<String, HashSet<String>>,
    pub(super) refresh_successors: HashMap<String, String>,
    pub(super) bearer_meta: HashMap<String, BearerTokenMeta>,
    pub(super) version: u64,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum TokenStoreStorageError {
    #[error("token store backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("token store payload cannot be encoded: {0}")]
    Codec(String),
    #[error("token store invariant violation: {0}")]
    InvariantViolation(String),
}
