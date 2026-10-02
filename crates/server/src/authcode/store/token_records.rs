#[cfg(test)]
use super::TokenSnapshot;
#[cfg(test)]
use super::{read_lock, write_lock, TokenStoreState};
use super::{token_storage_error_message, TokenStore, TokenStoreBackend};
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken, SenderBinding};
#[cfg(test)]
use std::time::SystemTime;

impl TokenStore {
    /// Observational owner/visibility lookup only; this never authorizes token use.
    pub(crate) async fn try_observe_access_record_async(
        &self,
        token: String,
    ) -> Result<Option<AccessToken>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || match &store.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => Ok(read_lock(state, "observe_access_record")?
                .access_tokens
                .get(&token)
                .cloned()),
            TokenStoreBackend::Redis(backend) => backend
                .observe_access_record(&token)
                .map_err(|error| token_storage_error_message(&error, "observe_access_record")),
        })
        .await
        .map_err(|error| format!("token store worker failed: {error}"))?
    }

    /// Obtain a consistent snapshot of the token store
    #[must_use]
    #[cfg(test)]
    pub fn snapshot(&self) -> TokenSnapshot {
        self.try_snapshot()
            .expect("test token store snapshot should succeed")
    }

    /// Obtain a consistent snapshot of the token store, reporting backend failures.
    #[cfg(test)]
    pub fn try_snapshot(&self) -> Result<TokenSnapshot, String> {
        self.try_with_state("snapshot", |state| {
            let now = SystemTime::now();
            TokenSnapshot {
                refresh_grants: state.refresh_grants.clone(),
                access_tokens: state.access_tokens.clone(),
                refresh_tokens: state.refresh_tokens.clone(),
                revoked_tokens: state
                    .revoked_tokens
                    .iter()
                    .filter(|(_, expires_at)| **expires_at > now)
                    .map(|(token, _)| token.clone())
                    .collect(),
                bearer_meta: state.bearer_meta.clone(),
                version: state.version,
            }
        })
    }

    /// Replace an access-token record in test fixtures.
    #[cfg(test)]
    pub(crate) fn try_replace_access_token_record(
        &self,
        token: AccessToken,
    ) -> Result<String, String> {
        let token_str = token.token.clone();
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "replace_access_token_record")?;
                state.access_tokens.insert(token_str.clone(), token);
                state.version = state.version.saturating_add(1);
                Ok(token_str)
            }
            TokenStoreBackend::Redis(backend) => backend
                .store_access_token(&token)
                .map(|()| token_str)
                .map_err(|error| {
                    token_storage_error_message(&error, "replace_access_token_record")
                }),
        }
    }

    /// Replace bearer-token metadata in test fixtures.
    #[cfg(test)]
    pub(crate) fn try_replace_bearer_meta_record(
        &self,
        meta: BearerTokenMeta,
    ) -> Result<(), String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "replace_bearer_meta_record")?;
                state.bearer_meta.insert(meta.token_id.clone(), meta);
                state.version = state.version.saturating_add(1);
                Ok(())
            }
            TokenStoreBackend::Redis(backend) => backend
                .store_bearer_meta(&meta)
                .map_err(|error| token_storage_error_message(&error, "replace_bearer_meta_record")),
        }
    }

    /// Retrieve bearer token metadata if present, reporting backend failures.
    pub fn try_get_bearer_meta(&self, token_id: &str) -> Result<Option<BearerTokenMeta>, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let state = read_lock(state, "get_bearer_meta")?;
                Ok(state.bearer_meta.get(token_id).cloned())
            }
            TokenStoreBackend::Redis(backend) => backend
                .get_bearer_meta(token_id)
                .map_err(|error| token_storage_error_message(&error, "get_bearer_meta")),
        }
    }

    /// Retrieve bearer token metadata on the blocking worker pool.
    pub async fn try_get_bearer_meta_async(
        &self,
        token_id: String,
    ) -> Result<Option<BearerTokenMeta>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_get_bearer_meta(&token_id))
            .await
            .map_err(|err| format!("token store worker failed: {err}"))?
    }

    #[cfg(test)]
    pub(super) fn known_token_client_id_locked(
        state: &TokenStoreState,
        token_str: &str,
    ) -> Option<String> {
        state
            .access_tokens
            .get(token_str)
            .map(|token| token.client_id.clone())
            .or_else(|| {
                state
                    .refresh_tokens
                    .get(token_str)
                    .map(|token| token.client_id.clone())
            })
            .or_else(|| {
                state
                    .bearer_meta
                    .get(token_str)
                    .map(|meta| meta.client_id.clone())
            })
    }

    /// Resolve the client that owns a known access, refresh, or bearer metadata record.
    ///
    /// Unlike [`Self::try_active_token_client_id`], this intentionally includes expired
    /// and rotated records that are still present in the store. Revocation uses
    /// this stricter view so inactive-but-known tokens cannot be used to cross a
    /// client ownership boundary.
    /// Resolve the client that owns a known access, refresh, or bearer metadata record,
    /// reporting backend failures.
    pub fn try_known_token_client_id(&self, token_str: &str) -> Result<Option<String>, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let state = read_lock(state, "known_token_client_id")?;
                Ok(Self::known_token_client_id_locked(&state, token_str))
            }
            TokenStoreBackend::Redis(backend) => backend
                .known_token_client_id(token_str)
                .map_err(|error| token_storage_error_message(&error, "known_token_client_id")),
        }
    }

    /// Retrieve a refresh token record without mutating rotation state, reporting backend failures.
    pub fn try_get_refresh_token(&self, token_str: &str) -> Result<Option<RefreshToken>, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let state = read_lock(state, "get_refresh_token")?;
                if Self::is_revoked_locked(&state, token_str, SystemTime::now()) {
                    return Ok(None);
                }
                Ok(state
                    .refresh_tokens
                    .get(token_str)
                    .filter(|token| {
                        Self::refresh_grant_active_locked(&state, token, SystemTime::now())
                            && token
                                .exchange_grant
                                .as_ref()
                                .and_then(|grant| grant.root())
                                .is_none_or(|root| {
                                    SystemTime::now() < root.expires_at
                                        && !Self::is_revoked_locked(
                                            &state,
                                            &root.id,
                                            SystemTime::now(),
                                        )
                                })
                    })
                    .cloned())
            }
            TokenStoreBackend::Redis(backend) => backend
                .get_refresh_token(token_str)
                .map_err(|error| token_storage_error_message(&error, "get_refresh_token")),
        }
    }

    /// Verify and get access token, reporting backend failures.
    pub fn try_verify_access_token(&self, token_str: &str) -> Result<Option<AccessToken>, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let state = read_lock(state, "verify_access_token")?;
                if Self::is_revoked_locked(&state, token_str, SystemTime::now()) {
                    return Ok(None);
                }
                Ok(state
                    .access_tokens
                    .get(token_str)
                    .filter(|token| {
                        Self::access_grant_active_locked(&state, token, SystemTime::now())
                            && !token.is_expired()
                            && token.exchange_root.as_ref().is_none_or(|root| {
                                SystemTime::now() < root.expires_at
                                    && !Self::is_revoked_locked(&state, &root.id, SystemTime::now())
                            })
                    })
                    .cloned())
            }
            TokenStoreBackend::Redis(backend) => backend
                .verify_access_token(token_str)
                .map_err(|error| token_storage_error_message(&error, "verify_access_token")),
        }
    }

    /// Verify and get an access token on the blocking worker pool.
    pub async fn try_verify_access_token_async(
        &self,
        token_str: String,
    ) -> Result<Option<AccessToken>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_verify_access_token(&token_str))
            .await
            .map_err(|err| format!("token store worker failed: {err}"))?
    }

    /// Resolve the client that owns a currently active access or refresh token,
    /// reporting backend failures.
    pub fn try_active_token_client_id(&self, token_str: &str) -> Result<Option<String>, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let state = read_lock(state, "active_token_client_id")?;
                let now = SystemTime::now();
                if Self::is_revoked_locked(&state, token_str, now) {
                    return Ok(None);
                }

                Ok(state
                    .access_tokens
                    .get(token_str)
                    .filter(|token| {
                        Self::access_grant_active_locked(&state, token, SystemTime::now())
                            && !token.is_expired()
                            && token.exchange_root.as_ref().is_none_or(|root| {
                                SystemTime::now() < root.expires_at
                                    && !Self::is_revoked_locked(&state, &root.id, SystemTime::now())
                            })
                    })
                    .map(|token| token.client_id.clone())
                    .or_else(|| {
                        state
                            .refresh_tokens
                            .get(token_str)
                            .filter(|token| {
                                Self::refresh_grant_active_locked(&state, token, now)
                                    && now < token.expires_at
                                    && !token.rotated
                                    && token
                                        .exchange_grant
                                        .as_ref()
                                        .and_then(|grant| grant.root())
                                        .is_none_or(|root| {
                                            now < root.expires_at
                                                && !Self::is_revoked_locked(&state, &root.id, now)
                                        })
                            })
                            .map(|token| token.client_id.clone())
                    }))
            }
            TokenStoreBackend::Redis(backend) => backend
                .active_token_client_id(token_str)
                .map_err(|error| token_storage_error_message(&error, "active_token_client_id")),
        }
    }

    /// Replace a refresh-token record in test fixtures.
    #[cfg(test)]
    pub(crate) fn try_replace_refresh_token_record(
        &self,
        token: RefreshToken,
    ) -> Result<String, String> {
        let token_str = token.token.clone();
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "replace_refresh_token_record")?;
                state.refresh_tokens.insert(token_str.clone(), token);
                state.refresh_children.entry(token_str.clone()).or_default();
                state.version = state.version.saturating_add(1);
                Ok(token_str)
            }
            TokenStoreBackend::Redis(backend) => backend
                .store_refresh_token(&token)
                .map(|()| token_str)
                .map_err(|error| {
                    token_storage_error_message(&error, "replace_refresh_token_record")
                }),
        }
    }

    /// Update sender binding metadata for a refresh token, reporting backend failures.
    pub fn try_set_refresh_sender_binding(
        &self,
        token_str: &str,
        sender_binding: Option<SenderBinding>,
    ) -> Result<bool, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "set_refresh_sender_binding")?;
                if Self::is_revoked_locked(&state, token_str, SystemTime::now())
                    || !state.refresh_tokens.get(token_str).is_some_and(|token| {
                        !token.rotated
                            && SystemTime::now() < token.expires_at
                            && Self::refresh_grant_active_locked(&state, token, SystemTime::now())
                    })
                {
                    return Ok(false);
                }
                if let Some(token) = state.refresh_tokens.get_mut(token_str) {
                    token.sender_binding = sender_binding;
                    state.version = state.version.saturating_add(1);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            TokenStoreBackend::Redis(backend) => backend
                .set_refresh_sender_binding(token_str, sender_binding)
                .map_err(|error| token_storage_error_message(&error, "set_refresh_sender_binding")),
        }
    }

    /// Check whether a refresh token has been revoked or rotated, reporting backend failures.
    pub fn try_is_refresh_revoked(&self, token: &str) -> Result<bool, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let state = read_lock(state, "is_refresh_revoked")?;
                if Self::is_revoked_locked(&state, token, SystemTime::now()) {
                    return Ok(true);
                }
                Ok(state.refresh_tokens.get(token).is_none_or(|refresh| {
                    refresh.rotated
                        || SystemTime::now() >= refresh.expires_at
                        || !Self::refresh_grant_active_locked(&state, refresh, SystemTime::now())
                }))
            }
            TokenStoreBackend::Redis(backend) => backend
                .is_refresh_revoked(token)
                .map_err(|error| token_storage_error_message(&error, "is_refresh_revoked")),
        }
    }

    /// Read refresh authority on the blocking worker pool for parent validation.
    pub(crate) async fn try_get_refresh_token_async(
        &self,
        token: String,
    ) -> Result<Option<RefreshToken>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_get_refresh_token(&token))
            .await
            .map_err(|err| format!("token store worker failed: {err}"))?
    }

    /// Check refresh-token revocation on the blocking worker pool.
    pub async fn try_is_refresh_revoked_async(&self, token: String) -> Result<bool, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_is_refresh_revoked(&token))
            .await
            .map_err(|err| format!("token store worker failed: {err}"))?
    }
}
