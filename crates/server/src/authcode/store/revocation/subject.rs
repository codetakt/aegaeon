#[cfg(test)]
use super::super::{read_lock, write_lock, TokenStoreState};
use super::super::{token_storage_error_message, TokenStore, TokenStoreBackend};
use crate::authcode::types::{BearerTokenMeta, RefreshToken};
#[cfg(test)]
use std::time::SystemTime;
use tracing::info;

impl TokenStore {
    #[cfg(test)]
    fn revoke_tokens_by_subject_locked(state: &mut TokenStoreState, subject: &str) -> usize {
        let now = SystemTime::now();
        Self::cleanup_revoked_locked(state, now);

        let mut count = 0usize;

        let access_keys: Vec<String> = state
            .access_tokens
            .iter()
            .filter(|(_, token)| token.user_id == subject)
            .map(|(key, _)| key.clone())
            .collect();
        for key in &access_keys {
            if let Some(token) = state.access_tokens.remove(key) {
                Self::insert_access_revoked_locked(state, key.clone(), &token, now);
            }
            count += 1;
        }

        let refresh_keys: Vec<String> = state
            .refresh_tokens
            .iter()
            .filter(|(_, token)| token.user_id == subject)
            .map(|(key, _)| key.clone())
            .collect();
        for key in &refresh_keys {
            if state.refresh_tokens.contains_key(key) {
                count = count.saturating_add(1);
                count = count.saturating_add(Self::revoke_refresh_family_locked(state, key, now));
            }
        }

        let meta_keys: Vec<String> = state
            .bearer_meta
            .iter()
            .filter(|(_, meta)| meta.user_id == subject)
            .map(|(key, _)| key.clone())
            .collect();
        for key in meta_keys {
            if let Some(meta) = state.bearer_meta.remove(&key) {
                Self::insert_revoked_locked(state, key, meta.expires_at, now);
            }
        }

        if count > 0 {
            state.version = state.version.saturating_add(1);
        }

        count
    }

    /// Revoke all tokens belonging to a given subject (`user_id`).
    ///
    /// # Errors
    ///
    /// Returns an error if the token store backend cannot confirm the mutation.
    pub fn try_revoke_tokens_by_subject(&self, subject: &str) -> Result<usize, String> {
        let count = match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "try_revoke_tokens_by_subject")?;
                Ok(Self::revoke_tokens_by_subject_locked(&mut state, subject))
            }
            TokenStoreBackend::Redis(backend) => {
                backend.revoke_tokens_by_subject(subject).map_err(|error| {
                    token_storage_error_message(&error, "try_revoke_tokens_by_subject")
                })
            }
        }?;

        if count > 0 {
            info!(
                target: "tokens",
                subject=%subject,
                revoked_count=count,
                "revoked all tokens for subject"
            );
        }

        Ok(count)
    }

    pub async fn try_revoke_tokens_by_subject_async(
        &self,
        subject: String,
    ) -> Result<usize, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_revoke_tokens_by_subject(&subject))
            .await
            .map_err(|err| format!("token store worker failed: {err}"))?
    }

    #[must_use = "handle the token store result to preserve backend failures"]
    pub fn try_list_bearer_meta_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<BearerTokenMeta>, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let state = read_lock(state, "try_list_bearer_meta_for_subject")?;
                let now = SystemTime::now();
                Ok(state
                    .bearer_meta
                    .values()
                    .filter(|meta| {
                        meta.user_id == subject
                            && meta.expires_at > now
                            && !Self::is_revoked_locked(&state, meta.token_id.as_str(), now)
                    })
                    .cloned()
                    .collect())
            }
            TokenStoreBackend::Redis(backend) => backend
                .list_bearer_meta_for_subject(subject)
                .map_err(|error| {
                    token_storage_error_message(&error, "try_list_bearer_meta_for_subject")
                }),
        }
    }

    pub async fn try_list_bearer_meta_for_subject_async(
        &self,
        subject: String,
    ) -> Result<Vec<BearerTokenMeta>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_list_bearer_meta_for_subject(&subject))
            .await
            .map_err(|err| format!("token store worker failed: {err}"))?
    }

    #[must_use = "handle the token store result to preserve backend failures"]
    pub fn try_list_refresh_tokens_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<RefreshToken>, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let state = read_lock(state, "try_list_refresh_tokens_for_subject")?;
                let now = SystemTime::now();
                Ok(state
                    .refresh_tokens
                    .values()
                    .filter(|token| {
                        token.user_id == subject
                            && token.expires_at > now
                            && !token.rotated
                            && !Self::is_revoked_locked(&state, token.token.as_str(), now)
                    })
                    .cloned()
                    .collect())
            }
            TokenStoreBackend::Redis(backend) => backend
                .list_refresh_tokens_for_subject(subject)
                .map_err(|error| {
                    token_storage_error_message(&error, "try_list_refresh_tokens_for_subject")
                }),
        }
    }

    pub async fn try_list_refresh_tokens_for_subject_async(
        &self,
        subject: String,
    ) -> Result<Vec<RefreshToken>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_list_refresh_tokens_for_subject(&subject))
            .await
            .map_err(|err| format!("token store worker failed: {err}"))?
    }

    #[must_use]
    #[cfg(test)]
    fn revoke_access_token_for_subject_locked(
        state: &mut TokenStoreState,
        subject: &str,
        token_str: &str,
    ) -> bool {
        let owns_token = state
            .access_tokens
            .get(token_str)
            .is_some_and(|token| token.user_id == subject);
        if !owns_token {
            return false;
        }
        let now = SystemTime::now();
        Self::cleanup_revoked_locked(state, now);
        let _ = Self::revoke_token_locked(state, token_str, now);
        state.version = state.version.saturating_add(1);
        true
    }

    #[must_use = "handle the token store result to preserve backend failures"]
    pub fn try_revoke_access_token_for_subject(
        &self,
        subject: &str,
        token_str: &str,
    ) -> Result<bool, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "try_revoke_access_token_for_subject")?;
                Ok(Self::revoke_access_token_for_subject_locked(
                    &mut state, subject, token_str,
                ))
            }
            TokenStoreBackend::Redis(backend) => backend
                .revoke_access_token_for_subject(subject, token_str)
                .map_err(|error| {
                    token_storage_error_message(&error, "try_revoke_access_token_for_subject")
                }),
        }
    }

    pub async fn try_revoke_access_token_for_subject_async(
        &self,
        subject: String,
        token_str: String,
    ) -> Result<bool, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.try_revoke_access_token_for_subject(&subject, &token_str)
        })
        .await
        .map_err(|err| format!("token store worker failed: {err}"))?
    }

    #[must_use]
    #[cfg(test)]
    fn revoke_refresh_token_for_subject_locked(
        state: &mut TokenStoreState,
        subject: &str,
        token_str: &str,
    ) -> bool {
        let owns_token = state
            .refresh_tokens
            .get(token_str)
            .is_some_and(|token| token.user_id == subject);
        if !owns_token {
            return false;
        }
        let now = SystemTime::now();
        Self::cleanup_revoked_locked(state, now);
        let _ = Self::revoke_token_locked(state, token_str, now);
        state.version = state.version.saturating_add(1);
        true
    }

    #[must_use = "handle the token store result to preserve backend failures"]
    pub fn try_revoke_refresh_token_for_subject(
        &self,
        subject: &str,
        token_str: &str,
    ) -> Result<bool, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "try_revoke_refresh_token_for_subject")?;
                Ok(Self::revoke_refresh_token_for_subject_locked(
                    &mut state, subject, token_str,
                ))
            }
            TokenStoreBackend::Redis(backend) => backend
                .revoke_refresh_token_for_subject(subject, token_str)
                .map_err(|error| {
                    token_storage_error_message(&error, "try_revoke_refresh_token_for_subject")
                }),
        }
    }

    pub async fn try_revoke_refresh_token_for_subject_async(
        &self,
        subject: String,
        token_str: String,
    ) -> Result<bool, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.try_revoke_refresh_token_for_subject(&subject, &token_str)
        })
        .await
        .map_err(|err| format!("token store worker failed: {err}"))?
    }
}
