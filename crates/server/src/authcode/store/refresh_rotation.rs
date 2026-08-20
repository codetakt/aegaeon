use super::token_consistency::{
    bearer_metadata_matches_access_token, refresh_token_matches_issued_grant,
};
#[cfg(test)]
use super::token_storage_error_message;
use super::{log_token_storage_error, RefreshRotationError, TokenStore, TokenStoreBackend};
#[cfg(test)]
use super::{write_lock, TokenStoreState};
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use crate::metrics_integration::MetricsIntegration;
#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use std::time::SystemTime;
use tracing::{info, warn};

impl TokenStore {
    /// Bind an access token to the refresh token that issued it (for cascade revocation).
    ///
    /// This helper exists only for focused store tests. Production grant issuance uses
    /// atomic grant-commit boundaries instead of standalone token graph mutation.
    #[cfg(test)]
    pub fn try_bind_refresh_access(
        &self,
        refresh_token: &str,
        access_token: &str,
    ) -> Result<(), String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "bind_refresh_access")?;
                state
                    .refresh_children
                    .entry(refresh_token.to_string())
                    .or_default()
                    .insert(access_token.to_string());
                state.version = state.version.saturating_add(1);
            }
            TokenStoreBackend::Redis(backend) => backend
                .bind_refresh_access(refresh_token, access_token)
                .map_err(|error| token_storage_error_message(&error, "bind_refresh_access"))?,
        }
        info!(
            target: "tokens",
            refresh_hash=%crate::util::secret_log_fingerprint(refresh_token),
            access_hash=%crate::util::secret_log_fingerprint(access_token),
            "refresh token bound to access token"
        );
        MetricsIntegration::with_global(MetricsIntegration::record_refresh_binding);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn revoke_refresh_family_locked(
        state: &mut TokenStoreState,
        root_refresh: &str,
        now: SystemTime,
    ) -> usize {
        let mut stack = vec![root_refresh.to_string()];
        let mut seen = HashSet::new();
        let mut child_count = 0usize;

        while let Some(refresh) = stack.pop() {
            if !seen.insert(refresh.clone()) {
                continue;
            }
            if let Some(successor) = state.refresh_successors.remove(&refresh) {
                stack.push(successor);
            }
            let refresh_expires_at = state
                .refresh_tokens
                .remove(&refresh)
                .map(|token| token.expires_at);
            if let Some(expires_at) = refresh_expires_at {
                Self::insert_revoked_locked(state, refresh.clone(), expires_at, now);
            }
            if let Some(meta) = state.bearer_meta.remove(&refresh) {
                Self::insert_revoked_locked(state, refresh.clone(), meta.expires_at, now);
            }
            if refresh_expires_at.is_some() {
                if let Some(child_tokens) = state.refresh_children.remove(&refresh) {
                    child_count = child_count.saturating_add(child_tokens.len());
                    for child in child_tokens {
                        if let Some(token) = state.access_tokens.remove(&child) {
                            Self::insert_access_revoked_locked(state, child.clone(), &token, now);
                        }
                        if let Some(meta) = state.bearer_meta.remove(&child) {
                            Self::insert_revoked_locked(state, child, meta.expires_at, now);
                        }
                    }
                }
            }
        }

        child_count
    }

    fn record_refresh_reuse(refresh: &str, child_count: usize) {
        warn!(
            target: "tokens",
            refresh_hash=%crate::util::secret_log_fingerprint(refresh),
            revoked_children=child_count,
            "refresh token reuse detected; cascading revoke"
        );
        MetricsIntegration::with_global(MetricsIntegration::record_refresh_rotation_conflict);
        if child_count > 0 {
            MetricsIntegration::with_global(|metrics| {
                metrics.record_refresh_cascade(child_count);
            });
        }
    }

    /// Validate that a refresh token is active without consuming it.
    ///
    /// Reuse of a rotated token is a security event: the whole refresh-token
    /// family is revoked immediately.
    pub fn prepare_refresh_rotation(
        &self,
        token_str: &str,
    ) -> Result<RefreshToken, RefreshRotationError> {
        let (result, reused_child_count) = match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "prepare_refresh_rotation")
                    .map_err(|_| RefreshRotationError::BackendUnavailable)?;
                let now = SystemTime::now();
                Self::cleanup_revoked_locked(&mut state, now);
                if Self::is_revoked_locked(&state, token_str, now) {
                    (Err(RefreshRotationError::Invalid), None)
                } else if let Some(token) = state.refresh_tokens.get(token_str).cloned() {
                    if token.rotated {
                        let child_count =
                            Self::revoke_refresh_family_locked(&mut state, token_str, now);
                        state.version = state.version.saturating_add(1);
                        (Err(RefreshRotationError::Reused), Some(child_count))
                    } else if now >= token.expires_at {
                        state.refresh_tokens.remove(token_str);
                        state.refresh_children.remove(token_str);
                        state.refresh_successors.remove(token_str);
                        state.version = state.version.saturating_add(1);
                        (Err(RefreshRotationError::Expired), None)
                    } else {
                        (Ok(token), None)
                    }
                } else {
                    (Err(RefreshRotationError::Invalid), None)
                }
            }
            TokenStoreBackend::Redis(backend) => backend
                .prepare_refresh_rotation(token_str)
                .map_err(|error| {
                    log_token_storage_error(&error, "prepare_refresh_rotation");
                    RefreshRotationError::BackendUnavailable
                })?,
        };
        if let Some(child_count) = reused_child_count {
            Self::record_refresh_reuse(token_str, child_count);
        }
        result
    }

    /// Validate that a refresh token is active on the blocking worker pool.
    pub async fn prepare_refresh_rotation_async(
        &self,
        token_str: String,
    ) -> Result<RefreshToken, RefreshRotationError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.prepare_refresh_rotation(&token_str))
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "token store worker failed during refresh lookup");
                RefreshRotationError::BackendUnavailable
            })?
    }

    /// Atomically rotate a refresh token and commit the issued replacement access token.
    ///
    /// This is the refresh-grant commit boundary: callers must complete all request
    /// validation and token signing before calling it.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "owned tokens make the atomic refresh rotation boundary explicit"
    )]
    pub fn store_refreshed_grant(
        &self,
        previous_refresh: &str,
        access_token: AccessToken,
        new_refresh: RefreshToken,
        meta: BearerTokenMeta,
    ) -> Result<(String, String), RefreshRotationError> {
        if bearer_metadata_matches_access_token(&access_token, &meta).is_err()
            || refresh_token_matches_issued_grant(&new_refresh, &access_token, &meta).is_err()
        {
            return Err(RefreshRotationError::InconsistentGrant);
        }
        let access_token_str = access_token.token.clone();
        let new_refresh_str = new_refresh.token.clone();
        if meta.token_id != access_token_str
            || meta.refresh_parent.as_deref() != Some(&new_refresh_str)
        {
            return Err(RefreshRotationError::InconsistentGrant);
        }

        let (result, reused_child_count) = match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let access_token_key = access_token_str.clone();
                let new_refresh_key = new_refresh_str.clone();
                let mut state = write_lock(state, "store_refreshed_grant")
                    .map_err(|_| RefreshRotationError::BackendUnavailable)?;
                let now = SystemTime::now();
                Self::cleanup_revoked_locked(&mut state, now);
                if Self::is_revoked_locked(&state, previous_refresh, now) {
                    (Err(RefreshRotationError::Invalid), None)
                } else if let Some(previous) = state.refresh_tokens.get(previous_refresh).cloned() {
                    if previous.rotated {
                        let child_count =
                            Self::revoke_refresh_family_locked(&mut state, previous_refresh, now);
                        state.version = state.version.saturating_add(1);
                        (Err(RefreshRotationError::Reused), Some(child_count))
                    } else if now >= previous.expires_at {
                        state.refresh_tokens.remove(previous_refresh);
                        state.refresh_children.remove(previous_refresh);
                        state.refresh_successors.remove(previous_refresh);
                        state.version = state.version.saturating_add(1);
                        (Err(RefreshRotationError::Expired), None)
                    } else {
                        if let Some(previous) = state.refresh_tokens.get_mut(previous_refresh) {
                            previous.rotated = true;
                        }
                        state
                            .refresh_successors
                            .insert(previous_refresh.to_string(), new_refresh_key.clone());
                        state
                            .refresh_tokens
                            .insert(new_refresh_key.clone(), new_refresh);
                        state
                            .refresh_children
                            .entry(new_refresh_key.clone())
                            .or_default()
                            .insert(access_token_key.clone());
                        state
                            .access_tokens
                            .insert(access_token_key.clone(), access_token);
                        state.bearer_meta.insert(meta.token_id.clone(), meta);
                        state.version = state.version.saturating_add(1);
                        (Ok(()), None)
                    }
                } else {
                    (Err(RefreshRotationError::Invalid), None)
                }
            }
            TokenStoreBackend::Redis(backend) => backend
                .store_refreshed_grant(previous_refresh, &access_token, &new_refresh, &meta)
                .map_err(|error| {
                    log_token_storage_error(&error, "store_refreshed_grant");
                    RefreshRotationError::BackendUnavailable
                })?,
        };
        if let Some(child_count) = reused_child_count {
            Self::record_refresh_reuse(previous_refresh, child_count);
        }
        result?;

        info!(
            target: "tokens",
            previous_hash=%crate::util::secret_log_fingerprint(previous_refresh),
            new_hash=%crate::util::secret_log_fingerprint(&new_refresh_str),
            "refresh token rotated"
        );
        info!(
            target: "tokens",
            refresh_hash=%crate::util::secret_log_fingerprint(&new_refresh_str),
            access_hash=%crate::util::secret_log_fingerprint(&access_token_str),
            "refresh token bound to access token"
        );
        MetricsIntegration::with_global(MetricsIntegration::record_refresh_binding);
        Ok((access_token_str, new_refresh_str))
    }

    /// Rotate a refresh token and commit its replacement grant on the blocking worker pool.
    pub async fn store_refreshed_grant_async(
        &self,
        previous_refresh: String,
        access_token: AccessToken,
        new_refresh: RefreshToken,
        meta: BearerTokenMeta,
    ) -> Result<(String, String), RefreshRotationError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.store_refreshed_grant(&previous_refresh, access_token, new_refresh, meta)
        })
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "token store worker failed during refresh commit");
            RefreshRotationError::BackendUnavailable
        })?
    }

    /// Rotate refresh token (RFC 9700), reporting backend failures.
    ///
    /// This helper exists only for focused store tests. Production refresh grants must
    /// use [`Self::store_refreshed_grant`] so refresh rotation and replacement grant
    /// persistence remain a single atomic commit boundary.
    #[cfg(test)]
    pub fn try_rotate_refresh_token(
        &self,
        token_str: &str,
    ) -> Result<Option<RefreshToken>, RefreshRotationError> {
        let refresh = match self.prepare_refresh_rotation(token_str) {
            Ok(refresh) => refresh,
            Err(
                RefreshRotationError::Invalid
                | RefreshRotationError::Expired
                | RefreshRotationError::Reused,
            ) => return Ok(None),
            Err(
                err @ (RefreshRotationError::InconsistentGrant
                | RefreshRotationError::BackendUnavailable),
            ) => {
                return Err(err);
            }
        };
        let mut token_to_rotate = refresh.clone();
        let new_token = token_to_rotate.rotate();

        let new_token_str = new_token.token.clone();
        let rotated = match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let new_token_key = new_token_str.clone();
                let mut state = write_lock(state, "rotate_refresh_token")
                    .map_err(|_| RefreshRotationError::BackendUnavailable)?;
                if let Some(previous) = state.refresh_tokens.get_mut(token_str) {
                    if previous.rotated || SystemTime::now() >= previous.expires_at {
                        false
                    } else {
                        previous.rotated = true;
                        state
                            .refresh_successors
                            .insert(token_str.to_string(), new_token_key.clone());
                        state
                            .refresh_tokens
                            .insert(new_token_key.clone(), new_token.clone());
                        state
                            .refresh_children
                            .entry(new_token_key.clone())
                            .or_default();
                        state.version = state.version.saturating_add(1);
                        true
                    }
                } else {
                    false
                }
            }
            TokenStoreBackend::Redis(backend) => backend
                .rotate_refresh_token(token_str, &new_token)
                .map_err(|error| {
                    log_token_storage_error(&error, "rotate_refresh_token");
                    RefreshRotationError::BackendUnavailable
                })?,
        };
        if !rotated {
            return Ok(None);
        }
        info!(
            target: "tokens",
            previous_hash=%crate::util::secret_log_fingerprint(token_str),
            new_hash=%crate::util::secret_log_fingerprint(&new_token_str),
            "refresh token rotated"
        );

        Ok(Some(new_token))
    }
}
