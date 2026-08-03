use super::token_consistency::{
    bearer_metadata_matches_access_token, refresh_token_matches_issued_grant,
};
#[cfg(test)]
use super::token_consistency::{meta_scope_set, scope_set, sender_bindings_match};
#[cfg(test)]
use super::write_lock;
use super::{token_storage_error_message, TokenStore, TokenStoreBackend};
use crate::authcode::store::AuthCodeStore;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use crate::metrics_integration::MetricsIntegration;
use crate::oidc::RedisOidcSessionGrantCommit;
#[cfg(test)]
use std::time::SystemTime;
use tracing::info;

pub(in crate::authcode) const AUTHORIZATION_CODE_GRANT_CODE_MISSING: &str =
    "authorization_code_invalid_or_expired";

pub(in crate::authcode) struct AuthorizationCodeGrantCommit {
    code_store: AuthCodeStore,
    code: String,
    expected_authorization_code_payload: String,
    access_token: AccessToken,
    refresh_token: Option<RefreshToken>,
    meta: BearerTokenMeta,
    oidc_session: Option<RedisOidcSessionGrantCommit>,
}

impl AuthorizationCodeGrantCommit {
    pub(in crate::authcode) fn new(
        code_store: AuthCodeStore,
        code: String,
        expected_authorization_code_payload: String,
        access_token: AccessToken,
        refresh_token: Option<RefreshToken>,
        meta: BearerTokenMeta,
        oidc_session: Option<RedisOidcSessionGrantCommit>,
    ) -> Self {
        Self {
            code_store,
            code,
            expected_authorization_code_payload,
            access_token,
            refresh_token,
            meta,
            oidc_session,
        }
    }
}

impl TokenStore {
    /// Atomically store a newly issued access token, optional refresh token, and bearer metadata.
    ///
    /// This keeps resource-server validation state from observing a partially issued grant.
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied metadata is not bound to the access token or refresh
    /// parent being committed.
    pub fn store_issued_grant(
        &self,
        access_token: AccessToken,
        refresh_token: Option<RefreshToken>,
        meta: BearerTokenMeta,
    ) -> Result<(String, Option<String>), String> {
        bearer_metadata_matches_access_token(&access_token, &meta).map_err(str::to_string)?;
        let access_token_str = access_token.token.clone();
        let refresh_token_str = refresh_token.as_ref().map(|token| token.token.clone());
        if meta.refresh_parent != refresh_token_str {
            return Err("bearer metadata refresh_parent must match the refresh token".to_string());
        }
        if let Some(refresh_token) = refresh_token.as_ref() {
            refresh_token_matches_issued_grant(refresh_token, &access_token, &meta)
                .map_err(str::to_string)?;
        }

        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "store_issued_grant")?;
                if state.access_tokens.contains_key(&access_token_str)
                    || state.bearer_meta.contains_key(&meta.token_id)
                    || refresh_token.as_ref().is_some_and(|refresh| {
                        state.refresh_tokens.contains_key(&refresh.token)
                            || state.refresh_children.contains_key(&refresh.token)
                    })
                {
                    return Err(
                        "token store invariant violation: issued grant token key collision"
                            .to_string(),
                    );
                }
                state
                    .access_tokens
                    .insert(access_token_str.clone(), access_token);
                if let Some(refresh_token) = refresh_token {
                    let refresh = refresh_token.token.clone();
                    state.refresh_tokens.insert(refresh.clone(), refresh_token);
                    state
                        .refresh_children
                        .entry(refresh)
                        .or_default()
                        .insert(access_token_str.clone());
                }
                state.bearer_meta.insert(meta.token_id.clone(), meta);
                state.version = state.version.saturating_add(1);
            }
            TokenStoreBackend::Redis(backend) => backend
                .store_issued_grant(&access_token, refresh_token.as_ref(), &meta)
                .map_err(|error| token_storage_error_message(&error, "store_issued_grant"))?,
        }
        if let Some(refresh) = refresh_token_str.as_deref() {
            info!(
                target: "tokens",
                refresh_hash=%crate::util::secret_log_fingerprint(refresh),
                access_hash=%crate::util::secret_log_fingerprint(&access_token_str),
                "refresh token bound to access token"
            );
            MetricsIntegration::with_global(MetricsIntegration::record_refresh_binding);
        }
        Ok((access_token_str, refresh_token_str))
    }

    /// Atomically store a newly issued grant on the blocking worker pool.
    pub async fn store_issued_grant_async(
        &self,
        access_token: AccessToken,
        refresh_token: Option<RefreshToken>,
        meta: BearerTokenMeta,
    ) -> Result<(String, Option<String>), String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.store_issued_grant(access_token, refresh_token, meta)
        })
        .await
        .map_err(|err| format!("token store worker failed: {err}"))?
    }

    /// Atomically consume an authorization code and store the issued grant.
    ///
    /// In Redis-backed production stores this is a single Lua script spanning
    /// the authorization-code key and token-store keys. This prevents losing a
    /// valid code after a token-store write failure and prevents observing a
    /// partially issued grant.
    pub(in crate::authcode) fn store_issued_authorization_code_grant(
        &self,
        commit: AuthorizationCodeGrantCommit,
    ) -> Result<(String, Option<String>), String> {
        let AuthorizationCodeGrantCommit {
            code_store,
            code,
            expected_authorization_code_payload,
            access_token,
            refresh_token,
            meta,
            oidc_session,
        } = commit;
        bearer_metadata_matches_access_token(&access_token, &meta).map_err(str::to_string)?;
        let access_token_str = access_token.token.clone();
        let refresh_token_str = refresh_token.as_ref().map(|token| token.token.clone());
        if meta.refresh_parent != refresh_token_str {
            return Err("bearer metadata refresh_parent must match the refresh token".to_string());
        }
        if let Some(refresh_token) = refresh_token.as_ref() {
            refresh_token_matches_issued_grant(refresh_token, &access_token, &meta)
                .map_err(str::to_string)?;
        }

        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(_) => {
                match code_store
                    .try_use_code_matching_payload(&code, &expected_authorization_code_payload)?
                {
                    Some(_) => {}
                    None => return Err(AUTHORIZATION_CODE_GRANT_CODE_MISSING.to_string()),
                }
                return self.store_issued_grant(access_token, refresh_token, meta);
            }
            TokenStoreBackend::Redis(backend) => {
                let auth_code = code_store.redis_commit_context(&code).ok_or_else(|| {
                    "authorization code store must be Redis-backed for atomic grant commit"
                        .to_string()
                })?;
                let committed = backend
                    .store_issued_grant_after_consuming_authorization_code(
                        &auth_code,
                        &expected_authorization_code_payload,
                        &access_token,
                        refresh_token.as_ref(),
                        &meta,
                        oidc_session.as_ref(),
                    )
                    .map_err(|error| {
                        token_storage_error_message(&error, "store_issued_authorization_code_grant")
                    })?;
                if !committed {
                    return Err(AUTHORIZATION_CODE_GRANT_CODE_MISSING.to_string());
                }
            }
        }
        if let Some(refresh) = refresh_token_str.as_deref() {
            info!(
                target: "tokens",
                refresh_hash=%crate::util::secret_log_fingerprint(refresh),
                access_hash=%crate::util::secret_log_fingerprint(&access_token_str),
                "refresh token bound to access token"
            );
            MetricsIntegration::with_global(MetricsIntegration::record_refresh_binding);
        }
        Ok((access_token_str, refresh_token_str))
    }

    /// Atomically consume an authorization code and store the issued grant on
    /// the blocking worker pool.
    pub(in crate::authcode) async fn store_issued_authorization_code_grant_async(
        &self,
        commit: AuthorizationCodeGrantCommit,
    ) -> Result<(String, Option<String>), String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.store_issued_authorization_code_grant(commit))
            .await
            .map_err(|err| format!("token store worker failed: {err}"))?
    }

    /// Atomically store an access token whose lifetime is governed by an existing refresh parent.
    ///
    /// This is used when a grant-derived access token is re-minted without issuing a new refresh
    /// token. The access token must remain a child of the active refresh token so family revocation
    /// and refresh-reuse detection continue to invalidate the whole chain.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata is inconsistent with the access token or the refresh parent
    /// is not currently active.
    pub fn store_access_for_refresh_parent(
        &self,
        access_token: AccessToken,
        meta: BearerTokenMeta,
    ) -> Result<String, String> {
        bearer_metadata_matches_access_token(&access_token, &meta).map_err(str::to_string)?;
        let access_token_str = access_token.token.clone();
        let refresh_parent = meta
            .refresh_parent
            .clone()
            .ok_or_else(|| "bearer metadata refresh_parent is required".to_string())?;

        let refresh_parent_for_store = refresh_parent.clone();
        let access_token_for_store = access_token;
        let meta_for_store = meta;
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let access_token_key = access_token_str.clone();
                let mut state = write_lock(state, "store_access_for_refresh_parent")?;
                let now = SystemTime::now();
                Self::cleanup_revoked_locked(&mut state, now);
                if Self::is_revoked_locked(&state, &refresh_parent_for_store, now) {
                    return Err("refresh_parent must be active".to_string());
                }
                let Some(parent) = state.refresh_tokens.get(&refresh_parent_for_store) else {
                    return Err("refresh_parent must be active".to_string());
                };
                if parent.rotated || now >= parent.expires_at {
                    return Err("refresh_parent must be active".to_string());
                }
                if parent.client_id != access_token_for_store.client_id
                    || parent.user_id != access_token_for_store.user_id
                {
                    return Err("refresh_parent owner must match the access token".to_string());
                }
                let parent_audience = parent.resource.as_deref().unwrap_or(&parent.client_id);
                if meta_for_store.audience != parent_audience {
                    return Err(
                        "bearer metadata audience must match refresh_parent resource".to_string(),
                    );
                }
                if !meta_scope_set(&meta_for_store).is_subset(&scope_set(parent.scope.as_deref())) {
                    return Err(
                        "bearer metadata scope must be a subset of refresh_parent scope"
                            .to_string(),
                    );
                }
                if !sender_bindings_match(
                    parent.sender_binding.as_ref(),
                    meta_for_store.sender_binding.as_ref(),
                ) {
                    return Err(
                        "bearer metadata sender_binding must match refresh_parent".to_string()
                    );
                }
                if state.access_tokens.contains_key(&access_token_key)
                    || state.bearer_meta.contains_key(&meta_for_store.token_id)
                {
                    return Err(
                        "token store invariant violation: refresh-parent access token key collision"
                            .to_string(),
                    );
                }

                state
                    .access_tokens
                    .insert(access_token_key.clone(), access_token_for_store);
                state
                    .refresh_children
                    .entry(refresh_parent_for_store.clone())
                    .or_default()
                    .insert(access_token_key.clone());
                state
                    .bearer_meta
                    .insert(meta_for_store.token_id.clone(), meta_for_store);
                state.version = state.version.saturating_add(1);
            }
            TokenStoreBackend::Redis(backend) => backend
                .store_access_for_refresh_parent(
                    &access_token_for_store,
                    &meta_for_store,
                    &refresh_parent_for_store,
                )
                .map_err(|error| {
                    token_storage_error_message(&error, "store_access_for_refresh_parent")
                })??,
        }

        info!(
            target: "tokens",
            refresh_hash=%crate::util::secret_log_fingerprint(&refresh_parent),
            access_hash=%crate::util::secret_log_fingerprint(&access_token_str),
            "refresh token bound to access token"
        );
        MetricsIntegration::with_global(MetricsIntegration::record_refresh_binding);
        Ok(access_token_str)
    }

    /// Store a refresh-parent-bound access token on the blocking worker pool.
    pub async fn store_access_for_refresh_parent_async(
        &self,
        access_token: AccessToken,
        meta: BearerTokenMeta,
    ) -> Result<String, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.store_access_for_refresh_parent(access_token, meta)
        })
        .await
        .map_err(|err| format!("token store worker failed: {err}"))?
    }
}
