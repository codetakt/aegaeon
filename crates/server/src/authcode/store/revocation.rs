use super::{
    token_storage_error_message, ClientBoundRevocationOutcome, TokenRevocationOutcome, TokenStore,
    TokenStoreBackend,
};
#[cfg(test)]
use super::{write_lock, TokenStoreState};
use crate::metrics_integration::MetricsIntegration;
#[cfg(test)]
use std::time::SystemTime;
use tracing::info;

mod subject;

impl TokenStore {
    #[cfg(test)]
    fn revoke_token_locked(
        state: &mut TokenStoreState,
        token_str: &str,
        now: SystemTime,
    ) -> TokenRevocationOutcome {
        let bearer_meta_removed = state.bearer_meta.remove(token_str);
        if let Some(token) = state.access_tokens.remove(token_str) {
            Self::insert_access_revoked_locked(state, token_str.to_string(), &token, now);
            if let Some(meta) = bearer_meta_removed {
                Self::insert_revoked_locked(state, token_str.to_string(), meta.expires_at, now);
            }
            return TokenRevocationOutcome::AccessToken;
        }

        if let Some(token) = state.refresh_tokens.remove(token_str) {
            Self::insert_revoked_locked(state, token_str.to_string(), token.expires_at, now);
            if let Some(meta) = bearer_meta_removed {
                Self::insert_revoked_locked(state, token_str.to_string(), meta.expires_at, now);
            }
            let child_tokens = state.refresh_children.remove(token_str);
            let mut child_count: usize = child_tokens.as_ref().map_or(0, |tokens| tokens.len());
            if let Some(successor) = state.refresh_successors.remove(token_str) {
                child_count = child_count
                    .saturating_add(Self::revoke_refresh_family_locked(state, &successor, now));
            }
            if let Some(child_tokens) = child_tokens {
                for child in child_tokens {
                    if let Some(token) = state.access_tokens.remove(&child) {
                        Self::insert_access_revoked_locked(state, child.clone(), &token, now);
                    }
                    if let Some(meta) = state.bearer_meta.remove(&child) {
                        Self::insert_revoked_locked(state, child, meta.expires_at, now);
                    }
                }
            }
            return TokenRevocationOutcome::RefreshToken { child_count };
        }

        if let Some(meta) = bearer_meta_removed {
            Self::insert_revoked_locked(state, token_str.to_string(), meta.expires_at, now);
            return TokenRevocationOutcome::BearerMeta;
        }

        TokenRevocationOutcome::Unknown
    }

    fn record_revocation_outcome(token_str: &str, outcome: &TokenRevocationOutcome) {
        match outcome {
            TokenRevocationOutcome::AccessToken => {
                MetricsIntegration::with_global(|metrics| metrics.record_refresh_cascade(0));
            }
            TokenRevocationOutcome::RefreshToken { child_count } if *child_count > 0 => {
                info!(
                    target: "tokens",
                    refresh_hash=%crate::util::secret_log_fingerprint(token_str),
                    revoked_children=*child_count,
                    "cascade revocation triggered"
                );
                MetricsIntegration::with_global(|metrics| {
                    metrics.record_refresh_cascade(*child_count);
                });
            }
            TokenRevocationOutcome::RefreshToken { .. }
            | TokenRevocationOutcome::BearerMeta
            | TokenRevocationOutcome::Unknown => {}
        }
    }

    /// Revoke a token, reporting backend failures.
    pub fn try_revoke_token(&self, token_str: &str) -> Result<(), String> {
        let outcome = match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "try_revoke_token")?;
                let now = SystemTime::now();
                Self::cleanup_revoked_locked(&mut state, now);
                let outcome = Self::revoke_token_locked(&mut state, token_str, now);
                if !matches!(outcome, TokenRevocationOutcome::Unknown) {
                    state.version = state.version.saturating_add(1);
                }
                Ok(outcome)
            }
            TokenStoreBackend::Redis(backend) => backend
                .revoke_token(token_str)
                .map_err(|error| token_storage_error_message(&error, "try_revoke_token")),
        }?;

        Self::record_revocation_outcome(token_str, &outcome);
        Ok(())
    }

    /// Revoke a token only when it is unknown or owned by the requesting client.
    ///
    /// RFC 7009 preserves a 200 response for unknown tokens, but that must not
    /// translate into a cross-client side effect or an unbounded revoked-token
    /// tombstone set. Unknown tokens are therefore a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if the token store backend cannot confirm the mutation.
    pub fn try_revoke_token_for_client(
        &self,
        token_str: &str,
        requesting_client_id: Option<&str>,
    ) -> Result<ClientBoundRevocationOutcome, String> {
        let outcome = match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "try_revoke_token_for_client")?;
                let now = SystemTime::now();
                Self::cleanup_revoked_locked(&mut state, now);
                let owner = Self::known_token_client_id_locked(&state, token_str);
                let owner_mismatch = if let (Some(owner), Some(requester)) =
                    (owner.as_deref(), requesting_client_id)
                {
                    owner != requester
                } else {
                    false
                };
                if owner_mismatch || (owner.is_some() && requesting_client_id.is_none()) {
                    Ok((ClientBoundRevocationOutcome::OwnerMismatch, None))
                } else if owner.is_none() {
                    Ok((ClientBoundRevocationOutcome::Unknown, None))
                } else {
                    let revocation = Self::revoke_token_locked(&mut state, token_str, now);
                    if !matches!(revocation, TokenRevocationOutcome::Unknown) {
                        state.version = state.version.saturating_add(1);
                    }
                    let client_outcome = if matches!(revocation, TokenRevocationOutcome::Unknown) {
                        ClientBoundRevocationOutcome::Unknown
                    } else {
                        ClientBoundRevocationOutcome::Revoked
                    };
                    Ok((client_outcome, Some(revocation)))
                }
            }
            TokenStoreBackend::Redis(backend) => backend
                .revoke_token_for_client(token_str, requesting_client_id)
                .map_err(|error| {
                    token_storage_error_message(&error, "try_revoke_token_for_client")
                }),
        }?;
        let (client_outcome, revocation_outcome) = outcome;

        if let Some(revocation_outcome) = revocation_outcome {
            Self::record_revocation_outcome(token_str, &revocation_outcome);
        }
        Ok(client_outcome)
    }

    /// Revoke a token for a client on the blocking worker pool.
    pub async fn try_revoke_token_for_client_async(
        &self,
        token_str: String,
        requesting_client_id: Option<String>,
    ) -> Result<ClientBoundRevocationOutcome, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.try_revoke_token_for_client(&token_str, requesting_client_id.as_deref())
        })
        .await
        .map_err(|err| format!("token store worker failed: {err}"))?
    }
}
