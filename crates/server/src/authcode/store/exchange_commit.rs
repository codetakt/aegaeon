//! Exchange publication keeps both the validated subject and refresh lineage live at commit.
use super::token_consistency::{
    bearer_metadata_matches_access_token, meta_scope_set, refresh_parent_audience, scope_set,
    sender_bindings_match,
};
use super::{TokenStore, TokenStoreBackend, TokenStoreStorageError};
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::{Duration, SystemTime};

pub(crate) fn validate_exchange_subject(
    access: &AccessToken,
    meta: &BearerTokenMeta,
) -> Result<(), &'static str> {
    bearer_metadata_matches_access_token(access, meta)?;
    if access
        .created_at
        .checked_add(Duration::from_secs(access.expires_in))
        .is_none_or(|deadline| meta.expires_at > deadline)
    {
        return Err("subject metadata exceeds the stored token lifetime");
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExchangeCommitError {
    #[error("exchange rejected: {0}")]
    Rejected(String),
    #[error("exchange storage failure: {0}")]
    Storage(String),
}

impl From<String> for ExchangeCommitError {
    fn from(error: String) -> Self {
        Self::Storage(error)
    }
}
impl From<&str> for ExchangeCommitError {
    fn from(error: &str) -> Self {
        Self::Rejected(error.into())
    }
}
impl From<TokenStoreStorageError> for ExchangeCommitError {
    fn from(error: TokenStoreStorageError) -> Self {
        Self::Storage(error.to_string())
    }
}
impl From<ExchangeCommitError> for String {
    fn from(error: ExchangeCommitError) -> Self {
        error.to_string()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "keep ordered legacy and target publication checks in one audit boundary"
)]
#[expect(
    clippy::suspicious_operation_groupings,
    reason = "legacy exchange must reject either a metadata grant or a stored access-token root"
)]
pub(super) fn validate_exchange_commit(
    access: &AccessToken,
    output: &BearerTokenMeta,
    subject: &BearerTokenMeta,
    parent: Option<&RefreshToken>,
    now: SystemTime,
) -> Result<(), &'static str> {
    bearer_metadata_matches_access_token(access, output)?;
    if now >= subject.expires_at
        || output.expires_at > subject.expires_at
        || now >= output.expires_at
        || access
            .created_at
            .checked_add(Duration::from_secs(access.expires_in))
            != Some(output.expires_at)
        || output.issued_at != access.created_at
    {
        return Err("exchange subject or output is expired or inconsistent");
    }
    if subject.client_id != output.client_id
        || subject.user_id != output.user_id
        || (output.refresh_parent.is_some() && subject.refresh_parent != output.refresh_parent)
    {
        return Err("exchange subject and output identity must match");
    }
    if subject.sender_binding.is_some()
        && !sender_bindings_match(
            subject.sender_binding.as_ref(),
            output.sender_binding.as_ref(),
        )
    {
        return Err("exchange cannot weaken the subject sender binding");
    }
    if let Some(parent) = parent {
        if parent.rotated
            || now >= parent.expires_at
            || parent.client_id != output.client_id
            || parent.user_id != output.user_id
            || subject.refresh_parent.as_deref() != Some(parent.token.as_str())
            || (parent.sender_binding.is_some()
                && !sender_bindings_match(
                    parent.sender_binding.as_ref(),
                    output.sender_binding.as_ref(),
                ))
        {
            return Err("exchange refresh lineage is expired or inconsistent");
        }
    } else if output.refresh_parent.is_some() {
        return Err("exchange refresh parent is missing");
    }
    if !crate::application_authorization::is_restriction(
        output.application_grant.as_ref(),
        subject.application_grant.as_ref(),
    ) || parent.is_some_and(|parent| {
        !crate::application_authorization::is_restriction(
            subject.application_grant.as_ref(),
            parent.application_grant.as_ref(),
        )
    }) {
        return Err("exchange application authority exceeds its parent");
    }
    if subject.exchange_grant.is_none() {
        if output.exchange_grant.is_some()
            || access.exchange_root.is_some()
            || output.audience != subject.audience
            || !meta_scope_set(output).is_subset(&meta_scope_set(subject))
            || output.authorization_details != subject.authorization_details
        {
            return Err("legacy exchange cannot acquire target authority or broaden its subject");
        }
        if let Some(parent) = parent {
            if parent.exchange_grant.is_some()
                || output.audience != refresh_parent_audience(parent)
                || !meta_scope_set(output).is_subset(&scope_set(parent.scope.as_deref()))
            {
                return Err("legacy exchange output exceeds the retained refresh grant");
            }
        }
        return Ok(());
    }
    let parent = parent.ok_or("target exchange requires refresh lineage")?;
    if subject.refresh_parent != output.refresh_parent {
        return Err("target exchange must retain refresh lineage");
    }
    let root = access
        .exchange_root
        .as_ref()
        .ok_or("exchange output lineage missing")?;
    if now >= root.expires_at || output.expires_at > root.expires_at {
        return Err("exchange lineage deadline exceeded");
    }
    let original = parent
        .exchange_grant
        .as_ref()
        .ok_or("refresh parent has no exchange authority")?;
    let current = subject
        .exchange_grant
        .as_ref()
        .ok_or("subject has no exchange authority")?;
    let selected = output
        .exchange_grant
        .as_ref()
        .ok_or("output has no exchange authority")?;
    if !current.is_restriction_of(original)
        || !selected.is_restriction_of(current)
        || !selected.covers_output(
            &output.client_id,
            &output.user_id,
            &output.audience,
            &output.granted_scopes,
        )
        || output.authorization_details.is_some()
        || output.claim_release_policy.is_some()
    {
        return Err("exchange output exceeds the retained target authority");
    }
    Ok(())
}

impl TokenStore {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "owned snapshots make the exchange publication boundary explicit"
    )]
    pub(crate) fn store_exchanged_access(
        &self,
        access: AccessToken,
        output: BearerTokenMeta,
        expected_subject: BearerTokenMeta,
    ) -> Result<String, ExchangeCommitError> {
        #[cfg(test)]
        let parent_id = output.refresh_parent.as_deref();
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = super::write_lock(state, "store_exchanged_access")?;
                let now = SystemTime::now();
                if parent_id.is_some_and(|id| Self::is_revoked_locked(&state, id, now))
                    || Self::is_revoked_locked(&state, &expected_subject.token_id, now)
                {
                    return Err("exchange lineage has been revoked".into());
                }
                if access
                    .exchange_root
                    .as_ref()
                    .is_some_and(|root| Self::is_revoked_locked(&state, &root.id, now))
                {
                    return Err("exchange lineage revoked or missing".into());
                }
                let parent = parent_id
                    .map(|id| state.refresh_tokens.get(id).ok_or("missing refresh parent"))
                    .transpose()?;
                let subject = state
                    .bearer_meta
                    .get(&expected_subject.token_id)
                    .ok_or("missing subject metadata")?;
                let subject_access = state
                    .access_tokens
                    .get(&expected_subject.token_id)
                    .ok_or("missing subject token")?;
                validate_exchange_subject(subject_access, subject)
                    .map_err(ExchangeCommitError::from)?;
                if subject_access.is_expired()
                    || serde_json::to_value(subject).map_err(|e| e.to_string())?
                        != serde_json::to_value(&expected_subject).map_err(|e| e.to_string())?
                {
                    return Err("exchange subject has changed".into());
                }
                validate_exchange_commit(&access, &output, subject, parent, now)
                    .map_err(ExchangeCommitError::from)?;
                if state.access_tokens.contains_key(&access.token)
                    || state.bearer_meta.contains_key(&access.token)
                {
                    return Err(ExchangeCommitError::Storage(
                        "exchange token collision".into(),
                    ));
                }
                if let Some(parent_id) = output.refresh_parent.as_ref() {
                    state
                        .refresh_children
                        .entry(parent_id.clone())
                        .or_default()
                        .insert(access.token.clone());
                }
                state
                    .access_tokens
                    .insert(access.token.clone(), access.clone());
                state.bearer_meta.insert(output.token_id.clone(), output);
                state.version = state.version.saturating_add(1);
            }
            TokenStoreBackend::Redis(backend) => {
                backend.store_exchanged_access(&access, &output, &expected_subject)?
            }
        }
        Ok(access.token)
    }

    pub(crate) async fn store_exchanged_access_async(
        &self,
        access: AccessToken,
        output: BearerTokenMeta,
        subject: BearerTokenMeta,
    ) -> Result<String, ExchangeCommitError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.store_exchanged_access(access, output, subject))
            .await
            .map_err(|error| {
                ExchangeCommitError::Storage(format!("exchange store worker failed: {error}"))
            })?
    }
}
