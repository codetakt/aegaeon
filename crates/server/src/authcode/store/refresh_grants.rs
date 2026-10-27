//! Durable refresh decisions are independent of optional neighbor indexes.
use crate::authcode::types::{
    AccessToken, BearerTokenMeta, RefreshGrantRecord, RefreshGrantRef, RefreshToken,
};
use std::time::{Duration, SystemTime};

pub(super) fn descendant_deadline(
    access: &AccessToken,
    meta: &BearerTokenMeta,
    refresh: Option<&RefreshToken>,
) -> Result<SystemTime, &'static str> {
    let access_deadline = access
        .created_at
        .checked_add(Duration::from_secs(access.expires_in))
        .ok_or("access token expiry overflow")?;
    Ok(access_deadline
        .max(meta.expires_at)
        .max(refresh.map_or(access_deadline, |token| token.expires_at)))
}

/// The only boundary allowed to allocate a new identity. The returned record
/// must be collision-checked and published atomically with these exact tokens.
pub(super) fn prepare_initial(
    access: &mut AccessToken,
    refresh: Option<&mut RefreshToken>,
    meta: &mut BearerTokenMeta,
) -> Result<Option<RefreshGrantRecord>, &'static str> {
    let Some(refresh) = refresh else {
        if access.refresh_grant.is_some()
            || meta.refresh_grant.is_some()
            || meta.refresh_parent.is_some()
        {
            return Err("initial independent access cannot inherit a refresh grant");
        }
        return Ok(None);
    };
    if refresh.rotated || refresh.rotation_count != 0 {
        return Err("initial refresh grant cannot be a rotated generation");
    }
    if access.refresh_grant.is_none()
        && meta.refresh_grant.is_none()
        && refresh.refresh_grant.is_none()
    {
        let reference = RefreshGrantRef::new();
        access.refresh_grant = Some(reference.clone());
        meta.refresh_grant = Some(reference.clone());
        refresh.refresh_grant = Some(reference);
    }
    let reference = refresh
        .refresh_grant
        .as_ref()
        .ok_or("missing initial refresh grant")?;
    if !reference.supported()
        || access.refresh_grant.as_ref() != Some(reference)
        || meta.refresh_grant.as_ref() != Some(reference)
    {
        return Err("initial refresh grant references disagree");
    }
    Ok(Some(RefreshGrantRecord {
        version: 1,
        reference: reference.clone(),
        client_id: refresh.client_id.clone(),
        user_id: refresh.user_id.clone(),
        revoked: false,
        retain_until: descendant_deadline(access, meta, Some(refresh))?,
    }))
}

pub(super) fn access_reference<'a>(
    access: &'a AccessToken,
    meta: &'a BearerTokenMeta,
) -> Result<Option<&'a RefreshGrantRef>, &'static str> {
    super::token_consistency::bearer_metadata_matches_access_token(access, meta)?;
    if access.refresh_grant != meta.refresh_grant {
        return Err("access and metadata refresh grant references disagree");
    }
    match access.refresh_grant.as_ref() {
        Some(reference) if reference.supported() => Ok(Some(reference)),
        None if meta.refresh_parent.is_none() => Ok(None),
        _ => Err("legacy or unsupported refresh grant; authorize again"),
    }
}

#[cfg(test)]
impl super::TokenStore {
    pub(super) fn refresh_grant_active_locked(
        state: &super::TokenStoreState,
        token: &RefreshToken,
        now: SystemTime,
    ) -> bool {
        token.refresh_grant.as_ref().is_some_and(|reference| {
            state
                .refresh_grants
                .get(&reference.id)
                .is_some_and(|record| {
                    record.active(reference, &token.client_id, &token.user_id, now)
                        && record.retain_until >= token.expires_at
                })
        })
    }

    pub(super) fn access_grant_active_locked(
        state: &super::TokenStoreState,
        access: &AccessToken,
        now: SystemTime,
    ) -> bool {
        let Some(meta) = state.bearer_meta.get(&access.token) else {
            return false;
        };
        let Ok(reference) = access_reference(access, meta) else {
            return false;
        };
        reference.is_none_or(|reference| {
            state
                .refresh_grants
                .get(&reference.id)
                .is_some_and(|record| {
                    record.active(reference, &access.client_id, &access.user_id, now)
                        && descendant_deadline(access, meta, None)
                            .is_ok_and(|deadline| record.retain_until >= deadline)
                })
        })
    }

    pub(super) fn extend_refresh_grant_locked(
        state: &mut super::TokenStoreState,
        access: &AccessToken,
        meta: &BearerTokenMeta,
        refresh: Option<&RefreshToken>,
        now: SystemTime,
    ) -> Result<(), &'static str> {
        let Some(reference) = access_reference(access, meta)? else {
            return Ok(());
        };
        if refresh.is_some_and(|token| token.refresh_grant.as_ref() != Some(reference)) {
            return Err("descendant refresh grant references disagree");
        }
        let deadline = descendant_deadline(access, meta, refresh)?;
        let record = state
            .refresh_grants
            .get_mut(&reference.id)
            .ok_or("missing refresh grant")?;
        if !record.active(reference, &access.client_id, &access.user_id, now) {
            return Err("refresh grant is inactive");
        }
        record.retain_until = record.retain_until.max(deadline);
        Ok(())
    }

    pub(super) fn revoke_refresh_grant_locked(
        state: &mut super::TokenStoreState,
        refresh: &RefreshToken,
    ) {
        let Some(reference) = refresh.refresh_grant.as_ref() else {
            return;
        };
        let Some(record) = state.refresh_grants.get_mut(&reference.id) else {
            return;
        };
        if !record.matches(reference, &refresh.client_id, &refresh.user_id) {
            return;
        }
        record.revoked = true;
    }
}

impl super::TokenStore {
    /// Recheck stored grant authority for an observed metadata snapshot.
    pub(crate) fn try_bearer_grant_active(&self, meta: &BearerTokenMeta) -> Result<bool, String> {
        let Some(access) = self.try_verify_access_token(&meta.token_id)? else {
            return Ok(false);
        };
        let Ok(reference) = access_reference(&access, meta) else {
            return Ok(false);
        };
        let Some(reference) = reference else {
            return Ok(true);
        };
        let Ok(deadline) = descendant_deadline(&access, meta, None) else {
            return Ok(false);
        };
        match &self.backend {
            #[cfg(test)]
            super::TokenStoreBackend::InMemory(state) => {
                let state = super::read_lock(state, "observed_bearer_grant")?;
                Ok(state
                    .refresh_grants
                    .get(&reference.id)
                    .is_some_and(|record| {
                        record.active(
                            reference,
                            &access.client_id,
                            &access.user_id,
                            SystemTime::now(),
                        ) && record.retain_until >= deadline
                    }))
            }
            super::TokenStoreBackend::Redis(backend) => backend
                .observed_grant_active(reference, &access.client_id, &access.user_id, deadline)
                .map_err(|error| {
                    super::token_storage_error_message(&error, "observed_bearer_grant")
                }),
        }
    }

    pub(crate) async fn try_bearer_grant_active_async(
        &self,
        meta: BearerTokenMeta,
    ) -> Result<bool, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_bearer_grant_active(&meta))
            .await
            .map_err(|error| format!("token store worker failed: {error}"))?
    }
}
