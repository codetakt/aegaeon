use super::common::{
    inventory_fingerprint, seconds_since_epoch, user_runtime_store_error_response,
};
use crate::authcode::types::BearerTokenMeta;
use crate::management::types::UserGrantInventoryEntry;
use crate::web::management::AppState;
use axum::response::Response;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub(in crate::web::management) struct UserGrantTarget {
    pub(in crate::web::management) source: &'static str,
    pub(in crate::web::management) raw_token_id: String,
}

pub(in crate::web::management) async fn collect_user_grants(
    state: &AppState,
    subject: &str,
    request_id: &str,
) -> Result<Vec<UserGrantInventoryEntry>, Response> {
    let mut seen = HashSet::new();
    let mut grants = state
        .tokens
        .store
        .try_list_bearer_meta_for_subject_async(subject.to_string())
        .await
        .map_err(|err| {
            user_runtime_store_error_response(
                "token store",
                &err,
                "Grant inventory store unavailable",
                request_id,
            )
        })?
        .into_iter()
        .filter_map(user_grant_entry_from_meta)
        .filter(|grant| seen.insert(grant.id.clone()))
        .collect::<Vec<_>>();
    grants.sort_by(|left, right| {
        right
            .expires_at_epoch_seconds
            .cmp(&left.expires_at_epoch_seconds)
    });
    Ok(grants)
}

pub(in crate::web::management) async fn find_user_grant_target(
    state: &AppState,
    subject: &str,
    grant_id: &str,
    request_id: &str,
) -> Result<Option<UserGrantTarget>, Response> {
    state
        .tokens
        .store
        .try_list_bearer_meta_for_subject_async(subject.to_string())
        .await
        .map_err(|err| {
            user_runtime_store_error_response(
                "token store",
                &err,
                "Grant inventory store unavailable",
                request_id,
            )
        })
        .map(|metadata| {
            metadata
                .into_iter()
                .find_map(|meta| match meta.refresh_parent.as_deref() {
                    Some(refresh_parent) if inventory_fingerprint(refresh_parent) == grant_id => {
                        Some(UserGrantTarget {
                            source: "refresh_token",
                            raw_token_id: refresh_parent.to_string(),
                        })
                    }
                    _ if inventory_fingerprint(&meta.token_id) == grant_id => {
                        Some(UserGrantTarget {
                            source: "access_token",
                            raw_token_id: meta.token_id,
                        })
                    }
                    _ => None,
                })
        })
}

fn user_grant_entry_from_meta(meta: BearerTokenMeta) -> Option<UserGrantInventoryEntry> {
    let (id, source) = match meta.refresh_parent.as_deref() {
        Some(refresh_parent) => (inventory_fingerprint(refresh_parent), "refresh_token"),
        None => (inventory_fingerprint(&meta.token_id), "access_token"),
    };
    Some(UserGrantInventoryEntry {
        id,
        source: source.to_string(),
        client_id: meta.client_id,
        scopes: meta.granted_scopes,
        audience: meta.audience,
        authorization_details: meta.authorization_details,
        auth_time_epoch_seconds: meta.auth_time_epoch_secs,
        acr: meta.acr,
        expires_at_epoch_seconds: seconds_since_epoch(meta.expires_at)?,
    })
}
