use super::common::{
    inventory_fingerprint, seconds_since_epoch, user_runtime_store_error_response,
};
use crate::authcode::store::{TokenInventoryKind, TokenInventoryRecord, TokenInventoryTarget};
use crate::authcode::types::BearerTokenMeta;
use crate::management::types::UserGrantInventoryEntry;
use crate::web::management::AppState;
use axum::response::Response;

#[derive(Debug, Clone)]
pub(in crate::web::management) struct UserGrantTarget {
    pub(in crate::web::management) source: &'static str,
    pub(in crate::web::management) raw_token_id: String,
}

pub(in crate::web::management) async fn collect_user_grants(
    state: &AppState,
    subject: &str,
    query: &crate::web::management::PaginationQuery,
    request_id: &str,
) -> Result<crate::management::types::ListUserGrantsResponse, Response> {
    let (records, page_info) = super::common::token_inventory_page(
        state,
        subject,
        TokenInventoryKind::Grants,
        query,
        request_id,
    )
    .await?;
    Ok(crate::management::types::ListUserGrantsResponse {
        grants: records
            .into_iter()
            .filter_map(|record| match record {
                TokenInventoryRecord::Grant(meta) => user_grant_entry_from_meta(*meta),
                _ => None,
            })
            .collect(),
        page_info,
    })
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
        .find_inventory_token(subject, TokenInventoryKind::Grants, grant_id)
        .await
        .map(|target| {
            target.map(|target| match target {
                TokenInventoryTarget::Access(raw_token_id) => UserGrantTarget {
                    source: "access_token",
                    raw_token_id,
                },
                TokenInventoryTarget::Refresh(raw_token_id) => UserGrantTarget {
                    source: "refresh_token",
                    raw_token_id,
                },
            })
        })
        .map_err(|err| {
            user_runtime_store_error_response(
                "token store",
                &err,
                "Grant inventory store unavailable",
                request_id,
            )
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
