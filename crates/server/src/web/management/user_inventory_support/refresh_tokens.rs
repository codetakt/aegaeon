use super::common::{
    inventory_fingerprint, seconds_since_epoch, user_runtime_store_error_response,
};
use crate::authcode::types::{RefreshToken, SenderBinding};
use crate::management::types::UserRefreshTokenInventoryEntry;
use crate::web::management::AppState;
use axum::response::Response;

use crate::authcode::store::{TokenInventoryKind, TokenInventoryRecord, TokenInventoryTarget};
pub(in crate::web::management) async fn collect_user_refresh_tokens(
    state: &AppState,
    subject: &str,
    query: &crate::web::management::PaginationQuery,
    request_id: &str,
) -> Result<crate::management::types::ListUserRefreshTokensResponse, Response> {
    let (records, page_info) = super::common::token_inventory_page(
        state,
        subject,
        TokenInventoryKind::Refresh,
        query,
        request_id,
    )
    .await?;
    Ok(crate::management::types::ListUserRefreshTokensResponse {
        refresh_tokens: records
            .into_iter()
            .filter_map(|record| match record {
                TokenInventoryRecord::Refresh(token) => user_refresh_token_entry_from_token(*token),
                _ => None,
            })
            .collect(),
        page_info,
    })
}

pub(in crate::web::management) async fn find_user_refresh_token_raw(
    state: &AppState,
    subject: &str,
    refresh_token_id: &str,
    request_id: &str,
) -> Result<Option<String>, Response> {
    state
        .tokens
        .store
        .find_inventory_token(subject, TokenInventoryKind::Refresh, refresh_token_id)
        .await
        .map(|target| {
            target.and_then(|target| match target {
                TokenInventoryTarget::Refresh(raw) => Some(raw),
                _ => None,
            })
        })
        .map_err(|err| {
            user_runtime_store_error_response(
                "token store",
                &err,
                "Refresh token inventory store unavailable",
                request_id,
            )
        })
}

fn user_refresh_token_entry_from_token(
    token: RefreshToken,
) -> Option<UserRefreshTokenInventoryEntry> {
    Some(UserRefreshTokenInventoryEntry {
        id: inventory_fingerprint(&token.token),
        client_id: token.client_id,
        scopes: split_scope_list(token.scope.as_deref()),
        resource: token.resource,
        sender_binding: token.sender_binding.as_ref().map(sender_binding_label),
        authorization_details: token.authorization_details,
        auth_time_epoch_seconds: token.auth_time_epoch_secs,
        acr: token.acr,
        expires_at_epoch_seconds: seconds_since_epoch(token.expires_at)?,
        rotation_count: token.rotation_count,
    })
}

fn sender_binding_label(binding: &SenderBinding) -> String {
    match binding {
        SenderBinding::DPoP { .. } => "dpop".to_string(),
        SenderBinding::Mtls { .. } => "mtls".to_string(),
    }
}

fn split_scope_list(scope: Option<&str>) -> Vec<String> {
    scope
        .unwrap_or("")
        .split_whitespace()
        .filter(|value| !value.is_empty())
        .map(std::string::ToString::to_string)
        .collect()
}
