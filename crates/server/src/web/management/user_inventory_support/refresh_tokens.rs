use super::common::{
    inventory_fingerprint, seconds_since_epoch, user_runtime_store_error_response,
};
use crate::authcode::types::{RefreshToken, SenderBinding};
use crate::management::types::UserRefreshTokenInventoryEntry;
use crate::web::management::AppState;
use axum::response::Response;

pub(in crate::web::management) async fn collect_user_refresh_tokens(
    state: &AppState,
    subject: &str,
    request_id: &str,
) -> Result<Vec<UserRefreshTokenInventoryEntry>, Response> {
    let mut refresh_tokens = state
        .tokens
        .store
        .try_list_refresh_tokens_for_subject_async(subject.to_string())
        .await
        .map_err(|err| {
            user_runtime_store_error_response(
                "token store",
                &err,
                "Refresh token inventory store unavailable",
                request_id,
            )
        })?
        .into_iter()
        .filter_map(user_refresh_token_entry_from_token)
        .collect::<Vec<_>>();
    refresh_tokens.sort_by(|left, right| {
        right
            .expires_at_epoch_seconds
            .cmp(&left.expires_at_epoch_seconds)
    });
    Ok(refresh_tokens)
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
        .try_list_refresh_tokens_for_subject_async(subject.to_string())
        .await
        .map_err(|err| {
            user_runtime_store_error_response(
                "token store",
                &err,
                "Refresh token inventory store unavailable",
                request_id,
            )
        })
        .map(|tokens| {
            tokens.into_iter().find_map(|token| {
                (inventory_fingerprint(&token.token) == refresh_token_id).then_some(token.token)
            })
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
