use crate::authcode::store::TokenStore;
use crate::authcode::types::{
    AccessToken, BearerTokenMeta, BearerTokenMetaInput, CnfClaim, SenderBinding,
};
use crate::middleware::tls::mtls_fingerprint_to_x5t_s256;
use serde_json::Value;
use std::time::{Duration, SystemTime};

pub(super) fn scope_members(
    scope: Option<&str>,
) -> Result<Vec<String>, crate::oauth_scope::ScopeStringError> {
    crate::oauth_scope::parse_optional_scope_string(scope)
}

pub(super) fn access_token_expires_at(
    created_at: SystemTime,
    expires_in: u64,
) -> Result<SystemTime, String> {
    created_at
        .checked_add(Duration::from_secs(expires_in))
        .ok_or_else(|| "access token expiry overflow".to_string())
}

pub(super) struct AccessTokenPersistence {
    pub(super) audience: String,
    pub(super) refresh_parent: Option<String>,
    pub(super) sender_binding: Option<SenderBinding>,
    pub(super) authorization_details: Option<Value>,
    pub(super) auth_time_epoch_secs: Option<i64>,
    pub(super) acr: Option<String>,
}

pub(super) async fn persist_access_with_meta_async(
    store: &TokenStore,
    mut access: AccessToken,
    persistence: AccessTokenPersistence,
) -> Result<(), String> {
    let AccessTokenPersistence {
        audience,
        refresh_parent,
        sender_binding,
        authorization_details,
        auth_time_epoch_secs,
        acr,
    } = persistence;

    access.cnf = match &sender_binding {
        Some(SenderBinding::DPoP { jkt }) => Some(CnfClaim::Jkt(jkt.clone())),
        Some(SenderBinding::Mtls { fingerprint }) => {
            mtls_fingerprint_to_x5t_s256(fingerprint).map(CnfClaim::X5tS256)
        }
        None => None,
    };
    let created_at = access.created_at;
    let expires_at = access_token_expires_at(created_at, access.expires_in)?;
    let token_id = access.token.clone();
    let client_id = access.client_id.clone();
    let user_id = access.user_id.clone();
    let granted_scopes = scope_members(access.scope.as_deref())
        .map_err(|error| format!("access token scope is invalid: {error}"))?;
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id,
        client_id,
        user_id,
        granted_scopes,
        audience,
        sender_binding: sender_binding.clone(),
        authorization_details,
        auth_time_epoch_secs,
        acr,
        issued_at: created_at,
        expires_at,
        refresh_parent,
    });
    if meta.refresh_parent.is_none() {
        store
            .store_issued_grant_async(access, None, meta)
            .await
            .map(|_| ())
    } else {
        store
            .store_access_for_refresh_parent_async(access, meta)
            .await
            .map(|_| ())
    }
}
