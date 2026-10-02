//! Begin with an already-authorized offline grant; consent is a fixture premise.
use super::*;
use crate::authcode::types::{
    AccessToken, BearerTokenMeta, BearerTokenMetaInput, RefreshTargetContext, RefreshToken,
    RefreshTokenInput,
};
use std::time::{Duration, SystemTime};

const GRANTED_SCOPE: &str = "api.read offline_access";

pub(super) fn seed_grant(state: &AppState) -> TestResult<String> {
    let mut refresh = RefreshToken::new(RefreshTokenInput {
        scope: Some(GRANTED_SCOPE.to_string()),
        ..RefreshTokenInput::new(BASIC.to_string(), "snapshot-user".to_string())
    });
    let audience = format!("{}/userinfo", state.issuer);
    refresh.target_context = Some(RefreshTargetContext {
        version: 1,
        audience: audience.clone(),
        token_issuer: Some(state.issuer.to_string()),
        oidc_issuer: None,
    });
    let token = format!("initial-{}", Uuid::new_v4());
    let now = SystemTime::now();
    let access = AccessToken {
        exchange_root: None,
        client_credentials_digest: None,
        token: token.clone(),
        token_type: "Bearer".to_string(),
        client_id: BASIC.to_string(),
        user_id: refresh.user_id.clone(),
        scope: refresh.scope.clone(),
        expires_in: 300,
        created_at: now,
        cnf: None,
    };
    let meta = BearerTokenMeta::new(BearerTokenMetaInput {
        token_id: token,
        client_id: BASIC.to_string(),
        user_id: refresh.user_id.clone(),
        granted_scopes: GRANTED_SCOPE.split(' ').map(str::to_owned).collect(),
        audience,
        sender_binding: None,
        authorization_details: None,
        auth_time_epoch_secs: Some(0),
        acr: None,
        issued_at: now,
        expires_at: now + Duration::from_secs(300),
        refresh_parent: Some(refresh.token.clone()),
    });
    let value = refresh.token.clone();
    state
        .tokens
        .store
        .store_issued_grant(access, Some(refresh), meta)?;
    Ok(value)
}
