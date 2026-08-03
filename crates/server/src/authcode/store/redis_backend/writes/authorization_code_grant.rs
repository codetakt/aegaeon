use super::super::super::redis_support::{
    access_token_expires_at, encode_redis_json, system_time_epoch_secs,
};
use super::super::scripts::{
    invoke_authorization_code_grant_commit, AuthorizationCodeGrantCommitArgs,
    AuthorizationCodeGrantCommitKeys,
};
use super::super::RedisTokenStoreBackend;
use crate::authcode::code_store::AuthCodeRedisCommitContext;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use crate::config::redis_store_urls_reference_same_endpoint;
use crate::oidc::RedisOidcSessionGrantCommit;

pub(super) struct AuthorizationCodeGrantCommitPlan {
    keys: AuthorizationCodeGrantCommitKeyPlan,
    args: AuthorizationCodeGrantCommitArgPlan,
}

struct AuthorizationCodeGrantCommitKeyPlan {
    auth_code: String,
    auth_code_version: String,
    token_version: String,
    access: String,
    subject_access: String,
    access_expiry: String,
    refresh: String,
    subject_refresh: String,
    refresh_expiry: String,
    refresh_children: String,
    bearer: String,
    subject_bearer: String,
    bearer_expiry: String,
    oidc_auth_session: String,
    oidc_session: String,
    oidc_logged_out_expiries: String,
    oidc_user_sessions: String,
    oidc_clients: String,
}

struct AuthorizationCodeGrantCommitArgPlan {
    access_payload: String,
    refresh_payload: String,
    bearer_payload: String,
    access_token: String,
    access_expires_at_epoch_secs: u64,
    has_refresh: bool,
    refresh_token: String,
    refresh_expires_at_epoch_secs: u64,
    bearer_token_id: String,
    bearer_expires_at_epoch_secs: u64,
    has_oidc_session: bool,
    oidc_user_id: String,
    oidc_auth_session_key: String,
    oidc_user_sessions_key: String,
    oidc_sid: String,
    oidc_now_epoch_secs: u64,
    oidc_ttl_secs: u64,
    oidc_session_key_prefix: String,
    oidc_clients_key_prefix: String,
    oidc_client_id: String,
    expected_code_payload: String,
}

impl AuthorizationCodeGrantCommitPlan {
    pub(super) fn new(
        backend: &RedisTokenStoreBackend,
        auth_code: &AuthCodeRedisCommitContext,
        expected_auth_code_payload: &str,
        access_token: &AccessToken,
        refresh_token: Option<&RefreshToken>,
        meta: &BearerTokenMeta,
        oidc_session: Option<&RedisOidcSessionGrantCommit>,
    ) -> Result<Self, TokenStoreStorageError> {
        validate_shared_redis_url(backend, auth_code, oidc_session)?;

        let access_token_payload = encode_redis_json(access_token)?;
        let refresh_token_payload = refresh_token
            .map(encode_redis_json)
            .transpose()?
            .unwrap_or_default();
        let bearer_payload = encode_redis_json(meta)?;

        let token_version = backend.keyspace.version_key();
        let absent_refresh_key = token_version.clone();
        let absent_oidc_key = token_version.clone();

        Ok(Self {
            keys: AuthorizationCodeGrantCommitKeyPlan {
                auth_code: auth_code.code_key.clone(),
                auth_code_version: auth_code.version_key.clone(),
                token_version: token_version.clone(),
                access: backend.keyspace.access_key(&access_token.token),
                subject_access: backend.keyspace.subject_access_key(&access_token.user_id),
                access_expiry: backend.keyspace.expiry_access_key(),
                refresh: refresh_token
                    .map(|token| backend.keyspace.refresh_key(&token.token))
                    .unwrap_or_else(|| absent_refresh_key.clone()),
                subject_refresh: refresh_token
                    .map(|token| backend.keyspace.subject_refresh_key(&token.user_id))
                    .unwrap_or_else(|| absent_refresh_key.clone()),
                refresh_expiry: backend.keyspace.expiry_refresh_key(),
                refresh_children: refresh_token
                    .map(|token| backend.keyspace.refresh_children_key(&token.token))
                    .unwrap_or_else(|| absent_refresh_key.clone()),
                bearer: backend.keyspace.bearer_key(&meta.token_id),
                subject_bearer: backend.keyspace.subject_bearer_key(&meta.user_id),
                bearer_expiry: backend.keyspace.expiry_bearer_key(),
                oidc_auth_session: oidc_session
                    .map(|session| session.auth_session_key.clone())
                    .unwrap_or_else(|| absent_oidc_key.clone()),
                oidc_session: oidc_session
                    .map(|session| session.session_key.clone())
                    .unwrap_or_else(|| absent_oidc_key.clone()),
                oidc_logged_out_expiries: oidc_session
                    .map(|session| session.logged_out_expiries_key.clone())
                    .unwrap_or_else(|| absent_oidc_key.clone()),
                oidc_user_sessions: oidc_session
                    .map(|session| session.user_sessions_key.clone())
                    .unwrap_or_else(|| absent_oidc_key.clone()),
                oidc_clients: oidc_session
                    .map(|session| session.clients_key.clone())
                    .unwrap_or(absent_oidc_key),
            },
            args: AuthorizationCodeGrantCommitArgPlan {
                access_payload: access_token_payload,
                refresh_payload: refresh_token_payload,
                bearer_payload,
                access_token: access_token.token.clone(),
                access_expires_at_epoch_secs: system_time_epoch_secs(access_token_expires_at(
                    access_token,
                )),
                has_refresh: refresh_token.is_some(),
                refresh_token: refresh_token
                    .map(|token| token.token.clone())
                    .unwrap_or_default(),
                refresh_expires_at_epoch_secs: refresh_token
                    .map(|token| system_time_epoch_secs(token.expires_at))
                    .unwrap_or_default(),
                bearer_token_id: meta.token_id.clone(),
                bearer_expires_at_epoch_secs: system_time_epoch_secs(meta.expires_at),
                has_oidc_session: oidc_session.is_some(),
                oidc_user_id: oidc_session
                    .map(|session| session.user_id.clone())
                    .unwrap_or_default(),
                oidc_auth_session_key: oidc_session
                    .map(|session| session.auth_session_key.clone())
                    .unwrap_or_default(),
                oidc_user_sessions_key: oidc_session
                    .map(|session| session.user_sessions_key.clone())
                    .unwrap_or_default(),
                oidc_sid: oidc_session
                    .map(|session| session.sid.clone())
                    .unwrap_or_default(),
                oidc_now_epoch_secs: oidc_session.map_or(0, |session| session.now_epoch_secs),
                oidc_ttl_secs: oidc_session.map_or(0, |session| session.ttl_secs),
                oidc_session_key_prefix: oidc_session
                    .map(|session| session.session_key_prefix.clone())
                    .unwrap_or_default(),
                oidc_clients_key_prefix: oidc_session
                    .map(|session| session.clients_key_prefix.clone())
                    .unwrap_or_default(),
                oidc_client_id: oidc_session
                    .map(|session| session.client_id.clone())
                    .unwrap_or_default(),
                expected_code_payload: expected_auth_code_payload.to_string(),
            },
        })
    }

    pub(super) fn invoke(
        &self,
        conn: &mut redis::Connection,
    ) -> Result<String, TokenStoreStorageError> {
        invoke_authorization_code_grant_commit(
            conn,
            AuthorizationCodeGrantCommitKeys {
                auth_code: self.keys.auth_code.as_str(),
                auth_code_version: self.keys.auth_code_version.as_str(),
                token_version: self.keys.token_version.as_str(),
                access: self.keys.access.as_str(),
                subject_access: self.keys.subject_access.as_str(),
                access_expiry: self.keys.access_expiry.as_str(),
                refresh: self.keys.refresh.as_str(),
                subject_refresh: self.keys.subject_refresh.as_str(),
                refresh_expiry: self.keys.refresh_expiry.as_str(),
                refresh_children: self.keys.refresh_children.as_str(),
                bearer: self.keys.bearer.as_str(),
                subject_bearer: self.keys.subject_bearer.as_str(),
                bearer_expiry: self.keys.bearer_expiry.as_str(),
                oidc_auth_session: self.keys.oidc_auth_session.as_str(),
                oidc_session: self.keys.oidc_session.as_str(),
                oidc_logged_out_expiries: self.keys.oidc_logged_out_expiries.as_str(),
                oidc_user_sessions: self.keys.oidc_user_sessions.as_str(),
                oidc_clients: self.keys.oidc_clients.as_str(),
            },
            AuthorizationCodeGrantCommitArgs {
                access_payload: self.args.access_payload.as_str(),
                refresh_payload: self.args.refresh_payload.as_str(),
                bearer_payload: self.args.bearer_payload.as_str(),
                access_token: self.args.access_token.as_str(),
                access_expires_at_epoch_secs: self.args.access_expires_at_epoch_secs,
                has_refresh: self.args.has_refresh,
                refresh_token: self.args.refresh_token.as_str(),
                refresh_expires_at_epoch_secs: self.args.refresh_expires_at_epoch_secs,
                bearer_token_id: self.args.bearer_token_id.as_str(),
                bearer_expires_at_epoch_secs: self.args.bearer_expires_at_epoch_secs,
                has_oidc_session: self.args.has_oidc_session,
                oidc_user_id: self.args.oidc_user_id.as_str(),
                oidc_auth_session_key: self.args.oidc_auth_session_key.as_str(),
                oidc_user_sessions_key: self.args.oidc_user_sessions_key.as_str(),
                oidc_sid: self.args.oidc_sid.as_str(),
                oidc_now_epoch_secs: self.args.oidc_now_epoch_secs,
                oidc_ttl_secs: self.args.oidc_ttl_secs,
                oidc_session_key_prefix: self.args.oidc_session_key_prefix.as_str(),
                oidc_clients_key_prefix: self.args.oidc_clients_key_prefix.as_str(),
                oidc_client_id: self.args.oidc_client_id.as_str(),
                expected_code_payload: self.args.expected_code_payload.as_str(),
            },
        )
        .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }
}

fn validate_shared_redis_url(
    backend: &RedisTokenStoreBackend,
    auth_code: &AuthCodeRedisCommitContext,
    oidc_session: Option<&RedisOidcSessionGrantCommit>,
) -> Result<(), TokenStoreStorageError> {
    if !redis_store_urls_reference_same_endpoint(backend.url.as_ref(), auth_code.url.as_ref()) {
        return Err(TokenStoreStorageError::BackendUnavailable(
            "authorization code and token store Redis URLs must match for atomic grant commit"
                .to_string(),
        ));
    }
    if let Some(oidc_session) = oidc_session {
        if !redis_store_urls_reference_same_endpoint(
            backend.url.as_ref(),
            oidc_session.url.as_ref(),
        ) {
            return Err(TokenStoreStorageError::BackendUnavailable(
                "OIDC session store Redis URL must match the authorization-code and token store Redis URL for atomic authorization-code grant commit".to_string(),
            ));
        }
    }
    Ok(())
}
