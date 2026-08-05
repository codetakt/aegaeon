use super::super::{OidcLogoutEvent, OidcSessionContext, RedisOidcSessionGrantCommit};
use super::OidcSessionStorageError;
use crate::config::RuntimeStateNamespace;
use std::sync::Arc;

pub(super) const OIDC_LOGOUT_SESSION_REDIS_URL_ENV: &str = "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL";

mod keyspace;
#[path = "redis/maintenance.rs"]
mod maintenance;
#[path = "redis/scripts/mod.rs"]
mod scripts;

use keyspace::RedisOidcSessionKeyspace;

#[derive(Clone)]
pub(super) struct RedisOidcSessionBackend {
    client: redis::Client,
    url: Arc<str>,
    keyspace: RedisOidcSessionKeyspace,
}

impl RedisOidcSessionBackend {
    pub(super) fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, OidcSessionStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                url: Arc::from(url.to_string().into_boxed_str()),
                keyspace: RedisOidcSessionKeyspace::from_authorization_code_grant_namespace(
                    namespace,
                ),
            })
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
    pub(super) fn new_with_prefix(
        url: &str,
        prefix: impl Into<Arc<str>>,
    ) -> Result<Self, OidcSessionStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                url: Arc::from(url.to_string().into_boxed_str()),
                keyspace: RedisOidcSessionKeyspace::from_test_prefix(prefix),
            })
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<redis::Connection, OidcSessionStorageError> {
        self.client
            .get_connection()
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn get_or_create_session(
        &self,
        context: OidcSessionContext<'_>,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<String, OidcSessionStorageError> {
        let auth_session_key = self.keyspace.auth_session_key(context.auth_session_id);
        let user_sessions_key = self.keyspace.user_sessions_key(context.user_id);
        let sid = uuid::Builder::from_random_bytes(
            aegaeon_crypto::rand::random_bytes(16)
                .try_into()
                .expect("random_bytes(16) yields exactly 16 bytes"),
        )
        .into_uuid()
        .to_string();
        let mut conn = self.prepared_connection(now_epoch_secs, ttl_secs)?;
        redis::Script::new(scripts::GET_OR_CREATE_SESSION)
            .key(&auth_session_key)
            .key(self.keyspace.session_key(&sid))
            .key(self.keyspace.logged_out_expiries_key())
            .key(&user_sessions_key)
            .arg(context.user_id)
            .arg(auth_session_key)
            .arg(user_sessions_key)
            .arg(&sid)
            .arg(now_epoch_secs)
            .arg(ttl_secs)
            .arg(self.keyspace.session_key_prefix())
            .arg(self.keyspace.clients_key_prefix())
            .invoke::<String>(&mut conn)
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn prepare_authorization_code_grant_commit(
        &self,
        context: OidcSessionContext<'_>,
        client_id: &str,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<RedisOidcSessionGrantCommit, OidcSessionStorageError> {
        let auth_session_key = self.keyspace.auth_session_key(context.auth_session_id);
        let user_sessions_key = self.keyspace.user_sessions_key(context.user_id);
        let sid = self
            .active_sid_for_auth_session(&auth_session_key, &user_sessions_key, context.user_id)?
            .unwrap_or_else(|| {
                uuid::Builder::from_random_bytes(
                    aegaeon_crypto::rand::random_bytes(16)
                        .try_into()
                        .expect("random_bytes(16) yields exactly 16 bytes"),
                )
                .into_uuid()
                .to_string()
            });

        Ok(RedisOidcSessionGrantCommit {
            url: self.url.clone(),
            auth_session_key,
            session_key: self.keyspace.session_key(&sid),
            logged_out_expiries_key: self.keyspace.logged_out_expiries_key(),
            user_sessions_key,
            clients_key: self.keyspace.clients_key(&sid),
            user_id: context.user_id.to_string(),
            sid,
            now_epoch_secs,
            ttl_secs,
            session_key_prefix: self.keyspace.session_key_prefix(),
            clients_key_prefix: self.keyspace.clients_key_prefix(),
            client_id: client_id.to_string(),
        })
    }

    fn active_sid_for_auth_session(
        &self,
        auth_session_key: &str,
        user_sessions_key: &str,
        user_id: &str,
    ) -> Result<Option<String>, OidcSessionStorageError> {
        let mut conn = self.connection()?;
        let Some(current_sid) = redis::cmd("GET")
            .arg(auth_session_key)
            .query::<Option<String>>(&mut conn)
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))?
        else {
            return Ok(None);
        };

        let values = redis::cmd("HMGET")
            .arg(self.keyspace.session_key(&current_sid))
            .arg("user_id")
            .arg("auth_session_key")
            .arg("user_sessions_key")
            .arg("logout_jti")
            .arg("logged_out_at_epoch_secs")
            .query::<Vec<Option<String>>>(&mut conn)
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))?;
        if values.len() != 5 {
            return Ok(None);
        }

        let active = matches!(
            (
                values[0].as_deref(),
                values[1].as_deref(),
                values[2].as_deref(),
                values[3].as_deref(),
                values[4].as_deref(),
            ),
            (Some(stored_user), Some(stored_auth_key), Some(stored_user_sessions_key), Some(""), Some(""))
                if stored_user == user_id
                    && stored_auth_key == auth_session_key
                    && stored_user_sessions_key == user_sessions_key
        );
        if active {
            return Ok(Some(current_sid));
        }

        Ok(None)
    }

    pub(super) fn add_client(
        &self,
        sid: &str,
        client_id: &str,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<bool, OidcSessionStorageError> {
        let mut conn = self.prepared_connection(now_epoch_secs, ttl_secs)?;
        redis::Script::new(scripts::ADD_CLIENT)
            .key(self.keyspace.session_key(sid))
            .key(self.keyspace.clients_key(sid))
            .key(self.keyspace.logged_out_expiries_key())
            .arg(sid)
            .arg(client_id)
            .arg(now_epoch_secs)
            .arg(ttl_secs)
            .invoke::<i64>(&mut conn)
            .map(|value| value == 1)
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn logout_by_sid_at(
        &self,
        sid: &str,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<Option<OidcLogoutEvent>, OidcSessionStorageError> {
        let jti = uuid::Uuid::new_v4().to_string();
        let expiry_score = Self::logout_expiry_score(now_epoch_secs, ttl_secs);
        let mut conn = self.prepared_connection(now_epoch_secs, ttl_secs)?;
        redis::Script::new(scripts::LOGOUT_BY_SID)
            .key(self.keyspace.session_key(sid))
            .key(self.keyspace.clients_key(sid))
            .key(self.keyspace.logged_out_expiries_key())
            .arg(sid)
            .arg(now_epoch_secs)
            .arg(ttl_secs)
            .arg(jti)
            .arg(expiry_score)
            .invoke::<Option<Vec<String>>>(&mut conn)
            .map(|reply| reply.and_then(redis_oidc_logout_event))
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn logout_by_auth_session_id_at(
        &self,
        auth_session_id: &str,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<Option<OidcLogoutEvent>, OidcSessionStorageError> {
        let auth_session_key = self.keyspace.auth_session_key(auth_session_id);
        let mut conn = self.prepared_connection(now_epoch_secs, ttl_secs)?;
        let Some(sid) = redis::cmd("GET")
            .arg(&auth_session_key)
            .query::<Option<String>>(&mut conn)
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))?
        else {
            return Ok(None);
        };

        drop(conn);
        let event = self.logout_by_sid_at(&sid, now_epoch_secs, ttl_secs)?;
        if event.is_none() {
            let mut conn = self.connection()?;
            redis::Script::new(scripts::DELETE_AUTH_SESSION_ALIAS_IF_CURRENT)
                .key(&auth_session_key)
                .arg(&sid)
                .invoke::<i64>(&mut conn)
                .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))?;
        }
        Ok(event)
    }

    #[cfg(test)]
    pub(super) fn prune_expired_at(
        &self,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<(), OidcSessionStorageError> {
        let mut conn = self.connection()?;
        self.cleanup_expired_with_conn(&mut conn, now_epoch_secs, ttl_secs)
    }

    pub(super) fn logout_by_user_at(
        &self,
        user_id: &str,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<Vec<OidcLogoutEvent>, OidcSessionStorageError> {
        let user_sessions_key = self.keyspace.user_sessions_key(user_id);
        let jti_prefix = uuid::Uuid::new_v4().to_string();
        let expiry_score = Self::logout_expiry_score(now_epoch_secs, ttl_secs);
        let mut conn = self.prepared_connection(now_epoch_secs, ttl_secs)?;
        redis::Script::new(scripts::LOGOUT_BY_USER)
            .key(&user_sessions_key)
            .key(self.keyspace.logged_out_expiries_key())
            .arg(user_id)
            .arg(now_epoch_secs)
            .arg(ttl_secs)
            .arg(jti_prefix)
            .arg(expiry_score)
            .arg(self.keyspace.session_key_prefix())
            .arg(self.keyspace.clients_key_prefix())
            .invoke::<Vec<Vec<String>>>(&mut conn)
            .map(|events| {
                events
                    .into_iter()
                    .filter_map(redis_oidc_logout_event)
                    .collect()
            })
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))
    }
}

fn redis_oidc_logout_event(mut reply: Vec<String>) -> Option<OidcLogoutEvent> {
    if reply.len() < 3 {
        return None;
    }
    let mut client_ids = reply.split_off(3);
    client_ids.sort();
    let [sid, user_id, jti]: [String; 3] = reply.try_into().ok()?;
    Some(OidcLogoutEvent {
        sid,
        user_id,
        jti,
        client_ids,
    })
}
