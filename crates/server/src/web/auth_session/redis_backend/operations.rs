use super::super::redis_state::RedisAuthSession;
use super::super::AuthSession;
use super::{scripts, AuthSessionStorageError, RedisAuthSessionBackend};

impl RedisAuthSessionBackend {
    fn record(
        &self,
        conn: &mut redis::Connection,
        sid: &str,
    ) -> Result<Option<RedisAuthSession>, AuthSessionStorageError> {
        redis::cmd("GET")
            .arg(self.keyspace.session_key(sid))
            .query::<Option<String>>(conn)
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))?
            .map(|payload| Self::decode_session(&payload))
            .transpose()
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))
    }

    pub(in crate::web::auth_session) fn get(
        &self,
        sid: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<AuthSession>, AuthSessionStorageError> {
        let mut conn = self.connection()?;
        let Some(record) = self.record(&mut conn, sid)? else {
            let _ = self.delete_sid_with_conn(&mut conn, sid)?;
            return Ok(None);
        };
        if !RedisAuthSession::session_is_live(&record, now_epoch_secs) {
            let _ = self.delete_sid_with_conn(&mut conn, sid)?;
            return Ok(None);
        }
        let Some(session) = record.to_session() else {
            let _ = self.delete_sid_with_conn(&mut conn, sid)?;
            return Ok(None);
        };
        Ok(Some(session))
    }

    pub(in crate::web::auth_session) fn create(
        &self,
        sid: &str,
        session: &AuthSession,
        now_epoch_secs: u64,
        max_sessions: usize,
    ) -> Result<(), AuthSessionStorageError> {
        let record = RedisAuthSession::from_session(session);
        let payload = Self::encode_session(&record)?;
        let retention_secs = Self::retention_secs(record.expires_at_epoch_secs, now_epoch_secs)?;
        let user_sessions_key = self.keyspace.user_sessions_key(&record.user_id);
        let mut conn = self.connection()?;
        redis::Script::new(scripts::CREATE_SESSION)
            .key(self.keyspace.session_key(sid))
            .key(self.keyspace.sid_user_key(sid))
            .key(&user_sessions_key)
            .key(self.keyspace.all_sessions_key())
            .key(self.keyspace.expiries_key())
            .arg(sid)
            .arg(payload)
            .arg(user_sessions_key)
            .arg(record.created_at_epoch_secs)
            .arg(record.expires_at_epoch_secs)
            .arg(retention_secs)
            .arg(max_sessions)
            .arg(now_epoch_secs)
            .arg(self.keyspace.session_key_prefix())
            .arg(self.keyspace.sid_user_key_prefix())
            .invoke::<i64>(&mut conn)
            .map(|_| ())
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))
    }

    pub(in crate::web::auth_session) fn delete_sid(
        &self,
        sid: &str,
    ) -> Result<bool, AuthSessionStorageError> {
        let mut conn = self.connection()?;
        self.delete_sid_with_conn(&mut conn, sid)
    }

    fn delete_sid_with_conn(
        &self,
        conn: &mut redis::Connection,
        sid: &str,
    ) -> Result<bool, AuthSessionStorageError> {
        let sid_user_key = self.keyspace.sid_user_key(sid);
        let user_sessions_key = redis::cmd("GET")
            .arg(&sid_user_key)
            .query::<Option<String>>(conn)
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))?;
        let script = redis::Script::new(scripts::DELETE_SID);
        let mut invocation = script.prepare_invoke();
        invocation
            .key(self.keyspace.session_key(sid))
            .key(sid_user_key)
            .key(self.keyspace.all_sessions_key())
            .key(self.keyspace.expiries_key());
        if let Some(user_sessions_key) = user_sessions_key {
            invocation.key(user_sessions_key);
        }
        invocation
            .arg(sid)
            .invoke::<i64>(conn)
            .map(|removed| removed > 0)
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))
    }

    pub(in crate::web::auth_session) fn delete_for_user(
        &self,
        user_id: &str,
        now_epoch_secs: u64,
    ) -> Result<usize, AuthSessionStorageError> {
        let user_sessions_key = self.keyspace.user_sessions_key(user_id);
        let mut conn = self.connection()?;
        let sids = redis::cmd("SMEMBERS")
            .arg(&user_sessions_key)
            .query::<Vec<String>>(&mut conn)
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))?;
        sids.into_iter().try_fold(0usize, |removed, sid| {
            match self.record(&mut conn, &sid)? {
                Some(record)
                    if RedisAuthSession::session_is_live(&record, now_epoch_secs)
                        && record.user_id == user_id
                        && record.to_session().is_some() =>
                {
                    self.delete_sid_with_conn(&mut conn, &sid)
                        .map(|deleted| removed + usize::from(deleted))
                }
                Some(record) if RedisAuthSession::session_is_live(&record, now_epoch_secs) => {
                    redis::cmd("SREM")
                        .arg(&user_sessions_key)
                        .arg(&sid)
                        .query::<usize>(&mut conn)
                        .map_err(|err| {
                            AuthSessionStorageError::BackendUnavailable(err.to_string())
                        })?;
                    Ok(removed)
                }
                _ => self.delete_sid_with_conn(&mut conn, &sid).map(|_| removed),
            }
        })
    }

    pub(in crate::web::auth_session) fn list_for_user(
        &self,
        user_id: &str,
        now_epoch_secs: u64,
    ) -> Result<Vec<(String, AuthSession)>, AuthSessionStorageError> {
        let user_sessions_key = self.keyspace.user_sessions_key(user_id);
        let mut conn = self.connection()?;
        let sids = redis::cmd("SMEMBERS")
            .arg(&user_sessions_key)
            .query::<Vec<String>>(&mut conn)
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))?;
        sids.into_iter().try_fold(Vec::new(), |mut sessions, sid| {
            match self.record(&mut conn, &sid)? {
                Some(record)
                    if RedisAuthSession::session_is_live(&record, now_epoch_secs)
                        && record.user_id == user_id =>
                {
                    if let Some(session) = record.to_session() {
                        sessions.push((sid, session));
                    } else {
                        let _ = self.delete_sid_with_conn(&mut conn, &sid)?;
                    }
                }
                Some(record) if RedisAuthSession::session_is_live(&record, now_epoch_secs) => {
                    redis::cmd("SREM")
                        .arg(&user_sessions_key)
                        .arg(&sid)
                        .query::<usize>(&mut conn)
                        .map_err(|err| {
                            AuthSessionStorageError::BackendUnavailable(err.to_string())
                        })?;
                }
                _ => {
                    let _ = self.delete_sid_with_conn(&mut conn, &sid)?;
                }
            }
            Ok(sessions)
        })
    }

    pub(in crate::web::auth_session) fn delete_for_user_session(
        &self,
        user_id: &str,
        sid: &str,
        now_epoch_secs: u64,
    ) -> Result<bool, AuthSessionStorageError> {
        let mut conn = self.connection()?;
        let should_delete = self.record(&mut conn, sid)?.is_some_and(|record| {
            RedisAuthSession::session_is_live(&record, now_epoch_secs)
                && record.user_id == user_id
                && record.to_session().is_some()
        });
        if should_delete {
            self.delete_sid_with_conn(&mut conn, sid)
        } else {
            Ok(false)
        }
    }

    pub(in crate::web::auth_session) fn cleanup_expired(
        &self,
        now_epoch_secs: u64,
    ) -> Result<usize, AuthSessionStorageError> {
        let mut conn = self.connection()?;
        let expired_sids = redis::cmd("ZRANGEBYSCORE")
            .arg(self.keyspace.expiries_key())
            .arg("-inf")
            .arg(now_epoch_secs)
            .query::<Vec<String>>(&mut conn)
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))?;
        expired_sids.into_iter().try_fold(0usize, |removed, sid| {
            let should_delete = self
                .record(&mut conn, &sid)?
                .is_some_and(|record| !RedisAuthSession::session_is_live(&record, now_epoch_secs));
            self.delete_sid_with_conn(&mut conn, &sid)
                .map(|deleted| removed + usize::from(should_delete && deleted))
        })
    }
}
