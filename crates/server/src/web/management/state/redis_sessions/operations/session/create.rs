use super::super::super::super::ManagementSession;
use super::super::super::{
    error::ManagementSessionStorageError, model::RedisManagementSession, scripts,
    RedisManagementSessionBackend,
};
use super::super::backend_unavailable;

impl RedisManagementSessionBackend {
    pub(in crate::web::management::state) fn create(
        &self,
        sid: &str,
        session: &ManagementSession,
        now_epoch_secs: u64,
        ttl_secs: u64,
        max_sessions: usize,
    ) -> Result<(), ManagementSessionStorageError> {
        let session = RedisManagementSession::from_session(session);
        let payload = session.encode()?;
        let retention_secs = session.retention_secs(now_epoch_secs, ttl_secs)?;
        let expires_at_epoch_secs = session.expires_at_epoch_secs(ttl_secs)?;
        let mut conn = self.connection()?;
        redis::Script::new(scripts::CREATE_SESSION)
            .key(self.keyspace.session_key(sid))
            .key(self.keyspace.all_sessions_key())
            .key(self.keyspace.expiries_key())
            .arg(sid)
            .arg(payload)
            .arg(session.created_at_epoch_secs)
            .arg(expires_at_epoch_secs)
            .arg(retention_secs)
            .arg(max_sessions)
            .arg(now_epoch_secs)
            .arg(self.keyspace.session_key_prefix())
            .invoke::<i64>(&mut conn)
            .map(|_| ())
            .map_err(|err| backend_unavailable(&err))
    }
}
