use super::super::super::super::ManagementSession;
use super::super::super::{
    error::ManagementSessionStorageError, model::RedisManagementSession,
    RedisManagementSessionBackend,
};
use super::super::backend_unavailable;

impl RedisManagementSessionBackend {
    fn record(
        &self,
        conn: &mut redis::Connection,
        sid: &str,
    ) -> Result<Option<RedisManagementSession>, ManagementSessionStorageError> {
        redis::cmd("GET")
            .arg(self.keyspace.session_key(sid))
            .query::<Option<String>>(conn)
            .map_err(|err| backend_unavailable(&err))?
            .map(|payload| RedisManagementSession::decode(&payload))
            .transpose()
            .map_err(|err| backend_unavailable(&err))
    }

    pub(in crate::web::management::state) fn get(
        &self,
        sid: &str,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<Option<ManagementSession>, ManagementSessionStorageError> {
        let mut conn = self.connection()?;
        let Some(session) = self.record(&mut conn, sid)? else {
            let _ = self.delete_sid_with_conn(&mut conn, sid)?;
            return Ok(None);
        };
        if !session.is_live(now_epoch_secs, ttl_secs) {
            let _ = self.delete_sid_with_conn(&mut conn, sid)?;
            return Ok(None);
        }
        let Some(session) = session.to_session() else {
            let _ = self.delete_sid_with_conn(&mut conn, sid)?;
            return Ok(None);
        };
        Ok(Some(session))
    }
}
