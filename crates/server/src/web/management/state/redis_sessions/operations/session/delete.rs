use super::super::super::{
    error::ManagementSessionStorageError, scripts, RedisManagementSessionBackend,
};
use super::super::backend_unavailable;

impl RedisManagementSessionBackend {
    pub(in crate::web::management::state) fn delete_sid(
        &self,
        sid: &str,
    ) -> Result<bool, ManagementSessionStorageError> {
        let mut conn = self.connection()?;
        self.delete_sid_with_conn(&mut conn, sid)
    }

    pub(in crate::web::management::state::redis_sessions::operations::session) fn delete_sid_with_conn(
        &self,
        conn: &mut redis::Connection,
        sid: &str,
    ) -> Result<bool, ManagementSessionStorageError> {
        redis::Script::new(scripts::DELETE_SESSION)
            .key(self.keyspace.session_key(sid))
            .key(self.keyspace.all_sessions_key())
            .key(self.keyspace.expiries_key())
            .arg(sid)
            .invoke::<i64>(conn)
            .map(|removed| removed > 0)
            .map_err(|err| backend_unavailable(&err))
    }
}
