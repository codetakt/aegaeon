use super::super::super::{error::ManagementSessionStorageError, RedisManagementSessionBackend};
use super::super::backend_unavailable;

impl RedisManagementSessionBackend {
    pub(in crate::web::management::state) fn len(
        &self,
    ) -> Result<usize, ManagementSessionStorageError> {
        let mut conn = self.connection()?;
        redis::cmd("ZCARD")
            .arg(self.keyspace.all_sessions_key())
            .query::<usize>(&mut conn)
            .map_err(|err| backend_unavailable(&err))
    }
}
