use super::super::super::redis_support::RedisTokenMutation;
use super::super::RedisTokenStoreBackend;
use crate::authcode::store::TokenStoreStorageError;
use std::time::SystemTime;

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store::redis_backend) fn collect_expired_revoked(
        &self,
        conn: &mut redis::Connection,
        now: SystemTime,
        mutation: &mut RedisTokenMutation,
    ) -> Result<(), TokenStoreStorageError> {
        for token in self.expired_index_members(conn, self.keyspace.expiry_revoked_key(), now)? {
            mutation.delete_revoked_token(token);
        }
        Ok(())
    }
}
