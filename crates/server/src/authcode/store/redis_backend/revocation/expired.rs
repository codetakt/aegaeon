use super::super::super::redis_support::{RedisRevokedTokenRecord, RedisTokenMutation};
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
            // Sorted-set scores are whole seconds; the record retains subsecond precision.
            if Self::get_observed_json::<RedisRevokedTokenRecord>(
                conn,
                self.keyspace.revoked_key(&token),
                mutation,
            )?
            .is_none_or(|record| record.expires_at <= now)
            {
                mutation.delete_revoked_token(token);
            }
        }
        Ok(())
    }
}
