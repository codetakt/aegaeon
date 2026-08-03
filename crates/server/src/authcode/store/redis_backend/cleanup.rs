use super::super::redis_support::{
    RedisRefreshPredecessorRecord, RedisRefreshSuccessorRecord, RedisRevokedTokenRecord,
    RedisTokenMutation,
};
use super::super::token_consistency::access_token_expired_at;
use super::RedisTokenStoreBackend;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::SystemTime;

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store) fn cleanup_expired(&self) -> Result<(), TokenStoreStorageError> {
        self.with_lock("cleanup_expired_direct", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();

            for token in self.expired_index_members(conn, self.keyspace.expiry_access_key(), now)? {
                match Self::get_json::<AccessToken>(conn, self.keyspace.access_key(&token))? {
                    Some(record) if access_token_expired_at(&record, now) => {
                        mutation.delete_access_token(token);
                    }
                    None => mutation.delete_access_token(token),
                    Some(_) => {}
                }
            }

            for token in
                self.expired_index_members(conn, self.keyspace.expiry_refresh_key(), now)?
            {
                match Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(&token))? {
                    Some(record) if now >= record.expires_at => {
                        mutation.delete_refresh_token(token.clone());
                        mutation.delete_key(self.keyspace.refresh_children_key(&token));
                        mutation.delete_key(self.keyspace.refresh_successor_key(&token));
                        if let Some(successor) = Self::get_json::<RedisRefreshSuccessorRecord>(
                            conn,
                            self.keyspace.refresh_successor_key(&token),
                        )? {
                            mutation.delete_key(
                                self.keyspace
                                    .refresh_predecessor_key(&successor.successor_refresh),
                            );
                        }
                        if let Some(predecessor) = Self::get_json::<RedisRefreshPredecessorRecord>(
                            conn,
                            self.keyspace.refresh_predecessor_key(&token),
                        )? {
                            mutation.delete_key(
                                self.keyspace
                                    .refresh_successor_key(&predecessor.predecessor_refresh),
                            );
                        }
                        mutation.delete_key(self.keyspace.refresh_predecessor_key(&token));
                    }
                    None => mutation.delete_refresh_token(token),
                    Some(_) => {}
                }
            }

            for token in self.expired_index_members(conn, self.keyspace.expiry_bearer_key(), now)? {
                match Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(&token))? {
                    Some(record) if now >= record.expires_at => {
                        mutation.delete_bearer_token(token);
                    }
                    None => mutation.delete_bearer_token(token),
                    Some(_) => {}
                }
            }

            for token in
                self.expired_index_members(conn, self.keyspace.expiry_revoked_key(), now)?
            {
                match Self::get_json::<RedisRevokedTokenRecord>(
                    conn,
                    self.keyspace.revoked_key(&token),
                )? {
                    Some(record) if now >= record.expires_at => {
                        mutation.delete_revoked_token(token);
                    }
                    None => mutation.delete_revoked_token(token),
                    Some(_) => {}
                }
            }

            let changed = !mutation.is_empty();
            self.apply_token_mutation(conn, mutation, changed)
        })
    }
}
