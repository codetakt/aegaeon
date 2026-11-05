use super::super::redis_support::{
    RedisRefreshPredecessorRecord, RedisRefreshSuccessorRecord, RedisTokenMutation,
};
use super::super::token_consistency::access_token_expired_at;
use super::RedisTokenStoreBackend;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::SystemTime;

impl RedisTokenStoreBackend {
    pub(super) fn collect_expired_refresh_links(
        &self,
        conn: &mut impl redis::ConnectionLike,
        token: &str,
        mutation: &mut RedisTokenMutation,
    ) -> Result<(), TokenStoreStorageError> {
        self.observed_refresh_children(conn, token, mutation)?;
        mutation.delete_key(self.keyspace.refresh_children_key(token));
        self.collect_refresh_successor(conn, token, mutation)?;
        let predecessor = Self::get_observed_json::<RedisRefreshPredecessorRecord>(
            conn,
            self.keyspace.refresh_predecessor_key(token),
            mutation,
        )?;
        self.collect_refresh_predecessor(conn, token, None, mutation)?;
        if let Some(predecessor) = predecessor {
            let key = self
                .keyspace
                .refresh_successor_key(&predecessor.predecessor_refresh);
            if let Some(record) =
                Self::get_observed_json::<RedisRefreshSuccessorRecord>(conn, key.clone(), mutation)?
            {
                if record.previous_refresh != predecessor.predecessor_refresh
                    || record.successor_refresh != token
                {
                    return Err(TokenStoreStorageError::InvariantViolation(
                        "refresh cleanup backlink mismatch".into(),
                    ));
                }
                mutation.delete_key(key);
            }
        }
        Ok(())
    }

    pub(super) fn collect_expired_tokens(
        &self,
        conn: &mut impl redis::ConnectionLike,
        now: SystemTime,
        mutation: &mut RedisTokenMutation,
    ) -> Result<(), TokenStoreStorageError> {
        for token in self.expired_index_members(conn, self.keyspace.expiry_access_key(), now)? {
            let record = Self::get_observed_json::<AccessToken>(
                conn,
                self.keyspace.access_key(&token),
                mutation,
            )?;
            if record.as_ref().is_some_and(|record| record.token != token) {
                return Err(TokenStoreStorageError::InvariantViolation(
                    "expired access identity mismatch".into(),
                ));
            }
            if record.is_none_or(|record| access_token_expired_at(&record, now)) {
                mutation.delete_access_token(token);
            }
        }
        for token in self.expired_index_members(conn, self.keyspace.expiry_refresh_key(), now)? {
            let record = Self::get_observed_json::<RefreshToken>(
                conn,
                self.keyspace.refresh_key(&token),
                mutation,
            )?;
            if record.as_ref().is_some_and(|record| record.token != token) {
                return Err(TokenStoreStorageError::InvariantViolation(
                    "expired refresh identity mismatch".into(),
                ));
            }
            match record {
                Some(record) if now >= record.expires_at => {
                    self.collect_expired_refresh_links(conn, &token, mutation)?;
                    mutation.delete_refresh_token(token);
                }
                None => {
                    // No root authorizes traversal. Reclaim only the exact orphan
                    // child index, including malformed historical residue.
                    Self::get_observed_raw(
                        conn,
                        self.keyspace.refresh_children_key(&token),
                        mutation,
                    )?;
                    mutation.delete_refresh_token(token);
                }
                Some(_) => {}
            }
        }
        for token in self.expired_index_members(conn, self.keyspace.expiry_bearer_key(), now)? {
            let record = Self::get_observed_json::<BearerTokenMeta>(
                conn,
                self.keyspace.bearer_key(&token),
                mutation,
            )?;
            if record
                .as_ref()
                .is_some_and(|record| record.token_id != token)
            {
                return Err(TokenStoreStorageError::InvariantViolation(
                    "expired bearer identity mismatch".into(),
                ));
            }
            if record.is_none_or(|record| now >= record.expires_at) {
                Self::get_observed_json::<AccessToken>(
                    conn,
                    self.keyspace.access_key(&token),
                    mutation,
                )?;
                mutation.delete_bearer_token(token);
            }
        }
        self.collect_expired_revoked(conn, now, mutation)
    }

    pub(in crate::authcode::store) fn cleanup_expired(&self) -> Result<(), TokenStoreStorageError> {
        self.with_lock("cleanup_expired_direct", |conn| {
            let now = SystemTime::now();
            self.cleanup_refresh_grants(conn, now)?;
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_tokens(conn, now, &mut mutation)?;
            let changed = !mutation.is_empty();
            self.apply_token_mutation(conn, mutation, changed)
        })
    }
}
