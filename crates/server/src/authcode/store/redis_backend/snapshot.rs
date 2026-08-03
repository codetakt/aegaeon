use super::super::redis_support::decode_redis_json;
#[cfg(test)]
use super::super::redis_support::encode_redis_json;
use super::super::redis_support::RedisTokenStoreKeyspace;
#[cfg(test)]
use super::super::redis_support::{
    RedisRefreshChildrenRecord, RedisRefreshSuccessorRecord, RedisRevokedTokenRecord,
};
use super::RedisTokenStoreBackend;
#[cfg(test)]
use crate::authcode::store::TokenStoreState;
use crate::authcode::store::TokenStoreStorageError;
#[cfg(test)]
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};

impl RedisTokenStoreBackend {
    #[cfg(test)]
    pub(super) fn scan_keys(
        conn: &mut redis::Connection,
        pattern: &str,
    ) -> Result<Vec<String>, TokenStoreStorageError> {
        let mut cursor = 0_u64;
        let mut keys = Vec::new();
        loop {
            let (next, mut page): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(256)
                .query(conn)
                .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?;
            keys.append(&mut page);
            cursor = next;
            if cursor == 0 {
                return Ok(keys);
            }
        }
    }

    #[cfg(test)]
    fn load_json_map<T>(
        &self,
        conn: &mut redis::Connection,
        pattern: &str,
        mut insert: impl FnMut(&mut TokenStoreState, T),
        state: &mut TokenStoreState,
    ) -> Result<(), TokenStoreStorageError>
    where
        T: serde::de::DeserializeOwned,
    {
        for key in Self::scan_keys(conn, pattern)? {
            if let Some(payload) = redis::cmd("GET")
                .arg(key)
                .query::<Option<String>>(conn)
                .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?
            {
                insert(state, decode_redis_json::<T>(&payload)?);
            }
        }
        Ok(())
    }

    pub(super) fn get_json<T>(
        conn: &mut redis::Connection,
        key: String,
    ) -> Result<Option<T>, TokenStoreStorageError>
    where
        T: serde::de::DeserializeOwned,
    {
        redis::cmd("GET")
            .arg(key)
            .query::<Option<String>>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?
            .map(|payload| decode_redis_json::<T>(&payload))
            .transpose()
    }

    pub(super) fn increment_version(
        pipe: &mut redis::Pipeline,
        keyspace: &RedisTokenStoreKeyspace,
    ) {
        pipe.cmd("INCR").arg(keyspace.version_key()).ignore();
    }

    #[cfg(test)]
    fn load_state_unlocked(
        &self,
        conn: &mut redis::Connection,
    ) -> Result<TokenStoreState, TokenStoreStorageError> {
        let version = redis::cmd("GET")
            .arg(self.keyspace.version_key())
            .query::<Option<u64>>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?
            .unwrap_or(0);
        let mut state = TokenStoreState {
            version,
            ..TokenStoreState::default()
        };

        self.load_json_map::<AccessToken>(
            conn,
            &self.keyspace.pattern("access"),
            |state, token| {
                state.access_tokens.insert(token.token.clone(), token);
            },
            &mut state,
        )?;
        self.load_json_map::<RefreshToken>(
            conn,
            &self.keyspace.pattern("refresh"),
            |state, token| {
                state.refresh_tokens.insert(token.token.clone(), token);
            },
            &mut state,
        )?;
        self.load_json_map::<BearerTokenMeta>(
            conn,
            &self.keyspace.pattern("bearer"),
            |state, meta| {
                state.bearer_meta.insert(meta.token_id.clone(), meta);
            },
            &mut state,
        )?;
        self.load_json_map::<RedisRevokedTokenRecord>(
            conn,
            &self.keyspace.pattern("revoked"),
            |state, record| {
                state.revoked_tokens.insert(record.token, record.expires_at);
            },
            &mut state,
        )?;
        self.load_json_map::<RedisRefreshChildrenRecord>(
            conn,
            &self.keyspace.pattern("refresh-children"),
            |state, record| {
                state
                    .refresh_children
                    .insert(record.refresh_token, record.access_tokens);
            },
            &mut state,
        )?;
        self.load_json_map::<RedisRefreshSuccessorRecord>(
            conn,
            &self.keyspace.pattern("refresh-successor"),
            |state, record| {
                state
                    .refresh_successors
                    .insert(record.previous_refresh, record.successor_refresh);
            },
            &mut state,
        )?;

        Ok(state)
    }

    #[cfg(test)]
    fn write_state_unlocked(
        &self,
        conn: &mut redis::Connection,
        state: &TokenStoreState,
    ) -> Result<(), TokenStoreStorageError> {
        let mut keys = Self::scan_keys(conn, &self.keyspace.all_pattern())?;
        keys.retain(|key| key != &self.keyspace.lock_key());

        let mut pipe = redis::pipe();
        pipe.atomic();
        if !keys.is_empty() {
            pipe.cmd("DEL").arg(keys).ignore();
        }
        pipe.cmd("SET")
            .arg(self.keyspace.version_key())
            .arg(state.version)
            .ignore();
        for token in state.access_tokens.values() {
            pipe.cmd("SET")
                .arg(self.keyspace.access_key(&token.token))
                .arg(encode_redis_json(token)?)
                .ignore();
        }
        for token in state.refresh_tokens.values() {
            pipe.cmd("SET")
                .arg(self.keyspace.refresh_key(&token.token))
                .arg(encode_redis_json(token)?)
                .ignore();
        }
        for meta in state.bearer_meta.values() {
            pipe.cmd("SET")
                .arg(self.keyspace.bearer_key(&meta.token_id))
                .arg(encode_redis_json(meta)?)
                .ignore();
        }
        for (token, expires_at) in &state.revoked_tokens {
            let record = RedisRevokedTokenRecord {
                token: token.clone(),
                expires_at: *expires_at,
            };
            pipe.cmd("SET")
                .arg(self.keyspace.revoked_key(token))
                .arg(encode_redis_json(&record)?)
                .ignore();
        }
        for (refresh_token, access_tokens) in &state.refresh_children {
            let record = RedisRefreshChildrenRecord {
                refresh_token: refresh_token.clone(),
                access_tokens: access_tokens.clone(),
            };
            pipe.cmd("SET")
                .arg(self.keyspace.refresh_children_key(refresh_token))
                .arg(encode_redis_json(&record)?)
                .ignore();
        }
        for (previous_refresh, successor_refresh) in &state.refresh_successors {
            let record = RedisRefreshSuccessorRecord {
                previous_refresh: previous_refresh.clone(),
                successor_refresh: successor_refresh.clone(),
            };
            pipe.cmd("SET")
                .arg(self.keyspace.refresh_successor_key(previous_refresh))
                .arg(encode_redis_json(&record)?)
                .ignore();
        }
        pipe.query::<()>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
    pub(in crate::authcode::store) fn load_state(
        &self,
    ) -> Result<TokenStoreState, TokenStoreStorageError> {
        self.with_lock("load_state", |conn| self.load_state_unlocked(conn))
    }

    #[cfg(test)]
    pub(in crate::authcode::store) fn mutate_state<R, F>(
        &self,
        mut f: F,
    ) -> Result<R, TokenStoreStorageError>
    where
        F: FnMut(&mut TokenStoreState) -> R,
    {
        self.with_lock("mutate_state", |conn| {
            let mut state = self.load_state_unlocked(conn)?;
            let result = f(&mut state);
            self.write_state_unlocked(conn, &state)?;
            Ok(result)
        })
    }

    #[cfg(test)]
    pub(in crate::authcode::store) fn clear_for_test(&self) -> Result<(), TokenStoreStorageError> {
        let mut conn = self.connection()?;
        let keys = Self::scan_keys(&mut conn, &self.keyspace.all_pattern())?;
        if keys.is_empty() {
            return Ok(());
        }
        redis::cmd("DEL")
            .arg(keys)
            .query::<i64>(&mut conn)
            .map(|_| ())
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }
}
