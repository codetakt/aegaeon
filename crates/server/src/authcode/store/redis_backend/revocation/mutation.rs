use super::super::super::redis_support::{
    encode_redis_json, RedisRevokedTokenRecord, RedisTokenMutation,
};
use super::super::RedisTokenStoreBackend;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store::redis_backend) fn apply_token_mutation(
        &self,
        conn: &mut redis::Connection,
        mutation: RedisTokenMutation,
        increment_version: bool,
    ) -> Result<(), TokenStoreStorageError> {
        if mutation.is_empty() && !increment_version {
            return Ok(());
        }

        let access_records = mutation
            .delete_access_tokens
            .iter()
            .map(|token| {
                Self::get_json::<AccessToken>(conn, self.keyspace.access_key(token))
                    .map(|record| (token.clone(), record))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let refresh_records = mutation
            .delete_refresh_tokens
            .iter()
            .map(|token| {
                Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(token))
                    .map(|record| (token.clone(), record))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bearer_records = mutation
            .delete_bearer_tokens
            .iter()
            .map(|token| {
                let record =
                    Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(token))?;
                if record.as_ref().is_some_and(|meta| meta.token_id != *token) {
                    return Err(TokenStoreStorageError::InvariantViolation(
                        "bearer metadata token identity mismatch during cleanup".into(),
                    ));
                }
                let access_missing = record.is_some()
                    && Self::get_json::<AccessToken>(conn, self.keyspace.access_key(token))?
                        .is_none();
                Ok((token.clone(), record, access_missing))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut revoked_records = Vec::with_capacity(mutation.revoked_until.len());
        for (token, expires_at) in mutation.revoked_until {
            let expires_at = self
                .revoked_expires_at(conn, &token)?
                .filter(|existing| *existing > expires_at)
                .unwrap_or(expires_at);
            revoked_records.push((token, expires_at));
        }

        let mut pipe = redis::pipe();
        pipe.atomic();
        for (token, record) in &access_records {
            pipe.cmd("DEL")
                .arg(self.keyspace.access_key(token))
                .ignore();
            self.deindex_access_cmd(&mut pipe, token, record.as_ref());
        }
        for (token, record) in &refresh_records {
            pipe.cmd("DEL")
                .arg(self.keyspace.refresh_key(token))
                .ignore();
            self.deindex_refresh_cmd(&mut pipe, token, record.as_ref());
            if record.is_none() {
                pipe.cmd("DEL")
                    .arg(self.keyspace.refresh_children_key(token))
                    .ignore();
            }
        }
        for (token, record, access_missing) in &bearer_records {
            if let Some(meta) = record.as_ref().filter(|_| *access_missing) {
                // Metadata is the owner carrier when final access publication failed.
                // Prune before losing it; never remove an extant access membership.
                pipe.cmd("SREM")
                    .arg(self.keyspace.subject_access_key(&meta.user_id))
                    .arg(token)
                    .ignore();
            }
            pipe.cmd("DEL")
                .arg(self.keyspace.bearer_key(token))
                .ignore();
            self.deindex_bearer_cmd(&mut pipe, token, record.as_ref());
        }
        for token in &mutation.delete_revoked_tokens {
            pipe.cmd("DEL")
                .arg(self.keyspace.revoked_key(token))
                .ignore();
            self.deindex_revoked_cmd(&mut pipe, token);
        }
        if !mutation.delete_keys.is_empty() {
            pipe.cmd("DEL")
                .arg(mutation.delete_keys.into_iter().collect::<Vec<_>>())
                .ignore();
        }
        for (token, expires_at) in revoked_records {
            let record = RedisRevokedTokenRecord {
                token: token.clone(),
                expires_at,
            };
            pipe.cmd("SET")
                .arg(self.keyspace.revoked_key(&token))
                .arg(encode_redis_json(&record)?)
                .ignore();
            self.index_revoked_cmd(&mut pipe, &token, expires_at);
        }
        if increment_version {
            Self::increment_version(&mut pipe, &self.keyspace);
        }
        pipe.query::<()>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }
}
