use super::super::super::redis_support::{
    encode_redis_json, RedisRevokedTokenRecord, RedisTokenMutation,
};
use super::super::RedisTokenStoreBackend;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};

impl RedisTokenStoreBackend {
    fn bearer_cleanup_record(
        &self,
        conn: &mut impl redis::ConnectionLike,
        token: &str,
    ) -> Result<(Option<BearerTokenMeta>, bool), TokenStoreStorageError> {
        let record = Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(token))?;
        if record.as_ref().is_some_and(|meta| meta.token_id != token) {
            return Err(TokenStoreStorageError::InvariantViolation(
                "bearer metadata token identity mismatch during cleanup".into(),
            ));
        }
        let access_missing = record.is_some()
            && Self::get_json::<AccessToken>(conn, self.keyspace.access_key(token))?.is_none();
        Ok((record, access_missing))
    }

    fn validate_cleanup_observations(
        &self,
        mutation: &RedisTokenMutation,
    ) -> Result<(), TokenStoreStorageError> {
        let mut required = mutation.delete_keys.clone();
        for token in &mutation.delete_access_tokens {
            required.insert(self.keyspace.access_key(token));
        }
        for token in &mutation.delete_refresh_tokens {
            required.insert(self.keyspace.refresh_key(token));
            required.insert(self.keyspace.refresh_children_key(token));
        }
        for token in &mutation.delete_bearer_tokens {
            required.insert(self.keyspace.bearer_key(token));
            // Absence of the access record authorizes removal of its membership.
            required.insert(self.keyspace.access_key(token));
        }
        for token in &mutation.delete_revoked_tokens {
            required.insert(self.keyspace.revoked_key(token));
        }
        if required
            .iter()
            .any(|key| !mutation.observed_records.contains_key(key))
        {
            return Err(TokenStoreStorageError::InvariantViolation(
                "token cleanup requires original observations for every deletion".into(),
            ));
        }
        Ok(())
    }

    pub(in crate::authcode::store::redis_backend) fn apply_token_mutation(
        &self,
        conn: &mut impl redis::ConnectionLike,
        mut mutation: RedisTokenMutation,
        increment_version: bool,
    ) -> Result<(), TokenStoreStorageError> {
        self.validate_cleanup_observations(&mutation)?;
        let observed = std::mem::take(&mut mutation.observed_records);
        let mut watched: Vec<_> = observed.keys().cloned().collect();
        watched.extend(
            mutation
                .revoked_until
                .keys()
                .map(|token| self.keyspace.revoked_key(token)),
        );
        if watched.is_empty() {
            return self.apply_prepared_token_mutation(conn, mutation, increment_version);
        }
        redis::cmd("WATCH")
            .arg(watched)
            .query::<()>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?;
        let outcome = (|| {
            for (key, expected) in observed {
                let current = redis::cmd("GET")
                    .arg(key)
                    .query::<Option<String>>(conn)
                    .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?;
                if current != expected {
                    return Err(TokenStoreStorageError::InvariantViolation(
                        "token cleanup observation changed".into(),
                    ));
                }
            }
            self.apply_prepared_token_mutation(conn, mutation, increment_version)
        })();
        let unwatch = redis::cmd("UNWATCH")
            .query::<()>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()));
        outcome.and(unwatch)
    }

    fn apply_prepared_token_mutation(
        &self,
        conn: &mut impl redis::ConnectionLike,
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
                let (record, access_missing) = self.bearer_cleanup_record(conn, token)?;
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
        pipe.query::<Option<()>>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?
            .ok_or_else(|| {
                TokenStoreStorageError::InvariantViolation(
                    "token cleanup transaction invalidated".into(),
                )
            })
    }
}

#[cfg(test)]
mod tests;
