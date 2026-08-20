use super::super::redis_support::{
    access_token_expires_at, decode_redis_json, encode_redis_json, system_time_epoch_secs,
    RedisRefreshChildrenRecord, RedisRefreshPredecessorRecord, RedisRefreshSuccessorRecord,
    RedisTokenMutation, TOKEN_STORE_REDIS_LOCK_RETRIES, TOKEN_STORE_REDIS_LOCK_RETRY_DELAY_MS,
};
use super::scripts::{
    invoke_refresh_rotation_commit, RefreshRotationCommitArgs, RefreshRotationCommitKeys,
};
use super::RedisTokenStoreBackend;
use crate::authcode::store::{RefreshRotationError, TokenStoreStorageError};
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

const REFRESH_ROTATION_OUTCOME_OK: &str = "ok";
const REFRESH_ROTATION_OUTCOME_BUSY: &str = "busy";
const REFRESH_ROTATION_OUTCOME_STALE: &str = "stale";
const REFRESH_ROTATION_OUTCOME_INVALID: &str = "invalid";
const REFRESH_ROTATION_OUTCOME_REUSED: &str = "reused";
const REFRESH_ROTATION_OUTCOME_EXPIRED: &str = "expired";
const REFRESH_ROTATION_OUTCOME_TOKEN_COLLISION: &str = "token_collision";
const REFRESH_ROTATION_OUTCOME_REFRESH_DECODE: &str = "refresh_decode";

impl RedisTokenStoreBackend {
    fn refresh_rotation_storage_error(outcome: &str) -> TokenStoreStorageError {
        match outcome {
            REFRESH_ROTATION_OUTCOME_TOKEN_COLLISION => TokenStoreStorageError::InvariantViolation(
                "refresh rotation would overwrite existing token store key".to_string(),
            ),
            REFRESH_ROTATION_OUTCOME_REFRESH_DECODE => TokenStoreStorageError::Codec(
                "refresh rotation script could not decode stored refresh state".to_string(),
            ),
            other => TokenStoreStorageError::BackendUnavailable(format!(
                "unexpected refresh rotation commit outcome: {other}"
            )),
        }
    }

    fn load_refresh_payload(
        conn: &mut redis::Connection,
        refresh_key: String,
    ) -> Result<Option<String>, TokenStoreStorageError> {
        redis::cmd("GET")
            .arg(refresh_key)
            .query::<Option<String>>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "existing atomic Redis orchestration; new oversized functions remain gated"
    )]
    fn invoke_refresh_rotation_commit_once(
        &self,
        conn: &mut redis::Connection,
        previous_refresh: &str,
        new_refresh: &RefreshToken,
        grant: Option<(&AccessToken, &BearerTokenMeta)>,
    ) -> Result<String, TokenStoreStorageError> {
        let previous_refresh_key = self.keyspace.refresh_key(previous_refresh);
        let Some(expected_previous_payload) =
            Self::load_refresh_payload(conn, previous_refresh_key.clone())?
        else {
            return Ok(REFRESH_ROTATION_OUTCOME_INVALID.to_string());
        };

        let previous = decode_redis_json::<RefreshToken>(&expected_previous_payload)?;
        if previous.rotated {
            return Ok(REFRESH_ROTATION_OUTCOME_REUSED.to_string());
        }

        let mut rotated_previous = previous;
        rotated_previous.rotated = true;

        let mut new_children = HashSet::new();
        if let Some((access_token, _)) = grant {
            new_children.insert(access_token.token.clone());
        }
        let new_children_payload = encode_redis_json(&RedisRefreshChildrenRecord {
            refresh_token: new_refresh.token.clone(),
            access_tokens: new_children,
        })?;
        let successor_payload = encode_redis_json(&RedisRefreshSuccessorRecord {
            previous_refresh: previous_refresh.to_string(),
            successor_refresh: new_refresh.token.clone(),
        })?;
        let predecessor_payload = encode_redis_json(&RedisRefreshPredecessorRecord {
            refresh_token: new_refresh.token.clone(),
            predecessor_refresh: previous_refresh.to_string(),
        })?;
        let previous_subject_refresh_key =
            self.keyspace.subject_refresh_key(&rotated_previous.user_id);
        let new_subject_refresh_key = self.keyspace.subject_refresh_key(&new_refresh.user_id);
        let rotated_previous_payload = encode_redis_json(&rotated_previous)?;
        let new_refresh_payload = encode_redis_json(new_refresh)?;

        let dummy_key = self.keyspace.version_key();
        let (access_payload, access_token_value, access_expires_at, access_key, subject_access_key) =
            if let Some((access_token, _)) = grant {
                (
                    encode_redis_json(access_token)?,
                    access_token.token.as_str(),
                    system_time_epoch_secs(access_token_expires_at(access_token)),
                    self.keyspace.access_key(&access_token.token),
                    self.keyspace.subject_access_key(&access_token.user_id),
                )
            } else {
                (String::new(), "", 0, dummy_key.clone(), dummy_key.clone())
            };
        let (bearer_payload, bearer_token_id, bearer_expires_at, bearer_key, subject_bearer_key) =
            if let Some((_, meta)) = grant {
                (
                    encode_redis_json(meta)?,
                    meta.token_id.as_str(),
                    system_time_epoch_secs(meta.expires_at),
                    self.keyspace.bearer_key(&meta.token_id),
                    self.keyspace.subject_bearer_key(&meta.user_id),
                )
            } else {
                (String::new(), "", 0, dummy_key.clone(), dummy_key.clone())
            };

        invoke_refresh_rotation_commit(
            conn,
            RefreshRotationCommitKeys {
                mutation_barrier: self.keyspace.lock_key().as_str(),
                previous_refresh: previous_refresh_key.as_str(),
                previous_revoked: self.keyspace.revoked_key(previous_refresh).as_str(),
                revoked_expiry: self.keyspace.expiry_revoked_key().as_str(),
                previous_children: self
                    .keyspace
                    .refresh_children_key(previous_refresh)
                    .as_str(),
                previous_successor: self
                    .keyspace
                    .refresh_successor_key(previous_refresh)
                    .as_str(),
                previous_predecessor: self
                    .keyspace
                    .refresh_predecessor_key(previous_refresh)
                    .as_str(),
                new_predecessor: self
                    .keyspace
                    .refresh_predecessor_key(&new_refresh.token)
                    .as_str(),
                new_refresh: self.keyspace.refresh_key(&new_refresh.token).as_str(),
                previous_subject_refresh: previous_subject_refresh_key.as_str(),
                subject_refresh: new_subject_refresh_key.as_str(),
                refresh_expiry: self.keyspace.expiry_refresh_key().as_str(),
                new_children: self
                    .keyspace
                    .refresh_children_key(&new_refresh.token)
                    .as_str(),
                access: access_key.as_str(),
                subject_access: subject_access_key.as_str(),
                access_expiry: self.keyspace.expiry_access_key().as_str(),
                bearer: bearer_key.as_str(),
                subject_bearer: subject_bearer_key.as_str(),
                bearer_expiry: self.keyspace.expiry_bearer_key().as_str(),
                version: dummy_key.as_str(),
            },
            RefreshRotationCommitArgs {
                now_epoch_secs: system_time_epoch_secs(SystemTime::now()),
                previous_refresh_token: previous_refresh,
                expected_previous_payload: expected_previous_payload.as_str(),
                rotated_previous_payload: rotated_previous_payload.as_str(),
                new_refresh_payload: new_refresh_payload.as_str(),
                new_refresh_token: new_refresh.token.as_str(),
                new_refresh_expires_at_epoch_secs: system_time_epoch_secs(new_refresh.expires_at),
                successor_payload: successor_payload.as_str(),
                predecessor_payload: predecessor_payload.as_str(),
                new_children_payload: new_children_payload.as_str(),
                has_grant: grant.is_some(),
                access_payload: access_payload.as_str(),
                access_token: access_token_value,
                access_expires_at_epoch_secs: access_expires_at,
                bearer_payload: bearer_payload.as_str(),
                bearer_token_id,
                bearer_expires_at_epoch_secs: bearer_expires_at,
            },
        )
        .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }

    fn commit_refresh_rotation_with_retry(
        &self,
        previous_refresh: &str,
        new_refresh: &RefreshToken,
        grant: Option<(&AccessToken, &BearerTokenMeta)>,
    ) -> Result<String, TokenStoreStorageError> {
        let mut conn = self.connection()?;
        for _ in 0..TOKEN_STORE_REDIS_LOCK_RETRIES {
            let outcome = self.invoke_refresh_rotation_commit_once(
                &mut conn,
                previous_refresh,
                new_refresh,
                grant,
            )?;
            if matches!(
                outcome.as_str(),
                REFRESH_ROTATION_OUTCOME_BUSY | REFRESH_ROTATION_OUTCOME_STALE
            ) {
                thread::sleep(Duration::from_millis(TOKEN_STORE_REDIS_LOCK_RETRY_DELAY_MS));
                continue;
            }
            return Ok(outcome);
        }
        Err(TokenStoreStorageError::BackendUnavailable(
            "timed out waiting for Redis token store mutation barrier during refresh rotation"
                .to_string(),
        ))
    }

    fn revoke_reused_refresh_family(&self, refresh: &str) -> Result<usize, TokenStoreStorageError> {
        self.with_lock("revoke_reused_refresh_family_direct", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_revoked(conn, now, &mut mutation)?;
            let child_count =
                self.revoke_refresh_family_direct(conn, refresh, now, &mut mutation)?;
            self.apply_token_mutation(conn, mutation, true)?;
            Ok(child_count)
        })
    }

    pub(in crate::authcode::store) fn prepare_refresh_rotation(
        &self,
        token: &str,
    ) -> Result<(Result<RefreshToken, RefreshRotationError>, Option<usize>), TokenStoreStorageError>
    {
        self.with_lock("prepare_refresh_rotation_direct", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_revoked(conn, now, &mut mutation)?;

            if self.is_revoked_direct(conn, token, now)? {
                self.apply_token_mutation(conn, mutation, false)?;
                return Ok((Err(RefreshRotationError::Invalid), None));
            }

            let Some(refresh) =
                Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(token))?
            else {
                self.apply_token_mutation(conn, mutation, false)?;
                return Ok((Err(RefreshRotationError::Invalid), None));
            };

            if refresh.rotated {
                let child_count =
                    self.revoke_refresh_family_direct(conn, token, now, &mut mutation)?;
                self.apply_token_mutation(conn, mutation, true)?;
                return Ok((Err(RefreshRotationError::Reused), Some(child_count)));
            }

            if now >= refresh.expires_at {
                mutation.delete_refresh_token(token.to_string());
                mutation.delete_key(self.keyspace.refresh_children_key(token));
                mutation.delete_key(self.keyspace.refresh_successor_key(token));
                mutation.delete_key(self.keyspace.refresh_predecessor_key(token));
                self.apply_token_mutation(conn, mutation, true)?;
                return Ok((Err(RefreshRotationError::Expired), None));
            }

            self.apply_token_mutation(conn, mutation, false)?;
            Ok((Ok(refresh), None))
        })
    }

    pub(in crate::authcode::store) fn store_refreshed_grant(
        &self,
        previous_refresh: &str,
        access_token: &AccessToken,
        new_refresh: &RefreshToken,
        meta: &BearerTokenMeta,
    ) -> Result<(Result<(), RefreshRotationError>, Option<usize>), TokenStoreStorageError> {
        match self.commit_refresh_rotation_with_retry(
            previous_refresh,
            new_refresh,
            Some((access_token, meta)),
        )? {
            outcome if outcome == REFRESH_ROTATION_OUTCOME_OK => Ok((Ok(()), None)),
            outcome if outcome == REFRESH_ROTATION_OUTCOME_INVALID => {
                Ok((Err(RefreshRotationError::Invalid), None))
            }
            outcome if outcome == REFRESH_ROTATION_OUTCOME_EXPIRED => {
                Ok((Err(RefreshRotationError::Expired), None))
            }
            outcome if outcome == REFRESH_ROTATION_OUTCOME_REUSED => {
                let child_count = self.revoke_reused_refresh_family(previous_refresh)?;
                Ok((Err(RefreshRotationError::Reused), Some(child_count)))
            }
            outcome => Err(Self::refresh_rotation_storage_error(outcome.as_str())),
        }
    }

    #[cfg(test)]
    pub(in crate::authcode::store) fn rotate_refresh_token(
        &self,
        previous_refresh: &str,
        new_refresh: &RefreshToken,
    ) -> Result<bool, TokenStoreStorageError> {
        match self.commit_refresh_rotation_with_retry(previous_refresh, new_refresh, None)? {
            outcome if outcome == REFRESH_ROTATION_OUTCOME_OK => Ok(true),
            outcome
                if matches!(
                    outcome.as_str(),
                    REFRESH_ROTATION_OUTCOME_INVALID
                        | REFRESH_ROTATION_OUTCOME_EXPIRED
                        | REFRESH_ROTATION_OUTCOME_REUSED
                ) =>
            {
                Ok(false)
            }
            outcome => Err(Self::refresh_rotation_storage_error(outcome.as_str())),
        }
    }
}
