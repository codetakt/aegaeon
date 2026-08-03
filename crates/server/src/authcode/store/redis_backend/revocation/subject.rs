use super::super::super::redis_support::RedisTokenMutation;
use super::super::RedisTokenStoreBackend;
use super::family::RefreshFamilyRevocationBudget;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::SystemTime;

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store) fn revoke_access_token_for_subject(
        &self,
        subject: &str,
        token: &str,
    ) -> Result<bool, TokenStoreStorageError> {
        self.with_lock("revoke_access_token_for_subject_direct", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_revoked(conn, now, &mut mutation)?;

            let owns_token = Self::get_json::<AccessToken>(conn, self.keyspace.access_key(token))?
                .is_some_and(|record| record.user_id == subject);
            if !owns_token {
                self.apply_token_mutation(conn, mutation, false)?;
                return Ok(false);
            }

            let _ = self.revoke_token_direct(conn, token, now, &mut mutation)?;
            self.apply_token_mutation(conn, mutation, true)?;
            Ok(true)
        })
    }

    pub(in crate::authcode::store) fn revoke_refresh_token_for_subject(
        &self,
        subject: &str,
        token: &str,
    ) -> Result<bool, TokenStoreStorageError> {
        self.with_lock("revoke_refresh_token_for_subject_direct", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_revoked(conn, now, &mut mutation)?;

            let owns_token =
                Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(token))?
                    .is_some_and(|record| record.user_id == subject);
            if !owns_token {
                self.apply_token_mutation(conn, mutation, false)?;
                return Ok(false);
            }

            let _ = self.revoke_token_direct(conn, token, now, &mut mutation)?;
            self.apply_token_mutation(conn, mutation, true)?;
            Ok(true)
        })
    }

    pub(in crate::authcode::store) fn revoke_tokens_by_subject(
        &self,
        subject: &str,
    ) -> Result<usize, TokenStoreStorageError> {
        self.with_lock("revoke_tokens_by_subject_direct", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_revoked(conn, now, &mut mutation)?;

            let mut count = 0usize;

            for token in self.subject_access_tokens(conn, subject)? {
                let Some(access) =
                    Self::get_json::<AccessToken>(conn, self.keyspace.access_key(&token))?
                else {
                    mutation.delete_access_token(token);
                    continue;
                };
                if access.user_id != subject {
                    mutation.delete_access_token(token);
                    continue;
                }
                mutation.delete_access_token(access.token.clone());
                mutation.revoke_access_until(access.token.clone(), &access, now);
                if let Some(meta) = Self::get_json::<BearerTokenMeta>(
                    conn,
                    self.keyspace.bearer_key(&access.token),
                )? {
                    mutation.delete_bearer_token(access.token.clone());
                    mutation.revoke_until(access.token, meta.expires_at, now);
                }
                count = count.saturating_add(1);
            }

            let mut family_budget = RefreshFamilyRevocationBudget::new();
            for token in self.subject_refresh_tokens(conn, subject)? {
                if mutation.delete_refresh_tokens.contains(&token) {
                    continue;
                }
                let Some(refresh) =
                    Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(&token))?
                else {
                    mutation.delete_refresh_token(token);
                    continue;
                };
                if refresh.user_id != subject {
                    mutation.delete_refresh_token(token);
                    continue;
                }
                count = count.saturating_add(1);
                count = count.saturating_add(self.revoke_refresh_family_direct_with_budget(
                    conn,
                    &refresh.token,
                    now,
                    &mut mutation,
                    &mut family_budget,
                )?);
            }

            for token in self.subject_bearer_tokens(conn, subject)? {
                if mutation.delete_bearer_tokens.contains(&token) {
                    continue;
                }
                let Some(meta) =
                    Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(&token))?
                else {
                    mutation.delete_bearer_token(token);
                    continue;
                };
                if meta.user_id != subject {
                    mutation.delete_bearer_token(token);
                    continue;
                }
                mutation.delete_bearer_token(meta.token_id.clone());
                mutation.revoke_until(meta.token_id, meta.expires_at, now);
            }

            self.apply_token_mutation(conn, mutation, count > 0)?;
            Ok(count)
        })
    }
}
