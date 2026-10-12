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

    fn revoke_subject_grant_authority(
        &self,
        conn: &mut redis::Connection,
        subject: &str,
    ) -> Result<(), TokenStoreStorageError> {
        for token in self.subject_refresh_tokens(conn, subject)? {
            if let Some(refresh) =
                Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(&token))?
            {
                if refresh.user_id == subject {
                    self.revoke_refresh_grant(
                        conn,
                        refresh.refresh_grant.as_ref(),
                        &refresh.client_id,
                        &refresh.user_id,
                    )?;
                    self.revoke_exchange_root(conn, refresh.exchange_grant.as_ref())?;
                }
            }
        }
        // Access descendants can remain live after refresh records/indexes expire.
        for token in self.subject_access_tokens(conn, subject)? {
            if let Some(access) =
                Self::get_json::<AccessToken>(conn, self.keyspace.access_key(&token))?
            {
                if access.user_id == subject {
                    self.revoke_refresh_grant(
                        conn,
                        access.refresh_grant.as_ref(),
                        &access.client_id,
                        &access.user_id,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn revoke_subject_access_records(
        &self,
        conn: &mut redis::Connection,
        subject: &str,
        now: SystemTime,
        mutation: &mut RedisTokenMutation,
    ) -> Result<(), TokenStoreStorageError> {
        for token in self.subject_access_tokens(conn, subject)? {
            let Some((raw, access)) =
                Self::inventory_record::<AccessToken>(conn, &self.keyspace.access_key(&token))?
            else {
                self.prune_missing_subject_member(
                    conn,
                    &self.keyspace.access_key(&token),
                    &self.keyspace.subject_access_key(subject),
                    &token,
                )?;
                continue;
            };
            if access.user_id != subject {
                self.prune_observed_subject_member(
                    conn,
                    &self.keyspace.access_key(&token),
                    &self.keyspace.subject_access_key(subject),
                    &token,
                    Some(&raw),
                )?;
                continue;
            }
            mutation.delete_access_token(access.token.clone());
            mutation.revoke_access_until(access.token.clone(), &access, now);
            if let Some(meta) =
                Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(&access.token))?
            {
                mutation.delete_bearer_token(access.token.clone());
                mutation.revoke_until(access.token, meta.expires_at, now);
            }
        }
        Ok(())
    }

    pub(in crate::authcode::store) fn revoke_tokens_by_subject(
        &self,
        subject: &str,
    ) -> Result<usize, TokenStoreStorageError> {
        self.with_lock("revoke_tokens_by_subject_direct", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_revoked(conn, now, &mut mutation)?;

            self.revoke_subject_grant_authority(conn, subject)?;

            self.revoke_subject_access_records(conn, subject, now, &mut mutation)?;

            let mut family_budget = RefreshFamilyRevocationBudget::new();
            for token in self.subject_refresh_tokens(conn, subject)? {
                if mutation.delete_refresh_tokens.contains(&token) {
                    continue;
                }
                let Some((raw, refresh)) = Self::inventory_record::<RefreshToken>(
                    conn,
                    &self.keyspace.refresh_key(&token),
                )?
                else {
                    self.prune_missing_subject_member(
                        conn,
                        &self.keyspace.refresh_key(&token),
                        &self.keyspace.subject_refresh_key(subject),
                        &token,
                    )?;
                    continue;
                };
                if refresh.user_id != subject {
                    self.prune_observed_subject_member(
                        conn,
                        &self.keyspace.refresh_key(&token),
                        &self.keyspace.subject_refresh_key(subject),
                        &token,
                        Some(&raw),
                    )?;
                    continue;
                }
                self.revoke_refresh_family_direct_with_budget(
                    conn,
                    &refresh.token,
                    now,
                    &mut mutation,
                    &mut family_budget,
                )?;
            }

            for token in self.subject_bearer_tokens(conn, subject)? {
                if mutation.delete_bearer_tokens.contains(&token) {
                    continue;
                }
                let Some((raw, meta)) = Self::inventory_record::<BearerTokenMeta>(
                    conn,
                    &self.keyspace.bearer_key(&token),
                )?
                else {
                    self.prune_missing_subject_member(
                        conn,
                        &self.keyspace.bearer_key(&token),
                        &self.keyspace.subject_bearer_key(subject),
                        &token,
                    )?;
                    continue;
                };
                if meta.user_id != subject {
                    self.prune_observed_subject_member(
                        conn,
                        &self.keyspace.bearer_key(&token),
                        &self.keyspace.subject_bearer_key(subject),
                        &token,
                        Some(&raw),
                    )?;
                    continue;
                }
                mutation.delete_bearer_token(meta.token_id.clone());
                mutation.revoke_until(meta.token_id, meta.expires_at, now);
            }

            // A token may be selected directly and through several family links.
            // Metadata and stale index entries are not additional tokens.
            let count = mutation
                .delete_access_tokens
                .len()
                .saturating_add(mutation.delete_refresh_tokens.len());
            self.apply_token_mutation(conn, mutation, count > 0)?;
            Ok(count)
        })
    }
}
