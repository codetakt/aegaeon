use super::super::redis_support::{decode_redis_json, RedisRevokedTokenRecord};
use super::super::token_consistency::token_is_active_revoked;
use super::RedisTokenStoreBackend;
use crate::authcode::store::refresh_grants::{access_reference, descendant_deadline};
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use serde::de::DeserializeOwned;
use std::time::SystemTime;

fn decode_inventory_record<T: DeserializeOwned>(
    raw: String,
) -> Result<(String, T), TokenStoreStorageError> {
    let record = decode_redis_json(&raw)?;
    Ok((raw, record))
}

fn inventory_record_matches_subject(
    indexed_token: &str,
    record_token: &str,
    subject: &str,
    record_subject: &str,
    expires_at: SystemTime,
    now: SystemTime,
) -> bool {
    indexed_token == record_token && subject == record_subject && expires_at > now
}

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store) fn observe_access_record(
        &self,
        token: &str,
    ) -> Result<Option<AccessToken>, TokenStoreStorageError> {
        Self::get_json(&mut self.connection()?, self.keyspace.access_key(token))
    }

    pub(super) fn access_grant_active(
        &self,
        conn: &mut impl redis::ConnectionLike,
        access: &AccessToken,
        now: SystemTime,
    ) -> Result<bool, TokenStoreStorageError> {
        let Some(meta) =
            Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(&access.token))?
        else {
            return Ok(false);
        };
        let Ok(reference) = access_reference(access, &meta) else {
            return Ok(false);
        };
        let Some(reference) = reference else {
            return Ok(true);
        };
        let Ok(deadline) = descendant_deadline(access, &meta, None) else {
            return Ok(false);
        };
        self.refresh_grant_active(
            conn,
            Some(reference),
            &access.client_id,
            &access.user_id,
            deadline,
            now,
        )
    }

    pub(super) fn revoked_expires_at(
        &self,
        conn: &mut impl redis::ConnectionLike,
        token: &str,
    ) -> Result<Option<SystemTime>, TokenStoreStorageError> {
        Self::get_json::<RedisRevokedTokenRecord>(conn, self.keyspace.revoked_key(token))
            .map(|record| record.map(|record| record.expires_at))
    }

    pub(super) fn is_revoked_direct(
        &self,
        conn: &mut impl redis::ConnectionLike,
        token: &str,
        now: SystemTime,
    ) -> Result<bool, TokenStoreStorageError> {
        Ok(token_is_active_revoked(
            self.revoked_expires_at(conn, token)?,
            now,
        ))
    }

    pub(in crate::authcode::store) fn get_bearer_meta(
        &self,
        token_id: &str,
    ) -> Result<Option<BearerTokenMeta>, TokenStoreStorageError> {
        let mut conn = self.connection()?;
        if let Some(meta) =
            Self::get_json::<BearerTokenMeta>(&mut conn, self.keyspace.bearer_key(token_id))?
        {
            return Ok(Some(meta));
        }
        Ok(None)
    }

    pub(super) fn inventory_record<T: DeserializeOwned>(
        conn: &mut impl redis::ConnectionLike,
        key: &str,
    ) -> Result<Option<(String, T)>, TokenStoreStorageError> {
        let raw: Option<String> = redis::cmd("GET")
            .arg(key)
            .query(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?;
        raw.map(decode_inventory_record).transpose()
    }

    fn access_record_active(
        &self,
        conn: &mut impl redis::ConnectionLike,
        access: &AccessToken,
        now: SystemTime,
    ) -> Result<bool, TokenStoreStorageError> {
        Ok(self.access_grant_active(conn, access, now)?
            && self.exchange_root_active(conn, access.exchange_root.as_ref(), now)?
            && !access.is_expired())
    }

    fn inventory_bearer_active(
        &self,
        conn: &mut impl redis::ConnectionLike,
        meta: &BearerTokenMeta,
        now: SystemTime,
    ) -> Result<bool, TokenStoreStorageError> {
        let Some(access) =
            Self::get_json::<AccessToken>(conn, self.keyspace.access_key(&meta.token_id))?
        else {
            return Ok(false);
        };
        if access.is_expired() || access_reference(&access, meta).is_err() {
            return Ok(false);
        }
        // Preserve the current-time verification checks as well as the original
        // inventory-time revocation and metadata-root checks, on this connection.
        let verification_time = SystemTime::now();
        Ok(
            !self.is_revoked_direct(conn, &meta.token_id, verification_time)?
                && self.access_record_active(conn, &access, verification_time)?
                && !self.is_revoked_direct(conn, &meta.token_id, now)?
                && self.exchange_root_active(
                    conn,
                    meta.exchange_grant.as_ref().and_then(|grant| grant.root()),
                    now,
                )?,
        )
    }

    pub(in crate::authcode::store) fn list_bearer_meta_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<BearerTokenMeta>, TokenStoreStorageError> {
        self.with_lock("list_bearer_meta_for_subject", |conn| {
            let now = SystemTime::now();
            let subject_key = self.keyspace.subject_bearer_key(subject);
            let mut metas = Vec::new();
            for token in self.subject_bearer_tokens(conn, subject)? {
                let record_key = self.keyspace.bearer_key(&token);
                match Self::inventory_record::<BearerTokenMeta>(conn, &record_key)? {
                    Some((raw, meta)) => {
                        if !inventory_record_matches_subject(
                            &token,
                            &meta.token_id,
                            subject,
                            &meta.user_id,
                            meta.expires_at,
                            now,
                        ) {
                            self.prune_observed_subject_member(
                                conn,
                                &record_key,
                                &subject_key,
                                &token,
                                Some(&raw),
                            )?;
                        } else if self.inventory_bearer_active(conn, &meta, now)? {
                            metas.push(meta);
                        }
                    }
                    None => self.prune_observed_subject_member(
                        conn,
                        &record_key,
                        &subject_key,
                        &token,
                        None,
                    )?,
                }
            }
            Ok(metas)
        })
    }

    pub(in crate::authcode::store) fn list_refresh_tokens_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<RefreshToken>, TokenStoreStorageError> {
        self.with_lock("list_refresh_tokens_for_subject", |conn| {
            let now = SystemTime::now();
            let subject_key = self.keyspace.subject_refresh_key(subject);
            let mut refresh_tokens = Vec::new();
            for token in self.subject_refresh_tokens(conn, subject)? {
                let record_key = self.keyspace.refresh_key(&token);
                match Self::inventory_record::<RefreshToken>(conn, &record_key)? {
                    Some((raw, refresh)) => {
                        if !inventory_record_matches_subject(
                            &token,
                            &refresh.token,
                            subject,
                            &refresh.user_id,
                            refresh.expires_at,
                            now,
                        ) {
                            self.prune_observed_subject_member(
                                conn,
                                &record_key,
                                &subject_key,
                                &token,
                                Some(&raw),
                            )?;
                        } else if !refresh.rotated
                            && self.refresh_grant_active(
                                conn,
                                refresh.refresh_grant.as_ref(),
                                &refresh.client_id,
                                &refresh.user_id,
                                refresh.expires_at,
                                now,
                            )?
                            && !self.is_revoked_direct(conn, &refresh.token, now)?
                            && self.exchange_root_active(
                                conn,
                                refresh
                                    .exchange_grant
                                    .as_ref()
                                    .and_then(|grant| grant.root()),
                                now,
                            )?
                        {
                            refresh_tokens.push(refresh);
                        }
                    }
                    None => self.prune_observed_subject_member(
                        conn,
                        &record_key,
                        &subject_key,
                        &token,
                        None,
                    )?,
                }
            }
            Ok(refresh_tokens)
        })
    }

    pub(in crate::authcode::store) fn known_token_client_id(
        &self,
        token: &str,
    ) -> Result<Option<String>, TokenStoreStorageError> {
        let mut conn = self.connection()?;
        if let Some(access) =
            Self::get_json::<AccessToken>(&mut conn, self.keyspace.access_key(token))?
        {
            return Ok(Some(access.client_id));
        }
        if let Some(refresh) =
            Self::get_json::<RefreshToken>(&mut conn, self.keyspace.refresh_key(token))?
        {
            return Ok(Some(refresh.client_id));
        }
        if let Some(meta) =
            Self::get_json::<BearerTokenMeta>(&mut conn, self.keyspace.bearer_key(token))?
        {
            return Ok(Some(meta.client_id));
        }
        Ok(None)
    }

    pub(in crate::authcode::store) fn get_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<RefreshToken>, TokenStoreStorageError> {
        let mut conn = self.connection()?;
        let now = SystemTime::now();
        if self.is_revoked_direct(&mut conn, token, now)? {
            return Ok(None);
        }
        if let Some(refresh) =
            Self::get_json::<RefreshToken>(&mut conn, self.keyspace.refresh_key(token))?
        {
            if !self.refresh_grant_active(
                &mut conn,
                refresh.refresh_grant.as_ref(),
                &refresh.client_id,
                &refresh.user_id,
                refresh.expires_at,
                now,
            )? || !self.exchange_root_active(
                &mut conn,
                refresh
                    .exchange_grant
                    .as_ref()
                    .and_then(|grant| grant.root()),
                now,
            )? {
                return Ok(None);
            }
            return Ok(Some(refresh));
        }
        Ok(None)
    }

    pub(in crate::authcode::store) fn verify_access_token(
        &self,
        token: &str,
    ) -> Result<Option<AccessToken>, TokenStoreStorageError> {
        let mut conn = self.connection()?;
        let now = SystemTime::now();
        if self.is_revoked_direct(&mut conn, token, now)? {
            return Ok(None);
        }
        if let Some(access) =
            Self::get_json::<AccessToken>(&mut conn, self.keyspace.access_key(token))?
        {
            return Ok(self
                .access_record_active(&mut conn, &access, now)?
                .then_some(access));
        }
        Ok(None)
    }

    pub(in crate::authcode::store) fn active_token_client_id(
        &self,
        token: &str,
    ) -> Result<Option<String>, TokenStoreStorageError> {
        let mut conn = self.connection()?;
        let now = SystemTime::now();
        if self.is_revoked_direct(&mut conn, token, now)? {
            return Ok(None);
        }
        if let Some(access) =
            Self::get_json::<AccessToken>(&mut conn, self.keyspace.access_key(token))?
        {
            if !self.access_grant_active(&mut conn, &access, now)?
                || !self.exchange_root_active(&mut conn, access.exchange_root.as_ref(), now)?
            {
                return Ok(None);
            }
            if !access.is_expired() {
                return Ok(Some(access.client_id));
            }
        }
        if let Some(refresh) =
            Self::get_json::<RefreshToken>(&mut conn, self.keyspace.refresh_key(token))?
        {
            if !self.refresh_grant_active(
                &mut conn,
                refresh.refresh_grant.as_ref(),
                &refresh.client_id,
                &refresh.user_id,
                refresh.expires_at,
                now,
            )? || !self.exchange_root_active(
                &mut conn,
                refresh
                    .exchange_grant
                    .as_ref()
                    .and_then(|grant| grant.root()),
                now,
            )? {
                return Ok(None);
            }
            if now < refresh.expires_at && !refresh.rotated {
                return Ok(Some(refresh.client_id));
            }
        }

        Ok(None)
    }

    pub(in crate::authcode::store) fn is_refresh_revoked(
        &self,
        token: &str,
    ) -> Result<bool, TokenStoreStorageError> {
        let mut conn = self.connection()?;
        let now = SystemTime::now();
        if self.is_revoked_direct(&mut conn, token, now)? {
            return Ok(true);
        }
        if let Some(refresh) =
            Self::get_json::<RefreshToken>(&mut conn, self.keyspace.refresh_key(token))?
        {
            return Ok(refresh.rotated
                || now >= refresh.expires_at
                || !self.refresh_grant_active(
                    &mut conn,
                    refresh.refresh_grant.as_ref(),
                    &refresh.client_id,
                    &refresh.user_id,
                    refresh.expires_at,
                    now,
                )?
                || !self.exchange_root_active(
                    &mut conn,
                    refresh
                        .exchange_grant
                        .as_ref()
                        .and_then(|grant| grant.root()),
                    now,
                )?);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
