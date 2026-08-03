use super::super::redis_support::RedisRevokedTokenRecord;
use super::super::redis_support::RedisTokenMutation;
use super::super::token_consistency::token_is_active_revoked;
use super::RedisTokenStoreBackend;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::SystemTime;

impl RedisTokenStoreBackend {
    pub(super) fn revoked_expires_at(
        &self,
        conn: &mut redis::Connection,
        token: &str,
    ) -> Result<Option<SystemTime>, TokenStoreStorageError> {
        Self::get_json::<RedisRevokedTokenRecord>(conn, self.keyspace.revoked_key(token))
            .map(|record| record.map(|record| record.expires_at))
    }

    pub(super) fn is_revoked_direct(
        &self,
        conn: &mut redis::Connection,
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

    pub(in crate::authcode::store) fn list_bearer_meta_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<BearerTokenMeta>, TokenStoreStorageError> {
        self.with_lock("list_bearer_meta_for_subject", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_revoked(conn, now, &mut mutation)?;

            let mut metas = Vec::new();
            for token in self.subject_bearer_tokens(conn, subject)? {
                match Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(&token))? {
                    Some(meta)
                        if meta.user_id == subject
                            && meta.expires_at > now
                            && !self.is_revoked_direct(conn, &meta.token_id, now)? =>
                    {
                        metas.push(meta);
                    }
                    Some(meta) if meta.user_id != subject || meta.expires_at <= now => {
                        mutation.delete_bearer_token(meta.token_id);
                    }
                    Some(_) => {}
                    None => {
                        mutation.delete_bearer_token(token);
                    }
                }
            }

            let changed = !mutation.is_empty();
            self.apply_token_mutation(conn, mutation, changed)?;
            Ok(metas)
        })
    }

    pub(in crate::authcode::store) fn list_refresh_tokens_for_subject(
        &self,
        subject: &str,
    ) -> Result<Vec<RefreshToken>, TokenStoreStorageError> {
        self.with_lock("list_refresh_tokens_for_subject", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_revoked(conn, now, &mut mutation)?;

            let mut refresh_tokens = Vec::new();
            for token in self.subject_refresh_tokens(conn, subject)? {
                match Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(&token))? {
                    Some(refresh)
                        if refresh.user_id == subject
                            && refresh.expires_at > now
                            && !refresh.rotated
                            && !self.is_revoked_direct(conn, &refresh.token, now)? =>
                    {
                        refresh_tokens.push(refresh);
                    }
                    Some(refresh) if refresh.user_id != subject || refresh.expires_at <= now => {
                        mutation.delete_refresh_token(refresh.token);
                    }
                    Some(_) => {}
                    None => {
                        mutation.delete_refresh_token(token);
                    }
                }
            }

            let changed = !mutation.is_empty();
            self.apply_token_mutation(conn, mutation, changed)?;
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
            return Ok((!access.is_expired()).then_some(access));
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
            if !access.is_expired() {
                return Ok(Some(access.client_id));
            }
        }
        if let Some(refresh) =
            Self::get_json::<RefreshToken>(&mut conn, self.keyspace.refresh_key(token))?
        {
            if now < refresh.expires_at && !refresh.rotated {
                return Ok(Some(refresh.client_id));
            }
        }
        if let Some(meta) =
            Self::get_json::<BearerTokenMeta>(&mut conn, self.keyspace.bearer_key(token))?
        {
            if now < meta.expires_at {
                return Ok(Some(meta.client_id));
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
            return Ok(refresh.rotated);
        }
        Ok(true)
    }

    pub(super) fn known_token_client_id_direct(
        &self,
        conn: &mut redis::Connection,
        token: &str,
    ) -> Result<Option<String>, TokenStoreStorageError> {
        if let Some(access) = Self::get_json::<AccessToken>(conn, self.keyspace.access_key(token))?
        {
            return Ok(Some(access.client_id));
        }
        if let Some(refresh) =
            Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(token))?
        {
            return Ok(Some(refresh.client_id));
        }
        if let Some(meta) =
            Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(token))?
        {
            return Ok(Some(meta.client_id));
        }
        Ok(None)
    }
}
