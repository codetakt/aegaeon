use super::super::redis_support::{
    encode_redis_json, RedisRefreshChildrenRecord, RedisTokenStoreKeyspace,
};
use super::super::token_consistency::{meta_scope_set, scope_set, sender_bindings_match};
use super::collision::reject_existing_token_keys;
use super::commit_result::authorization_code_grant_commit_result;
use super::RedisTokenStoreBackend;
use crate::authcode::code_store::AuthCodeRedisCommitContext;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken, SenderBinding};
use crate::oidc::RedisOidcSessionGrantCommit;
use std::collections::HashSet;
use std::time::SystemTime;

#[path = "writes/authorization_code_grant.rs"]
mod authorization_code_grant;
use authorization_code_grant::AuthorizationCodeGrantCommitPlan;

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store) fn store_issued_grant_after_consuming_authorization_code(
        &self,
        auth_code: &AuthCodeRedisCommitContext,
        expected_auth_code_payload: &str,
        access_token: &AccessToken,
        refresh_token: Option<&RefreshToken>,
        meta: &BearerTokenMeta,
        oidc_session: Option<&RedisOidcSessionGrantCommit>,
    ) -> Result<bool, TokenStoreStorageError> {
        let plan = AuthorizationCodeGrantCommitPlan::new(
            self,
            auth_code,
            expected_auth_code_payload,
            access_token,
            refresh_token,
            meta,
            oidc_session,
        )?;

        self.with_lock(
            "store_issued_grant_after_consuming_authorization_code",
            |conn| {
                let outcome = plan.invoke(conn)?;
                authorization_code_grant_commit_result(outcome.as_str())
            },
        )
    }

    #[cfg(test)]
    pub(in crate::authcode::store) fn store_access_token(
        &self,
        token: &AccessToken,
    ) -> Result<(), TokenStoreStorageError> {
        self.with_lock("store_access_token_direct", |conn| {
            let previous =
                Self::get_json::<AccessToken>(conn, self.keyspace.access_key(&token.token))?;
            let mut pipe = redis::pipe();
            pipe.atomic();
            self.deindex_access_cmd(&mut pipe, &token.token, previous.as_ref());
            pipe.cmd("SET")
                .arg(self.keyspace.access_key(&token.token))
                .arg(encode_redis_json(token)?)
                .ignore();
            self.index_access_cmd(&mut pipe, token);
            Self::increment_version(&mut pipe, &self.keyspace);
            pipe.query::<()>(conn)
                .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
        })
    }

    #[cfg(test)]
    pub(in crate::authcode::store) fn store_bearer_meta(
        &self,
        meta: &BearerTokenMeta,
    ) -> Result<(), TokenStoreStorageError> {
        self.with_lock("store_bearer_meta_direct", |conn| {
            let previous =
                Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(&meta.token_id))?;
            let mut pipe = redis::pipe();
            pipe.atomic();
            self.deindex_bearer_cmd(&mut pipe, &meta.token_id, previous.as_ref());
            pipe.cmd("SET")
                .arg(self.keyspace.bearer_key(&meta.token_id))
                .arg(encode_redis_json(meta)?)
                .ignore();
            self.index_bearer_cmd(&mut pipe, meta);
            Self::increment_version(&mut pipe, &self.keyspace);
            pipe.query::<()>(conn)
                .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
        })
    }

    pub(super) fn refresh_children(
        &self,
        conn: &mut redis::Connection,
        refresh_token: &str,
    ) -> Result<HashSet<String>, TokenStoreStorageError> {
        Ok(Self::get_json::<RedisRefreshChildrenRecord>(
            conn,
            self.keyspace.refresh_children_key(refresh_token),
        )?
        .map_or_else(HashSet::new, |record| record.access_tokens))
    }

    pub(super) fn set_refresh_children_cmd(
        pipe: &mut redis::Pipeline,
        keyspace: &RedisTokenStoreKeyspace,
        refresh_token: &str,
        access_tokens: HashSet<String>,
    ) -> Result<(), TokenStoreStorageError> {
        let record = RedisRefreshChildrenRecord {
            refresh_token: refresh_token.to_string(),
            access_tokens,
        };
        pipe.cmd("SET")
            .arg(keyspace.refresh_children_key(refresh_token))
            .arg(encode_redis_json(&record)?)
            .ignore();
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::authcode::store) fn store_refresh_token(
        &self,
        token: &RefreshToken,
    ) -> Result<(), TokenStoreStorageError> {
        self.with_lock("store_refresh_token_direct", |conn| {
            let previous =
                Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(&token.token))?;
            let access_tokens = self.refresh_children(conn, &token.token)?;
            let mut pipe = redis::pipe();
            pipe.atomic();
            self.deindex_refresh_cmd(&mut pipe, &token.token, previous.as_ref());
            pipe.cmd("SET")
                .arg(self.keyspace.refresh_key(&token.token))
                .arg(encode_redis_json(token)?)
                .ignore();
            self.index_refresh_cmd(&mut pipe, token);
            Self::set_refresh_children_cmd(&mut pipe, &self.keyspace, &token.token, access_tokens)?;
            Self::increment_version(&mut pipe, &self.keyspace);
            pipe.query::<()>(conn)
                .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
        })
    }

    pub(in crate::authcode::store) fn store_issued_grant(
        &self,
        access_token: &AccessToken,
        refresh_token: Option<&RefreshToken>,
        meta: &BearerTokenMeta,
    ) -> Result<(), TokenStoreStorageError> {
        self.with_lock("store_issued_grant_direct", |conn| {
            let mut collision_keys = vec![
                self.keyspace.access_key(&access_token.token),
                self.keyspace.bearer_key(&meta.token_id),
            ];
            if let Some(refresh) = refresh_token {
                collision_keys.push(self.keyspace.refresh_key(&refresh.token));
                collision_keys.push(self.keyspace.refresh_children_key(&refresh.token));
            }
            reject_existing_token_keys(conn, &collision_keys, "issued grant")?;

            let refresh_children = refresh_token
                .map(|refresh| {
                    let mut children = HashSet::new();
                    children.insert(access_token.token.clone());
                    Ok::<_, TokenStoreStorageError>((refresh.token.as_str(), children))
                })
                .transpose()?;

            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.cmd("SET")
                .arg(self.keyspace.access_key(&access_token.token))
                .arg(encode_redis_json(access_token)?)
                .ignore();
            self.index_access_cmd(&mut pipe, access_token);
            if let Some(refresh) = refresh_token {
                pipe.cmd("SET")
                    .arg(self.keyspace.refresh_key(&refresh.token))
                    .arg(encode_redis_json(refresh)?)
                    .ignore();
                self.index_refresh_cmd(&mut pipe, refresh);
            }
            if let Some((refresh, children)) = refresh_children {
                Self::set_refresh_children_cmd(&mut pipe, &self.keyspace, refresh, children)?;
            }
            pipe.cmd("SET")
                .arg(self.keyspace.bearer_key(&meta.token_id))
                .arg(encode_redis_json(meta)?)
                .ignore();
            self.index_bearer_cmd(&mut pipe, meta);
            Self::increment_version(&mut pipe, &self.keyspace);
            pipe.query::<()>(conn)
                .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
        })
    }

    pub(in crate::authcode::store) fn store_access_for_refresh_parent(
        &self,
        access_token: &AccessToken,
        meta: &BearerTokenMeta,
        refresh_parent: &str,
    ) -> Result<Result<(), String>, TokenStoreStorageError> {
        self.with_lock("store_access_for_refresh_parent_direct", |conn| {
            let now = SystemTime::now();
            if self.is_revoked_direct(conn, refresh_parent, now)? {
                return Ok(Err("refresh_parent must be active".to_string()));
            }
            let Some(parent) =
                Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(refresh_parent))?
            else {
                return Ok(Err("refresh_parent must be active".to_string()));
            };
            if parent.rotated || now >= parent.expires_at {
                return Ok(Err("refresh_parent must be active".to_string()));
            }
            if parent.client_id != access_token.client_id || parent.user_id != access_token.user_id
            {
                return Ok(Err(
                    "refresh_parent owner must match the access token".to_string()
                ));
            }
            let parent_audience = parent.resource.as_deref().unwrap_or(&parent.client_id);
            if meta.audience != parent_audience {
                return Ok(Err(
                    "bearer metadata audience must match refresh_parent resource".to_string(),
                ));
            }
            if !meta_scope_set(meta).is_subset(&scope_set(parent.scope.as_deref())) {
                return Ok(Err(
                    "bearer metadata scope must be a subset of refresh_parent scope".to_string(),
                ));
            }
            if !sender_bindings_match(parent.sender_binding.as_ref(), meta.sender_binding.as_ref())
            {
                return Ok(Err(
                    "bearer metadata sender_binding must match refresh_parent".to_string(),
                ));
            }

            reject_existing_token_keys(
                conn,
                &[
                    self.keyspace.access_key(&access_token.token),
                    self.keyspace.bearer_key(&meta.token_id),
                ],
                "refresh-parent access grant",
            )?;

            let mut children = self.refresh_children(conn, refresh_parent)?;
            children.insert(access_token.token.clone());

            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.cmd("SET")
                .arg(self.keyspace.access_key(&access_token.token))
                .arg(encode_redis_json(access_token)?)
                .ignore();
            self.index_access_cmd(&mut pipe, access_token);
            Self::set_refresh_children_cmd(&mut pipe, &self.keyspace, refresh_parent, children)?;
            pipe.cmd("SET")
                .arg(self.keyspace.bearer_key(&meta.token_id))
                .arg(encode_redis_json(meta)?)
                .ignore();
            self.index_bearer_cmd(&mut pipe, meta);
            Self::increment_version(&mut pipe, &self.keyspace);
            pipe.query::<()>(conn)
                .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?;
            Ok(Ok(()))
        })
    }

    #[cfg(test)]
    pub(in crate::authcode::store) fn bind_refresh_access(
        &self,
        refresh_token: &str,
        access_token: &str,
    ) -> Result<(), TokenStoreStorageError> {
        self.with_lock("bind_refresh_access_direct", |conn| {
            let mut children = self.refresh_children(conn, refresh_token)?;
            children.insert(access_token.to_string());

            let mut pipe = redis::pipe();
            pipe.atomic();
            Self::set_refresh_children_cmd(&mut pipe, &self.keyspace, refresh_token, children)?;
            Self::increment_version(&mut pipe, &self.keyspace);
            pipe.query::<()>(conn)
                .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
        })
    }

    pub(in crate::authcode::store) fn set_refresh_sender_binding(
        &self,
        refresh_token: &str,
        sender_binding: Option<SenderBinding>,
    ) -> Result<bool, TokenStoreStorageError> {
        self.with_lock("set_refresh_sender_binding_direct", |conn| {
            let Some(mut token) =
                Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(refresh_token))?
            else {
                return Ok(false);
            };
            token.sender_binding = sender_binding;

            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.cmd("SET")
                .arg(self.keyspace.refresh_key(refresh_token))
                .arg(encode_redis_json(&token)?)
                .ignore();
            self.index_refresh_cmd(&mut pipe, &token);
            Self::increment_version(&mut pipe, &self.keyspace);
            pipe.query::<()>(conn)
                .map(|()| true)
                .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
        })
    }
}
