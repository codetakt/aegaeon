#[cfg(test)]
use super::super::redis_support::RedisTokenStoreKeyspace;
use super::super::redis_support::{encode_redis_json, RedisRefreshChildrenRecord};
use super::collision::reject_existing_token_keys;
use super::commit_result::authorization_code_grant_commit_result;
use super::refresh_grants::GrantCommit;
use super::{IssuedGrantRecords, RedisTokenStoreBackend};
use crate::authcode::code_store::AuthCodeRedisCommitContext;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::RefreshGrantRecord;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken, SenderBinding};
use crate::oidc::RedisOidcSessionGrantCommit;
use std::collections::HashSet;
use std::time::SystemTime;

#[path = "writes/authorization_code_grant.rs"]
mod authorization_code_grant;
use authorization_code_grant::AuthorizationCodeGrantCommitPlan;
#[path = "writes/direct_grant.rs"]
mod direct_grant;
use direct_grant::DirectGrant;

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store) fn store_issued_grant_after_consuming_authorization_code(
        &self,
        auth_code: &AuthCodeRedisCommitContext,
        expected_auth_code_payload: &str,
        records: IssuedGrantRecords<'_>,
        oidc_session: Option<&RedisOidcSessionGrantCommit>,
    ) -> Result<bool, TokenStoreStorageError> {
        let plan = AuthorizationCodeGrantCommitPlan::new(
            self,
            auth_code,
            expected_auth_code_payload,
            records,
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

    #[cfg(test)]
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
        grant_record: Option<&RefreshGrantRecord>,
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

            let children = match refresh_children {
                Some((refresh, access_tokens)) => encode_redis_json(&RedisRefreshChildrenRecord {
                    refresh_token: refresh.into(),
                    access_tokens,
                })?,
                None => String::new(),
            };
            let grant = GrantCommit::initial(self, grant_record)?;
            let outcome = self.commit_direct_grant(
                conn,
                DirectGrant {
                    access: access_token,
                    meta,
                    refresh: refresh_token,
                    parent_payload: None,
                    children: &children,
                    grant: &grant,
                },
            )?;
            if outcome == "ok" {
                Ok(())
            } else {
                Err(TokenStoreStorageError::InvariantViolation(format!(
                    "issued grant commit rejected: {outcome}"
                )))
            }
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
            let parent_payload: Option<String> = redis::cmd("GET")
                .arg(self.keyspace.refresh_key(refresh_parent))
                .query(conn)
                .map_err(|error| TokenStoreStorageError::BackendUnavailable(error.to_string()))?;
            let Some(parent_payload) = parent_payload else {
                return Ok(Err("refresh_parent must be active".into()));
            };
            let parent: RefreshToken =
                super::super::redis_support::decode_redis_json(&parent_payload)?;
            if let Err(error) = super::super::token_consistency::refresh_parent_matches_remint(
                &parent,
                access_token,
                meta,
                now,
            ) {
                return Ok(Err(error.into()));
            }
            if !self.refresh_grant_active(
                conn,
                parent.refresh_grant.as_ref(),
                &parent.client_id,
                &parent.user_id,
                parent.expires_at,
                now,
            )? {
                return Ok(Err(
                    "refresh grant is inactive or retention is inconsistent".into(),
                ));
            }
            if !self.exchange_root_active(
                conn,
                parent
                    .exchange_grant
                    .as_ref()
                    .and_then(|grant| grant.root()),
                now,
            )? {
                return Ok(Err(
                    "refresh_parent exchange authority must remain active and unchanged".into(),
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

            let children = encode_redis_json(&RedisRefreshChildrenRecord {
                refresh_token: refresh_parent.into(),
                access_tokens: children,
            })?;
            let deadline = super::super::refresh_grants::descendant_deadline(
                access_token,
                meta,
                Some(&parent),
            )
            .map_err(|error| TokenStoreStorageError::InvariantViolation(error.into()))?;
            let Some(grant) = self.descendant_grant_commit(
                conn,
                parent.refresh_grant.as_ref(),
                &parent.client_id,
                &parent.user_id,
                deadline,
            )?
            else {
                return Ok(Err("refresh grant is inactive".into()));
            };
            let outcome = self.commit_direct_grant(
                conn,
                DirectGrant {
                    access: access_token,
                    meta,
                    refresh: Some(&parent),
                    parent_payload: Some(&parent_payload),
                    children: &children,
                    grant: &grant,
                },
            )?;
            if outcome == "ok" {
                Ok(Ok(()))
            } else if outcome == "invalid" {
                Ok(Err("refresh grant is inactive".into()))
            } else {
                Err(TokenStoreStorageError::InvariantViolation(format!(
                    "refresh-parent commit rejected: {outcome}"
                )))
            }
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
            let raw: Option<String> = redis::cmd("GET").arg(self.keyspace.refresh_key(refresh_token)).query(conn).map_err(|error| TokenStoreStorageError::BackendUnavailable(error.to_string()))?;
            let Some(raw) = raw else { return Ok(false); };
            let mut token: RefreshToken = super::super::redis_support::decode_redis_json(&raw)?;
            if token.rotated || SystemTime::now() >= token.expires_at { return Ok(false); }
            if !self.refresh_grant_active(conn, token.refresh_grant.as_ref(), &token.client_id, &token.user_id, token.expires_at, SystemTime::now())? { return Ok(false); }
            let Some(grant) = self.descendant_grant_commit(conn, token.refresh_grant.as_ref(), &token.client_id, &token.user_id, token.expires_at)? else { return Ok(false); };
            token.sender_binding = sender_binding;
            let deadline = token.expires_at.duration_since(std::time::UNIX_EPOCH).map_err(|_| TokenStoreStorageError::InvariantViolation("refresh deadline before epoch".into()))?;
            let script = GrantCommit::script(r"
if redis.call('GET', KEYS[1]) ~= ARGV[1] or redis.call('EXISTS', KEYS[3]) ~= 0 then return 'invalid' end
local time = redis.call('TIME')
if decimal_ge(time[1], ARGV[3]) and (time[1] ~= ARGV[3] or tonumber(time[2])*1000 >= tonumber(ARGV[4])) then return 'invalid' end
if not refresh_grant_acl_allows() or not acl_allows('INCR', KEYS[2]) or not acl_allows('SET', KEYS[1], ARGV[2]) then return 'acl_denied' end
redis.call('INCR', KEYS[2])
commit_refresh_grant()
-- The binding is the final publication; earlier failure preserves its old bytes.
redis.call('SET', KEYS[1], ARGV[2])
return 'ok'
");
            let mut call = script.prepare_invoke();
            call.key(self.keyspace.refresh_key(refresh_token)).key(self.keyspace.version_key()).key(self.keyspace.revoked_key(refresh_token))
                .arg(raw).arg(encode_redis_json(&token)?).arg(deadline.as_secs()).arg(deadline.subsec_nanos());
            grant.append(&mut call);
            let result: String = call.invoke(conn).map_err(|error| TokenStoreStorageError::BackendUnavailable(error.to_string()))?;
            match result.as_str() { "ok" => Ok(true), "invalid" => Ok(false), _ => Err(TokenStoreStorageError::InvariantViolation(format!("refresh sender binding update rejected: {result}"))) }
        })
    }
}
