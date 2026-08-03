use super::super::super::redis_support::{RedisRefreshSuccessorRecord, RedisTokenMutation};
use super::super::RedisTokenStoreBackend;
use super::family::RefreshFamilyRevocationBudget;
use crate::authcode::store::{
    ClientBoundRevocationOutcome, TokenRevocationOutcome, TokenStoreStorageError,
};
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::SystemTime;

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store::redis_backend::revocation) fn revoke_token_direct(
        &self,
        conn: &mut redis::Connection,
        token: &str,
        now: SystemTime,
        mutation: &mut RedisTokenMutation,
    ) -> Result<TokenRevocationOutcome, TokenStoreStorageError> {
        let bearer_meta = Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(token))?;
        if bearer_meta.is_some() {
            mutation.delete_bearer_token(token.to_string());
        }

        if let Some(access) = Self::get_json::<AccessToken>(conn, self.keyspace.access_key(token))?
        {
            mutation.delete_access_token(token.to_string());
            mutation.revoke_access_until(token.to_string(), &access, now);
            if let Some(meta) = bearer_meta {
                mutation.revoke_until(token.to_string(), meta.expires_at, now);
            }
            return Ok(TokenRevocationOutcome::AccessToken);
        }

        if let Some(refresh) =
            Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(token))?
        {
            mutation.delete_refresh_token(token.to_string());
            mutation.revoke_until(token.to_string(), refresh.expires_at, now);
            if let Some(meta) = bearer_meta {
                mutation.revoke_until(token.to_string(), meta.expires_at, now);
            }

            let mut budget = RefreshFamilyRevocationBudget::new();
            budget.consume_refresh_visit(token)?;
            let child_tokens = self.refresh_children(conn, token)?;
            mutation.delete_key(self.keyspace.refresh_children_key(token));
            budget.consume_child_tokens(token, child_tokens.len())?;
            let mut child_count = child_tokens.len();
            if let Some(successor) = Self::get_json::<RedisRefreshSuccessorRecord>(
                conn,
                self.keyspace.refresh_successor_key(token),
            )? {
                mutation.delete_key(self.keyspace.refresh_successor_key(token));
                mutation.delete_key(
                    self.keyspace
                        .refresh_predecessor_key(&successor.successor_refresh),
                );
                child_count =
                    child_count.saturating_add(self.revoke_refresh_family_direct_with_budget(
                        conn,
                        &successor.successor_refresh,
                        now,
                        mutation,
                        &mut budget,
                    )?);
            }
            mutation.delete_key(self.keyspace.refresh_predecessor_key(token));
            for child in child_tokens {
                self.revoke_access_and_meta_direct(conn, &child, now, mutation)?;
            }
            return Ok(TokenRevocationOutcome::RefreshToken { child_count });
        }

        if let Some(meta) = bearer_meta {
            mutation.revoke_until(token.to_string(), meta.expires_at, now);
            return Ok(TokenRevocationOutcome::BearerMeta);
        }

        Ok(TokenRevocationOutcome::Unknown)
    }

    pub(in crate::authcode::store) fn revoke_token(
        &self,
        token: &str,
    ) -> Result<TokenRevocationOutcome, TokenStoreStorageError> {
        self.with_lock("revoke_token_direct", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_revoked(conn, now, &mut mutation)?;
            let outcome = self.revoke_token_direct(conn, token, now, &mut mutation)?;
            let increment_version = !matches!(outcome, TokenRevocationOutcome::Unknown);
            self.apply_token_mutation(conn, mutation, increment_version)?;
            Ok(outcome)
        })
    }

    pub(in crate::authcode::store) fn revoke_token_for_client(
        &self,
        token: &str,
        requesting_client_id: Option<&str>,
    ) -> Result<
        (ClientBoundRevocationOutcome, Option<TokenRevocationOutcome>),
        TokenStoreStorageError,
    > {
        self.with_lock("revoke_token_for_client_direct", |conn| {
            let now = SystemTime::now();
            let mut mutation = RedisTokenMutation::default();
            self.collect_expired_revoked(conn, now, &mut mutation)?;

            let owner = self.known_token_client_id_direct(conn, token)?;
            if let (Some(owner), Some(requester)) = (owner.as_deref(), requesting_client_id) {
                if owner != requester {
                    self.apply_token_mutation(conn, mutation, false)?;
                    return Ok((ClientBoundRevocationOutcome::OwnerMismatch, None));
                }
            }
            if owner.is_some() && requesting_client_id.is_none() {
                self.apply_token_mutation(conn, mutation, false)?;
                return Ok((ClientBoundRevocationOutcome::OwnerMismatch, None));
            }
            if owner.is_none() {
                self.apply_token_mutation(conn, mutation, false)?;
                return Ok((ClientBoundRevocationOutcome::Unknown, None));
            }

            let revocation = self.revoke_token_direct(conn, token, now, &mut mutation)?;
            let increment_version = !matches!(revocation, TokenRevocationOutcome::Unknown);
            self.apply_token_mutation(conn, mutation, increment_version)?;
            let client_outcome = if matches!(revocation, TokenRevocationOutcome::Unknown) {
                ClientBoundRevocationOutcome::Unknown
            } else {
                ClientBoundRevocationOutcome::Revoked
            };
            Ok((client_outcome, Some(revocation)))
        })
    }
}
