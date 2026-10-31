use super::super::super::redis_support::RedisTokenMutation;
use super::super::RedisTokenStoreBackend;
use crate::authcode::store::{
    ClientBoundRevocationOutcome, TokenRevocationOutcome, TokenStoreStorageError,
};
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::SystemTime;

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store::redis_backend::revocation) fn revoke_token_direct(
        &self,
        conn: &mut impl redis::ConnectionLike,
        token: &str,
        now: SystemTime,
        mutation: &mut RedisTokenMutation,
    ) -> Result<TokenRevocationOutcome, TokenStoreStorageError> {
        let bearer_meta = Self::get_observed_json::<BearerTokenMeta>(
            conn,
            self.keyspace.bearer_key(token),
            mutation,
        )?;
        if bearer_meta
            .as_ref()
            .is_some_and(|meta| meta.token_id != token)
        {
            return Err(TokenStoreStorageError::InvariantViolation(
                "bearer cleanup identity mismatch".into(),
            ));
        }
        if bearer_meta.is_some() {
            mutation.delete_bearer_token(token.to_string());
        }

        if let Some(access) =
            Self::get_observed_json::<AccessToken>(conn, self.keyspace.access_key(token), mutation)?
        {
            if access.token != token {
                return Err(TokenStoreStorageError::InvariantViolation(
                    "access cleanup identity mismatch".into(),
                ));
            }
            mutation.delete_access_token(token.to_string());
            mutation.revoke_access_until(token.to_string(), &access, now);
            if let Some(meta) = bearer_meta {
                mutation.revoke_until(token.to_string(), meta.expires_at, now);
            }
            return Ok(TokenRevocationOutcome::AccessToken);
        }

        if Self::get_observed_json::<RefreshToken>(
            conn,
            self.keyspace.refresh_key(token),
            mutation,
        )?
        .is_some()
        {
            let child_count = self.revoke_refresh_family_direct(conn, token, now, mutation)?;
            return Ok(TokenRevocationOutcome::RefreshToken { child_count });
        }

        if let Some(meta) = bearer_meta {
            mutation.revoke_until(token.to_string(), meta.expires_at, now);
            return Ok(TokenRevocationOutcome::BearerMeta);
        }

        Ok(TokenRevocationOutcome::Unknown)
    }

    fn observed_token_client_id(
        &self,
        conn: &mut impl redis::ConnectionLike,
        token: &str,
        mutation: &mut RedisTokenMutation,
    ) -> Result<Option<String>, TokenStoreStorageError> {
        if let Some(access) =
            Self::get_observed_json::<AccessToken>(conn, self.keyspace.access_key(token), mutation)?
        {
            return Ok(Some(access.client_id));
        }
        if let Some(refresh) = Self::get_observed_json::<RefreshToken>(
            conn,
            self.keyspace.refresh_key(token),
            mutation,
        )? {
            return Ok(Some(refresh.client_id));
        }
        Ok(Self::get_observed_json::<BearerTokenMeta>(
            conn,
            self.keyspace.bearer_key(token),
            mutation,
        )?
        .map(|meta| meta.client_id))
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

            let owner = self.observed_token_client_id(conn, token, &mut mutation)?;
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
