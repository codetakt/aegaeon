use super::super::super::redis_support::{
    RedisRefreshChildrenRecord, RedisRefreshPredecessorRecord, RedisRefreshSuccessorRecord,
    RedisTokenMutation, MAX_REFRESH_FAMILY_REVOCATION_CHILD_TOKENS,
    MAX_REFRESH_FAMILY_REVOCATION_REFRESH_VISITS,
};
use super::super::RedisTokenStoreBackend;
use crate::authcode::store::{token_consistency::refresh_family_matches, TokenStoreStorageError};
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::collections::HashSet;
use std::time::SystemTime;

pub(in crate::authcode::store::redis_backend::revocation) struct RefreshFamilyRevocationBudget {
    refresh_visits_remaining: usize,
    child_tokens_remaining: usize,
}

impl RefreshFamilyRevocationBudget {
    pub(in crate::authcode::store::redis_backend::revocation) const fn new() -> Self {
        Self {
            refresh_visits_remaining: MAX_REFRESH_FAMILY_REVOCATION_REFRESH_VISITS,
            child_tokens_remaining: MAX_REFRESH_FAMILY_REVOCATION_CHILD_TOKENS,
        }
    }

    #[cfg(test)]
    const fn with_limits(refresh_visits: usize, child_tokens: usize) -> Self {
        Self {
            refresh_visits_remaining: refresh_visits,
            child_tokens_remaining: child_tokens,
        }
    }

    pub(in crate::authcode::store::redis_backend::revocation) fn consume_refresh_visit(
        &mut self,
        refresh: &str,
    ) -> Result<(), TokenStoreStorageError> {
        self.refresh_visits_remaining =
            self.refresh_visits_remaining
                .checked_sub(1)
                .ok_or_else(|| {
                    refresh_family_revocation_limit_error("refresh token visits", refresh)
                })?;
        Ok(())
    }

    pub(in crate::authcode::store::redis_backend::revocation) fn consume_child_tokens(
        &mut self,
        refresh: &str,
        count: usize,
    ) -> Result<(), TokenStoreStorageError> {
        self.child_tokens_remaining = self
            .child_tokens_remaining
            .checked_sub(count)
            .ok_or_else(|| refresh_family_revocation_limit_error("child access tokens", refresh))?;
        Ok(())
    }
}

fn refresh_family_revocation_limit_error(kind: &str, _refresh: &str) -> TokenStoreStorageError {
    TokenStoreStorageError::InvariantViolation(format!(
        "refresh token family revocation exceeded {kind} budget"
    ))
}

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store::redis_backend::revocation) fn revoke_access_and_meta_direct(
        &self,
        conn: &mut redis::Connection,
        token: &str,
        root: &RefreshToken,
        now: SystemTime,
        mutation: &mut RedisTokenMutation,
    ) -> Result<(), TokenStoreStorageError> {
        if let Some(access) =
            Self::get_observed_json::<AccessToken>(conn, self.keyspace.access_key(token), mutation)?
        {
            if access.token != token
                || !refresh_family_matches(
                    root,
                    access.refresh_grant.as_ref(),
                    &access.client_id,
                    &access.user_id,
                )
            {
                return Err(TokenStoreStorageError::InvariantViolation(
                    "access cleanup token identity mismatch".into(),
                ));
            }
            mutation.delete_access_token(token.to_string());
            mutation.revoke_access_until(token.to_string(), &access, now);
        }
        if let Some(meta) = Self::get_observed_json::<BearerTokenMeta>(
            conn,
            self.keyspace.bearer_key(token),
            mutation,
        )? {
            if meta.token_id != token
                || !refresh_family_matches(
                    root,
                    meta.refresh_grant.as_ref(),
                    &meta.client_id,
                    &meta.user_id,
                )
            {
                return Err(TokenStoreStorageError::InvariantViolation(
                    "bearer cleanup token identity mismatch".into(),
                ));
            }
            mutation.delete_bearer_token(token.to_string());
            mutation.revoke_until(token.to_string(), meta.expires_at, now);
        }
        Ok(())
    }

    pub(in crate::authcode::store::redis_backend) fn revoke_refresh_family_direct(
        &self,
        conn: &mut redis::Connection,
        root_refresh: &str,
        now: SystemTime,
        mutation: &mut RedisTokenMutation,
    ) -> Result<usize, TokenStoreStorageError> {
        let mut budget = RefreshFamilyRevocationBudget::new();
        self.revoke_refresh_family_direct_with_budget(
            conn,
            root_refresh,
            now,
            mutation,
            &mut budget,
        )
    }

    pub(in crate::authcode::store::redis_backend) fn collect_refresh_predecessor(
        &self,
        conn: &mut redis::Connection,
        refresh: &str,
        parent: Option<&str>,
        mutation: &mut RedisTokenMutation,
    ) -> Result<(), TokenStoreStorageError> {
        let key = self.keyspace.refresh_predecessor_key(refresh);
        if let Some(record) =
            Self::get_observed_json::<RedisRefreshPredecessorRecord>(conn, key.clone(), mutation)?
        {
            if record.refresh_token != refresh
                || parent.is_some_and(|expected| record.predecessor_refresh != expected)
            {
                return Err(TokenStoreStorageError::InvariantViolation(
                    "refresh predecessor identity mismatch".into(),
                ));
            }
        }
        mutation.delete_key(key);
        Ok(())
    }

    pub(in crate::authcode::store::redis_backend) fn collect_refresh_successor(
        &self,
        conn: &mut redis::Connection,
        refresh: &str,
        mutation: &mut RedisTokenMutation,
    ) -> Result<Option<String>, TokenStoreStorageError> {
        let key = self.keyspace.refresh_successor_key(refresh);
        let Some(record) =
            Self::get_observed_json::<RedisRefreshSuccessorRecord>(conn, key.clone(), mutation)?
        else {
            return Ok(None);
        };
        if record.previous_refresh != refresh {
            return Err(TokenStoreStorageError::InvariantViolation(
                "refresh successor identity mismatch".into(),
            ));
        }
        self.collect_refresh_predecessor(conn, &record.successor_refresh, Some(refresh), mutation)?;
        mutation.delete_key(key);
        Ok(Some(record.successor_refresh))
    }

    pub(in crate::authcode::store::redis_backend) fn observed_refresh_children(
        &self,
        conn: &mut redis::Connection,
        refresh: &str,
        mutation: &mut RedisTokenMutation,
    ) -> Result<HashSet<String>, TokenStoreStorageError> {
        let record = Self::get_observed_json::<RedisRefreshChildrenRecord>(
            conn,
            self.keyspace.refresh_children_key(refresh),
            mutation,
        )?;
        if record
            .as_ref()
            .is_some_and(|value| value.refresh_token != refresh)
        {
            return Err(TokenStoreStorageError::InvariantViolation(
                "refresh child index identity mismatch".into(),
            ));
        }
        Ok(record.map_or_else(HashSet::new, |value| value.access_tokens))
    }

    pub(in crate::authcode::store::redis_backend::revocation) fn revoke_refresh_family_direct_with_budget(
        &self,
        conn: &mut redis::Connection,
        root_refresh: &str,
        now: SystemTime,
        mutation: &mut RedisTokenMutation,
        budget: &mut RefreshFamilyRevocationBudget,
    ) -> Result<usize, TokenStoreStorageError> {
        let Some(root) = Self::get_observed_json::<RefreshToken>(
            conn,
            self.keyspace.refresh_key(root_refresh),
            mutation,
        )?
        else {
            return Ok(0);
        };
        if root.token != root_refresh {
            return Err(TokenStoreStorageError::InvariantViolation(
                "refresh cleanup token identity mismatch".into(),
            ));
        }
        self.revoke_refresh_grant(
            conn,
            root.refresh_grant.as_ref(),
            &root.client_id,
            &root.user_id,
        )?;
        self.revoke_exchange_root(conn, root.exchange_grant.as_ref())?;
        let mut stack = vec![root_refresh.to_string()];
        let mut seen = HashSet::new();
        let mut child_count = 0usize;

        while let Some(refresh) = stack.pop() {
            if !seen.insert(refresh.clone()) {
                continue;
            }
            budget.consume_refresh_visit(&refresh)?;

            if let Some(successor) = self.collect_refresh_successor(conn, &refresh, mutation)? {
                stack.push(successor);
            }

            let refresh_token = Self::get_observed_json::<RefreshToken>(
                conn,
                self.keyspace.refresh_key(&refresh),
                mutation,
            )?;
            let refresh_exists = refresh_token.is_some();
            if let Some(token) = refresh_token {
                if token.token != refresh
                    || !refresh_family_matches(
                        &root,
                        token.refresh_grant.as_ref(),
                        &token.client_id,
                        &token.user_id,
                    )
                {
                    return Err(TokenStoreStorageError::InvariantViolation(
                        "refresh cleanup token identity mismatch".into(),
                    ));
                }
                self.revoke_refresh_grant(
                    conn,
                    token.refresh_grant.as_ref(),
                    &token.client_id,
                    &token.user_id,
                )?;
                self.revoke_exchange_root(conn, token.exchange_grant.as_ref())?;
                mutation.delete_refresh_token(refresh.clone());
                mutation.revoke_until(refresh.clone(), token.expires_at, now);
            }
            self.collect_refresh_predecessor(conn, &refresh, None, mutation)?;

            if let Some(meta) = Self::get_observed_json::<BearerTokenMeta>(
                conn,
                self.keyspace.bearer_key(&refresh),
                mutation,
            )? {
                if meta.token_id != refresh
                    || !refresh_family_matches(
                        &root,
                        meta.refresh_grant.as_ref(),
                        &meta.client_id,
                        &meta.user_id,
                    )
                {
                    return Err(TokenStoreStorageError::InvariantViolation(
                        "bearer cleanup token identity mismatch".into(),
                    ));
                }
                Self::get_observed_json::<AccessToken>(
                    conn,
                    self.keyspace.access_key(&refresh),
                    mutation,
                )?;
                mutation.delete_bearer_token(refresh.clone());
                mutation.revoke_until(refresh.clone(), meta.expires_at, now);
            }

            if refresh_exists {
                let child_tokens = self.observed_refresh_children(conn, &refresh, mutation)?;
                mutation.delete_key(self.keyspace.refresh_children_key(&refresh));
                budget.consume_child_tokens(&refresh, child_tokens.len())?;
                child_count = child_count.saturating_add(child_tokens.len());
                for child in child_tokens {
                    self.revoke_access_and_meta_direct(conn, &child, &root, now, mutation)?;
                }
            }
        }

        Ok(child_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invariant_message(error: TokenStoreStorageError) -> String {
        match error {
            TokenStoreStorageError::InvariantViolation(message) => message,
            other => panic!("expected invariant violation, got {other:?}"),
        }
    }

    #[test]
    fn revocation_budget_rejects_refresh_visit_overflow() {
        let mut budget = RefreshFamilyRevocationBudget::with_limits(1, 8);

        assert!(budget.consume_refresh_visit("r1").is_ok());
        let message = invariant_message(
            budget
                .consume_refresh_visit("r2")
                .expect_err("second refresh visit must exceed budget"),
        );

        assert!(message.contains("refresh token visits"));
    }

    #[test]
    fn revocation_budget_rejects_child_token_overflow() {
        let mut budget = RefreshFamilyRevocationBudget::with_limits(8, 2);

        assert!(budget.consume_child_tokens("r1", 2).is_ok());
        let message = invariant_message(
            budget
                .consume_child_tokens("r1", 1)
                .expect_err("third child token must exceed budget"),
        );

        assert!(message.contains("child access tokens"));
    }
}
