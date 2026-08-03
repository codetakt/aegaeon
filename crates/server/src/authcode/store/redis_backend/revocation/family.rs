use super::super::super::redis_support::{
    RedisRefreshSuccessorRecord, RedisTokenMutation, MAX_REFRESH_FAMILY_REVOCATION_CHILD_TOKENS,
    MAX_REFRESH_FAMILY_REVOCATION_REFRESH_VISITS,
};
use super::super::RedisTokenStoreBackend;
use crate::authcode::store::TokenStoreStorageError;
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
        now: SystemTime,
        mutation: &mut RedisTokenMutation,
    ) -> Result<(), TokenStoreStorageError> {
        if let Some(access) = Self::get_json::<AccessToken>(conn, self.keyspace.access_key(token))?
        {
            mutation.delete_access_token(token.to_string());
            mutation.revoke_access_until(token.to_string(), &access, now);
        }
        if let Some(meta) =
            Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(token))?
        {
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

    pub(in crate::authcode::store::redis_backend::revocation) fn revoke_refresh_family_direct_with_budget(
        &self,
        conn: &mut redis::Connection,
        root_refresh: &str,
        now: SystemTime,
        mutation: &mut RedisTokenMutation,
        budget: &mut RefreshFamilyRevocationBudget,
    ) -> Result<usize, TokenStoreStorageError> {
        let mut stack = vec![root_refresh.to_string()];
        let mut seen = HashSet::new();
        let mut child_count = 0usize;

        while let Some(refresh) = stack.pop() {
            if !seen.insert(refresh.clone()) {
                continue;
            }
            budget.consume_refresh_visit(&refresh)?;

            if let Some(successor) = Self::get_json::<RedisRefreshSuccessorRecord>(
                conn,
                self.keyspace.refresh_successor_key(&refresh),
            )? {
                mutation.delete_key(self.keyspace.refresh_successor_key(&refresh));
                mutation.delete_key(
                    self.keyspace
                        .refresh_predecessor_key(&successor.successor_refresh),
                );
                stack.push(successor.successor_refresh);
            }

            let refresh_token =
                Self::get_json::<RefreshToken>(conn, self.keyspace.refresh_key(&refresh))?;
            let refresh_exists = refresh_token.is_some();
            if let Some(token) = refresh_token {
                mutation.delete_refresh_token(refresh.clone());
                mutation.revoke_until(refresh.clone(), token.expires_at, now);
            }
            mutation.delete_key(self.keyspace.refresh_predecessor_key(&refresh));

            if let Some(meta) =
                Self::get_json::<BearerTokenMeta>(conn, self.keyspace.bearer_key(&refresh))?
            {
                mutation.delete_bearer_token(refresh.clone());
                mutation.revoke_until(refresh.clone(), meta.expires_at, now);
            }

            if refresh_exists {
                let child_tokens = self.refresh_children(conn, &refresh)?;
                mutation.delete_key(self.keyspace.refresh_children_key(&refresh));
                budget.consume_child_tokens(&refresh, child_tokens.len())?;
                child_count = child_count.saturating_add(child_tokens.len());
                for child in child_tokens {
                    self.revoke_access_and_meta_direct(conn, &child, now, mutation)?;
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
