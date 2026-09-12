//! A root marker is independent of bounded child cleanup and of the mutation lease.
use super::RedisTokenStoreBackend;
use crate::authcode::store::{
    redis_support::{encode_redis_json, RedisRevokedTokenRecord},
    TokenStoreStorageError,
};
use crate::policy::token_exchange::{ExchangeGrant, ExchangeRoot};
use std::time::SystemTime;

impl RedisTokenStoreBackend {
    pub(super) fn exchange_root_active(
        &self,
        conn: &mut redis::Connection,
        root: Option<&ExchangeRoot>,
        now: SystemTime,
    ) -> Result<bool, TokenStoreStorageError> {
        let Some(root) = root else {
            return Ok(true);
        };
        Ok(now < root.expires_at && !self.is_revoked_direct(conn, &root.id, now)?)
    }

    /// Commit irrevocable denial before walking a possibly oversized or incomplete child index.
    /// All tokens in this root share one immutable deadline, so an older writer cannot shorten it.
    pub(super) fn revoke_exchange_root(
        &self,
        conn: &mut redis::Connection,
        grant: Option<&ExchangeGrant>,
    ) -> Result<(), TokenStoreStorageError> {
        let Some(root) = grant.and_then(ExchangeGrant::root) else {
            return Ok(());
        };
        let record = RedisRevokedTokenRecord {
            token: root.id.clone(),
            expires_at: root.expires_at,
        };
        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("SET")
            .arg(self.keyspace.revoked_key(&root.id))
            .arg(encode_redis_json(&record)?)
            .ignore();
        self.index_revoked_cmd(&mut pipe, &root.id, root.expires_at);
        Self::increment_version(&mut pipe, &self.keyspace);
        pipe.query::<()>(conn)
            .map_err(|error| TokenStoreStorageError::BackendUnavailable(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authcode::store::redis_support::RedisTokenMutation;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    #[ignore = "requires AEGAEON_TEST_REDIS_URL"]
    fn token_exchange_target_root_cleanup_preserves_subsecond_denial() -> Result<(), String> {
        let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|error| error.to_string())?;
        let backend =
            RedisTokenStoreBackend::new_for_tests(&url).map_err(|error| format!("{error:?}"))?;
        let mut conn = backend.connection().map_err(|error| format!("{error:?}"))?;
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs()
            + 30;
        let deadline = UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_millis(900);
        let root = ExchangeRoot {
            id: format!("exchange-root:{}", uuid::Uuid::new_v4()),
            expires_at: deadline,
        };
        let record = RedisRevokedTokenRecord {
            token: root.id.clone(),
            expires_at: deadline,
        };
        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("SET")
            .arg(backend.keyspace.revoked_key(&root.id))
            .arg(encode_redis_json(&record).map_err(|error| format!("{error:?}"))?)
            .ignore();
        backend.index_revoked_cmd(&mut pipe, &root.id, deadline);
        pipe.query::<()>(&mut conn)
            .map_err(|error| error.to_string())?;
        let mut mutation = RedisTokenMutation::default();
        backend
            .collect_expired_revoked(
                &mut conn,
                deadline - Duration::from_millis(500),
                &mut mutation,
            )
            .map_err(|error| format!("{error:?}"))?;
        assert!(
            !mutation.delete_revoked_tokens.contains(&root.id),
            "floor-second index must not erase a still-live tombstone"
        );
        Ok(())
    }
}
