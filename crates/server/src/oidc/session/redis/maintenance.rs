use super::super::OidcSessionStorageError;
use super::{scripts, RedisOidcSessionBackend};

impl RedisOidcSessionBackend {
    pub(super) fn logout_expiry_score(logged_out_at_epoch_secs: u64, ttl_secs: u64) -> u64 {
        logged_out_at_epoch_secs.saturating_add(ttl_secs)
    }

    pub(super) fn prepared_connection(
        &self,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<redis::Connection, OidcSessionStorageError> {
        let mut conn = self.connection()?;
        self.cleanup_expired_with_conn(&mut conn, now_epoch_secs, ttl_secs)?;
        Ok(conn)
    }

    pub(super) fn cleanup_expired_with_conn(
        &self,
        conn: &mut redis::Connection,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<(), OidcSessionStorageError> {
        redis::Script::new(scripts::CLEANUP_EXPIRED)
            .key(self.keyspace.logged_out_expiries_key())
            .arg(now_epoch_secs)
            .arg(ttl_secs)
            .arg(now_epoch_secs.saturating_add(ttl_secs))
            .arg(self.keyspace.session_key_prefix())
            .arg(self.keyspace.clients_key_prefix())
            .invoke::<i64>(conn)
            .map(|_| ())
            .map_err(|err| OidcSessionStorageError::BackendUnavailable(err.to_string()))
    }
}
