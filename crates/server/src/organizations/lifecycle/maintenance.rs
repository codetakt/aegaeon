//! Offline operations select current state and exclude online sessions. No redo journal.
use super::*;
use std::path::Path;

pub(crate) fn options(endpoint: &str, ca: &Path) -> anyhow::Result<PgConnectOptions> {
    let bytes = crate::organizations::store_observation::transport::certificate(ca)?;
    Ok(
        crate::organizations::store_observation::transport::postgres_options(endpoint, ca, bytes)?
            .application_name("aegaeon-organization-maintenance"),
    )
}

impl Selection {
    /// The exclusive session lock follows the actual maintenance connection
    /// through its transactions and close. Loss releases it in PostgreSQL; a
    /// later attempt rechecks the selected state and domain receipts.
    pub(crate) async fn bind_maintenance(
        self,
        connection: &mut PgConnection,
    ) -> Result<(), sqlx::Error> {
        tokio::time::timeout(BIND_TIMEOUT, async {
            let locked: bool = sqlx::query_scalar("SELECT pg_catalog.pg_try_advisory_lock($1,$2)")
                .bind(LOCK_DOMAIN).bind(LOCK_KEY).fetch_one(&mut *connection).await?;
            if !locked { return Err(refused()); }
            let selected: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM aegaeon_lifecycle.current WHERE singleton AND deployment_id=$1 AND generation=$2) AND NOT pg_catalog.pg_is_in_recovery()")
                .bind(self.deployment).bind(self.generation).fetch_one(&mut *connection).await?;
            if !selected { return Err(refused()); }
            Ok(())
        }).await.map_err(|_| sqlx::Error::PoolTimedOut)?
    }
}
