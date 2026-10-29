//! A request admission lease follows every checked-out read connection through cleanup.
use sqlx::{pool::PoolConnection, Connection, PgConnection, PgPool, Postgres};
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;

pub(crate) struct AdmittedConnection {
    connection: Option<PoolConnection<Postgres>>,
    admission: Option<Arc<OwnedSemaphorePermit>>,
    previous_timeout: Option<String>,
}

impl AdmittedConnection {
    pub(crate) async fn acquire(pool: &PgPool) -> Result<Self, sqlx::Error> {
        let admission = super::credentials::admission::current();
        if admission.is_none() {
            return Ok(Self {
                connection: Some(pool.acquire().await?),
                admission,
                previous_timeout: None,
            });
        }
        let pool = pool.clone();
        // Cancellation while acquiring/configuring a connection must also keep
        // the lease. Dropping an unobserved task result invokes our cleanup.
        tokio::spawn(async move {
            let connection = pool.acquire().await?;
            let mut owned = Self {
                connection: Some(connection),
                admission,
                previous_timeout: None,
            };
            let previous = sqlx::query_scalar::<_, String>("SHOW statement_timeout")
                .fetch_one(owned.as_mut())
                .await?;
            owned.previous_timeout = Some(previous);
            sqlx::query("SELECT set_config('statement_timeout', LEAST(COALESCE(NULLIF(setting::bigint,0),5000),5000)::text, false) FROM pg_settings WHERE name='statement_timeout'")
                .execute(owned.as_mut())
                .await?;
            Ok(owned)
        })
        .await
        .map_err(|error| sqlx::Error::Protocol(format!("admitted read unavailable: {error}")))?
    }

    pub(crate) fn as_mut(&mut self) -> &mut PgConnection {
        self.connection.as_mut().expect("owned connection")
    }

    pub(crate) async fn release(mut self) {
        let _ = tokio::spawn(async move {
            self.cleanup().await;
        })
        .await;
    }

    async fn cleanup(&mut self) {
        let Some(mut connection) = self.connection.take() else {
            return;
        };
        if self.admission.is_some() {
            // SQLx drains any pending statement/queued rollback before this
            // reset. A cancelled query remains bounded by the server timeout.
            let drained = match connection.ping().await {
                Ok(()) => true,
                Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("57014") => {
                    // The cancelled statement's ErrorResponse precedes its
                    // ReadyForQuery and any queued rollback. Finish consuming
                    // those protocol messages; never replay application SQL.
                    connection.ping().await.is_ok()
                }
                Err(_) => false,
            };
            let restored = if let Some(previous) = self.previous_timeout.take().filter(|_| drained)
            {
                sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                    .bind(previous)
                    .execute(&mut *connection)
                    .await
                    .is_ok()
            } else {
                false
            };
            if !restored {
                let _ = connection.close().await;
                return;
            }
        }
        connection.return_to_pool().await;
    }
}

impl Drop for AdmittedConnection {
    fn drop(&mut self) {
        if self.connection.is_some() {
            let mut owned = Self {
                connection: self.connection.take(),
                admission: self.admission.take(),
                previous_timeout: self.previous_timeout.take(),
            };
            tokio::spawn(async move {
                owned.cleanup().await;
            });
        }
    }
}

#[cfg(test)]
mod tests;
