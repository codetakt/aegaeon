//! A request admission lease follows every checked-out read connection through cleanup.
use sqlx::{pool::PoolConnection, Connection, PgConnection, PgPool, Postgres};
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;

pub(crate) fn request_admission_active() -> bool {
    super::credentials::admission::current().is_some()
}

pub(crate) struct AdmittedConnection {
    connection: Option<PoolConnection<Postgres>>,
    organization: Option<crate::organizations::request_work::AdmittedConnection>,
    organization_owner: Option<crate::organizations::request_work::Admission>,
    admission: Option<Arc<OwnedSemaphorePermit>>,
    previous_timeout: Option<String>,
    runtime: tokio::runtime::Handle,
}

impl AdmittedConnection {
    pub(crate) async fn acquire(pool: &PgPool) -> Result<Self, sqlx::Error> {
        let admission = super::credentials::admission::current();
        super::credentials::admission::ensure_open(admission.as_ref())
            .map_err(|_| sqlx::Error::PoolClosed)?;
        if let Some(owner) = crate::organizations::request_work::async_store::task_owner()? {
            let pool = pool.clone();
            return tokio::spawn(async move {
                let mut acquisition =
                    super::credentials::admission::CompletionGuard::new(admission.clone());
                let connection = owner.connection(&pool).await?;
                let owned = Self {
                    connection: None,
                    organization: Some(connection),
                    organization_owner: Some(owner),
                    admission,
                    previous_timeout: None,
                    runtime: tokio::runtime::Handle::current(),
                };
                acquisition.complete();
                Ok(owned)
            })
            .await
            .map_err(|error| {
                sqlx::Error::Protocol(format!("Organizations authority read unavailable: {error}"))
            })?;
        }
        if admission.is_none() {
            return Ok(Self {
                connection: Some(pool.acquire().await?),
                organization: None,
                organization_owner: None,
                admission,
                previous_timeout: None,
                runtime: tokio::runtime::Handle::current(),
            });
        }
        let pool = pool.clone();
        // Cancellation while acquiring/configuring a connection must also keep
        // the lease. Dropping an unobserved task result invokes our cleanup.
        tokio::spawn(async move {
            let mut acquisition = super::credentials::admission::CompletionGuard::new(admission.clone());
            let connection = pool.acquire().await;
            acquisition.complete();
            let connection = connection?;
            let mut owned = Self {
                connection: Some(connection),
                organization: None,
                organization_owner: None,
                admission,
                previous_timeout: None,
                runtime: tokio::runtime::Handle::current(),
            };
            let previous = sqlx::query_scalar::<_, String>("SHOW statement_timeout")
                .fetch_one(owned.as_mut()?)
                .await?;
            owned.previous_timeout = Some(previous);
            sqlx::query("SELECT set_config('statement_timeout', LEAST(COALESCE(NULLIF(setting::bigint,0),5000),5000)::text, false) FROM pg_settings WHERE name='statement_timeout'")
                .execute(owned.as_mut()?)
                .await?;
            Ok(owned)
        })
        .await
        .map_err(|error| sqlx::Error::Protocol(format!("admitted read unavailable: {error}")))?
    }

    pub(crate) fn as_mut(&mut self) -> Result<&mut PgConnection, sqlx::Error> {
        if let Some(connection) = self.organization.as_mut() {
            return connection.as_mut();
        }
        self.connection
            .as_deref_mut()
            .ok_or_else(|| sqlx::Error::Protocol("admitted connection was already released".into()))
    }

    pub(crate) async fn release(mut self) {
        if let Some(cleanup) = self.take_cleanup() {
            let _ = self.runtime.spawn(cleanup.run()).await;
        }
    }

    fn take_cleanup(&mut self) -> Option<Cleanup> {
        if self.connection.is_none() && self.organization.is_none() {
            return None;
        }
        Some(Cleanup {
            connection: self.connection.take(),
            organization: self.organization.take(),
            organization_owner: self.organization_owner.take(),
            admission: self.admission.take(),
            previous_timeout: self.previous_timeout.take(),
            runtime: self.runtime.clone(),
            finished: false,
        })
    }
}

// A cancelled cleanup future must never recursively spawn another cleanup.
struct Cleanup {
    connection: Option<PoolConnection<Postgres>>,
    organization: Option<crate::organizations::request_work::AdmittedConnection>,
    organization_owner: Option<crate::organizations::request_work::Admission>,
    admission: Option<Arc<OwnedSemaphorePermit>>,
    previous_timeout: Option<String>,
    runtime: tokio::runtime::Handle,
    finished: bool,
}

impl Cleanup {
    async fn run(mut self) {
        if let Some(connection) = self.organization.take() {
            connection.release().await;
            self.finished = self
                .organization_owner
                .as_ref()
                .is_some_and(|owner| owner.ensure_open().is_ok());
            return;
        }
        let Some(connection) = self.connection.as_mut() else {
            self.finished = true;
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
                    .execute(&mut **connection)
                    .await
                    .is_ok()
            } else {
                false
            };
            if !restored {
                if let Some(connection) = self.connection.take() {
                    self.finished = connection.close().await.is_ok();
                }
                return;
            }
        }
        // SQLx moves its live connection into the returned future. Remove the
        // now-empty wrapper from our fallback before awaiting that future, so
        // interruption cannot detach an already transferred connection.
        if let Some(mut returning) = self.connection.take() {
            returning.return_to_pool().await;
        }
        self.finished = true;
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if !self.finished {
            super::credentials::admission::close(self.admission.as_ref());
            if let Some(owner) = &self.organization_owner {
                owner.close_until_restart();
            }
            if let Some(connection) = self.connection.take() {
                let _entered = self.runtime.enter();
                drop(connection.detach());
            }
        }
    }
}

impl Drop for AdmittedConnection {
    fn drop(&mut self) {
        if let Some(cleanup) = self.take_cleanup() {
            self.runtime.spawn(cleanup.run());
        }
    }
}

#[cfg(test)]
mod tests;
