//! Admission must precede body reading and all database-using middleware.
//! A lease follows checked-out connections through protocol/pool cleanup.
use sqlx::{pool::PoolConnection, Connection, PgConnection, PgPool, Postgres};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const MAX_REQUESTS: usize = 4;
static REQUESTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_REQUESTS)));
static REVOCATIONS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));
static SNAPSHOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));
static COMMIT_BOUNDARY: Mutex<()> = Mutex::new(());

/// No constructor accepts a caller-supplied claim or bypass flag.
#[derive(Clone)]
pub struct Admission {
    _permit: Arc<OwnedSemaphorePermit>,
    limit: Arc<Semaphore>,
    snapshot: bool,
    parent: Option<Arc<Self>>,
}

impl Admission {
    #[cfg(test)]
    pub(crate) fn isolated_for_test() -> Result<Self, sqlx::Error> {
        Self::from_limit(&Arc::new(Semaphore::new(1)))
    }

    #[cfg(test)]
    pub(crate) async fn drain_for_test() -> Result<(), Box<dyn std::error::Error>> {
        // Pool closure may finish before the cleanup task releases its own
        // permit. Observe actual ownership without reopening or resetting it.
        let ordinary = tokio::time::timeout(
            Duration::from_secs(30),
            REQUESTS.clone().acquire_many_owned(MAX_REQUESTS as u32),
        )
        .await??;
        let revocation =
            tokio::time::timeout(Duration::from_secs(30), REVOCATIONS.clone().acquire_owned())
                .await??;
        let snapshot =
            tokio::time::timeout(Duration::from_secs(30), SNAPSHOTS.clone().acquire_owned())
                .await??;
        drop((ordinary, revocation, snapshot));
        Ok(())
    }

    pub(crate) fn close_until_restart(&self) {
        let _boundary = COMMIT_BOUNDARY
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.limit.close();
        if let Some(parent) = &self.parent {
            parent.limit.close();
        }
    }

    // The linearization point is this check under the closure lock. No database
    // I/O occurs under the lock; a commit admitted first may finish afterward.
    pub(crate) fn admit_commit(&self) -> Result<(), sqlx::Error> {
        let _boundary = COMMIT_BOUNDARY.lock().map_err(|_| {
            self.limit.close();
            sqlx::Error::PoolClosed
        })?;
        self.ensure_open()
    }

    pub fn try_acquire() -> Result<Self, sqlx::Error> {
        Self::from_limit(&REQUESTS)
    }

    /// Only the revoke-only route may use this separate process-wide reserve.
    pub(crate) fn try_acquire_revocation() -> Result<Self, sqlx::Error> {
        Self::from_limit(&REVOCATIONS)
    }

    /// Reserved for the read-only snapshot worker. Ordinary mutations retain
    /// their existing connection and transaction deadlines.
    pub(crate) fn try_acquire_snapshot() -> Result<Self, sqlx::Error> {
        let mut admission = Self::from_limit(&SNAPSHOTS)?;
        admission.snapshot = true;
        Ok(admission)
    }

    /// Live authority work consumes ordinary capacity and retains the snapshot
    /// lease through any detached session/SQL/pool cleanup it owns.
    pub(crate) fn current_snapshot_authority(&self) -> Result<Self, sqlx::Error> {
        self.ensure_open()?;
        if !self.snapshot {
            return Err(sqlx::Error::Protocol("snapshot admission required".into()));
        }
        let mut current = Self::try_acquire()?;
        current.parent = Some(Arc::new(self.clone()));
        Ok(current)
    }

    fn from_limit(limit: &Arc<Semaphore>) -> Result<Self, sqlx::Error> {
        limit
            .clone()
            .try_acquire_owned()
            .map(|permit| Self {
                _permit: Arc::new(permit),
                limit: limit.clone(),
                snapshot: false,
                parent: None,
            })
            .map_err(|_| sqlx::Error::PoolTimedOut)
    }

    pub(crate) fn ensure_open(&self) -> Result<(), sqlx::Error> {
        if let Some(parent) = &self.parent {
            parent.ensure_open()?;
        }
        if self.limit.is_closed() {
            Err(sqlx::Error::PoolClosed)
        } else {
            Ok(())
        }
    }

    pub async fn connection(&self, pool: &PgPool) -> Result<AdmittedConnection, sqlx::Error> {
        self.ensure_open()?;
        // An opaque pool acquisition can run connection hooks. Its owner must
        // survive caller cancellation until the pool's own finite deadline.
        if pool.options().get_acquire_timeout() > Duration::from_secs(30) {
            return Err(sqlx::Error::Configuration(
                "Organizations pool acquisition exceeds 30 seconds".into(),
            ));
        }
        let pool = pool.clone();
        let admission = self.clone();
        tokio::spawn(async move {
            let mut acquisition = Acquisition { admission: admission.clone(), finished: false };
            let connection = pool.acquire().await;
            acquisition.finished = true;
            let connection = connection?;
            let mut owned = AdmittedConnection {
                connection: Some(connection),
                admission,
                previous: None,
                runtime: tokio::runtime::Handle::current(),
            };
            let previous: Vec<String> = sqlx::query_scalar(
                "SELECT ARRAY[current_setting('statement_timeout'),current_setting('lock_timeout'),current_setting('idle_in_transaction_session_timeout'),current_setting('transaction_timeout')]",
            )
            .fetch_one(owned.as_mut()?)
            .await?;
            owned.previous = Some(previous.try_into().map_err(|_| {
                sqlx::Error::Protocol("incomplete Organizations timeout settings".into())
            })?);
            let (idle, transaction) = if owned.admission.snapshot { (30_000i64, 3_600_000i64) } else { (10_000, 20_000) };
            sqlx::query(
                "SELECT set_config(name,LEAST(COALESCE(NULLIF(setting::bigint,0),budget),budget)::text,false) FROM pg_settings JOIN (VALUES ('statement_timeout',5000::bigint),('lock_timeout',1000::bigint),('idle_in_transaction_session_timeout',$1::bigint),('transaction_timeout',$2::bigint)) AS limits(name,budget) USING(name)",
            ).bind(idle).bind(transaction)
            .execute(owned.as_mut()?)
            .await?;
            Ok(owned)
        })
        .await
        .map_err(|error| sqlx::Error::Protocol(format!("Organizations connection worker failed: {error}")))?
    }
}

struct Acquisition {
    admission: Admission,
    finished: bool,
}

impl Drop for Acquisition {
    fn drop(&mut self) {
        if !self.finished {
            self.admission.close_until_restart();
        }
    }
}

pub struct AdmittedConnection {
    connection: Option<PoolConnection<Postgres>>,
    admission: Admission,
    previous: Option<[String; 4]>,
    runtime: tokio::runtime::Handle,
}

impl AdmittedConnection {
    pub fn as_mut(&mut self) -> Result<&mut PgConnection, sqlx::Error> {
        self.admission.ensure_open()?;
        self.connection.as_deref_mut().ok_or_else(|| {
            sqlx::Error::Protocol("Organizations connection already released".into())
        })
    }

    pub async fn release(mut self) {
        if let Some(cleanup) = self.take_cleanup() {
            let _ = tokio::spawn(cleanup.run()).await;
        }
    }

    fn take_cleanup(&mut self) -> Option<Cleanup> {
        self.connection.take().map(|connection| Cleanup {
            connection: Some(connection),
            admission: self.admission.clone(),
            previous: self.previous.take(),
            finished: false,
            runtime: self.runtime.clone(),
        })
    }
}

// This owner must never spawn another cleanup from its destructor. A dying
// runtime cancels newly spawned futures before polling them.
struct Cleanup {
    connection: Option<PoolConnection<Postgres>>,
    admission: Admission,
    previous: Option<[String; 4]>,
    finished: bool,
    runtime: tokio::runtime::Handle,
}

impl Cleanup {
    async fn run(mut self) {
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        // Drain a cancelled statement and any queued rollback. ErrorResponse
        // 57014 precedes ReadyForQuery, so consuming it is not sufficient.
        let drained = match connection.ping().await {
            Ok(()) => true,
            Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("57014") => {
                connection.ping().await.is_ok()
            }
            Err(_) => false,
        };
        let restored = if let Some([statement, lock, idle, transaction]) =
            self.previous.take().filter(|_| drained)
        {
            sqlx::query("SELECT set_config('statement_timeout',$1,false),set_config('lock_timeout',$2,false),set_config('idle_in_transaction_session_timeout',$3,false),set_config('transaction_timeout',$4,false)")
                .bind(statement).bind(lock).bind(idle).bind(transaction)
                .execute(&mut **connection).await.is_ok()
        } else {
            false
        };
        if restored {
            // SQLx transfers the live connection into its return future. The
            // fallback must not detach the empty wrapper after interruption.
            if let Some(mut returning) = self.connection.take() {
                returning.return_to_pool().await;
            }
            self.finished = true;
        } else if let Some(connection) = self.connection.take() {
            self.finished = connection.close().await.is_ok();
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if !self.finished {
            // An interrupted cleanup does not prove that the server stopped.
            // Close this admission class until process restart; never replenish
            // its capacity on an unconfirmed cleanup or shutdown.
            self.admission.close_until_restart();
            if let Some(connection) = self.connection.take() {
                // Detach before dropping the transport, never return a dirty
                // connection to the pool. SQLx may schedule pool maintenance;
                // enter the original handle even when dropped outside runtime.
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
