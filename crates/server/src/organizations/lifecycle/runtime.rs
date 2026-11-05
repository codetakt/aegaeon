use super::*;
use crate::organizations::{
    request_work::{Admission, CapacityClass},
    witness::{
        work::{Execution, Starter},
        Error,
    },
};
use sqlx::Connection;
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::Semaphore;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
pub struct Limits {
    pub ordinary: u32,
    pub revocation: u32,
    pub snapshot: u32,
}

/// One captured generation and bounded local ownership. SQL authority is checked
/// by the pool's physical-connection hook, never by a deserialized admission flag.
pub struct Runtime {
    pub(crate) selection: Selection,
    pub(crate) pool: PgPool,
    revocation_pool: PgPool,
    pub(super) proofs: super::proofs::Barrier,
    pub(crate) environments: BTreeMap<Uuid, String>,
    ordinary: Arc<Semaphore>,
    revocation: Arc<Semaphore>,
    snapshot: Arc<Semaphore>,
    closed: AtomicBool,
}
impl Runtime {
    pub async fn checked(
        selection: Selection,
        options: PgPoolOptions,
        endpoint: PgConnectOptions,
        environments: Vec<(Uuid, String)>,
        limits: Limits,
    ) -> Result<Arc<Self>> {
        if environments.is_empty()
            || environments.len() > 1024
            || !(1..=4096).contains(&limits.ordinary)
            || !(1..=64).contains(&limits.revocation)
            || !(1..=4).contains(&limits.snapshot)
            || options.get_max_connections() < 2
            || options.get_acquire_timeout() > Duration::from_secs(30)
        {
            return Err(Error::Refused);
        }
        let mut registry = BTreeMap::new();
        for (id, issuer) in environments {
            let url = url::Url::parse(&issuer).map_err(|_| Error::Refused)?;
            if id.is_nil()
                || issuer.len() > 16384
                || url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || registry.values().any(|old| old == &issuer)
                || registry.insert(id, issuer).is_some()
            {
                return Err(Error::Refused);
            }
        }
        // Reserve physical SQL capacity as well as request owners. Ordinary
        // traffic cannot borrow this pool; both pools stay within the configured
        // total and every connection holds the same generation fence.
        let (ordinary, reserved) = aegaeon_pure::organization_recovery::connection_partition(
            options.get_max_connections(),
            limits.revocation,
        )
        .ok_or(Error::Refused)?;
        // SQLx retries after_connect refusals until acquire_timeout. Validate
        // once on a bounded direct connection so startup distinguishes an explicit
        // generation/role refusal from unavailable transport. Every subsequent
        // physical pool connection still repeats bind; this is not cached authority.
        tokio::time::timeout(options.get_acquire_timeout(), async {
            let mut connection = PgConnection::connect_with(&endpoint).await?;
            let selected = selection.bind(&mut connection).await;
            let closed = connection.close().await;
            selected.and(closed)
        })
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(|error| match error {
            sqlx::Error::Protocol(ref reason)
                if reason == "runtime lifecycle selection refused" =>
            {
                Error::SelectionRefused
            }
            other => Error::Storage(other),
        })?;
        let revocation_pool = selection.pool(
            options.clone().min_connections(0).max_connections(reserved),
            endpoint.clone(),
        );
        let pool = selection.pool(
            options.min_connections(0).max_connections(ordinary),
            endpoint,
        );
        if let Err(error) = pool.acquire().await {
            close_pool(&pool).await;
            return Err(error.into());
        }
        let proofs = match super::proofs::Barrier::load(&pool).await {
            Ok(proofs) => proofs,
            Err(error) => {
                close_pool(&pool).await;
                return Err(error.into());
            }
        };
        Ok(Arc::new(Self {
            selection,
            proofs,
            pool,
            revocation_pool,
            environments: registry,
            ordinary: Arc::new(Semaphore::new(limits.ordinary as usize)),
            revocation: Arc::new(Semaphore::new(limits.revocation as usize)),
            snapshot: Arc::new(Semaphore::new(limits.snapshot as usize)),
            closed: AtomicBool::new(false),
        }))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
    pub fn selection(&self) -> Selection {
        self.selection
    }
    pub async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        tokio::join!(close_pool(&self.pool), close_pool(&self.revocation_pool));
    }
    pub(in crate::organizations) fn connection_pool(&self, class: CapacityClass) -> &PgPool {
        match class {
            CapacityClass::Revocation => &self.revocation_pool,
            CapacityClass::Ordinary | CapacityClass::Snapshot => &self.pool,
        }
    }
    pub(crate) fn ensure_open(&self) -> std::result::Result<(), sqlx::Error> {
        if self.closed.load(Ordering::SeqCst)
            || self.pool.is_closed()
            || self.revocation_pool.is_closed()
        {
            Err(sqlx::Error::PoolClosed)
        } else {
            Ok(())
        }
    }
    pub(crate) fn admit(
        self: &Arc<Self>,
        class: CapacityClass,
        environment: Option<Uuid>,
    ) -> Result<Admission> {
        self.ensure_open()?;
        if environment.is_some_and(|id| !self.environments.contains_key(&id)) {
            return Err(Error::Refused);
        }
        let limit = match class {
            CapacityClass::Ordinary => &self.ordinary,
            CapacityClass::Revocation => &self.revocation,
            CapacityClass::Snapshot => &self.snapshot,
        };
        Admission::for_runtime(self.clone(), limit, class, environment).map_err(|error| match error
        {
            sqlx::Error::PoolTimedOut => Error::CapacityExhausted,
            sqlx::Error::PoolClosed => Error::AdmissionClosed,
            other => Error::Storage(other),
        })
    }
    pub fn start<T, F, Fut>(
        self: &Arc<Self>,
        environment: Option<Uuid>,
        class: CapacityClass,
        operation: F,
    ) -> Result<Execution<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        let local = self.admit(class, environment)?;
        Ok(CurrentStart.dispatch(local, operation))
    }
}

pub(in crate::organizations) struct CurrentStart;
impl Starter for CurrentStart {
    fn start<T, F>(
        self,
        local: Admission,
        operation: F,
        deadline: tokio::time::Instant,
    ) -> Execution<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        Execution::from_worker(tokio::spawn(async move {
            tokio::time::timeout_at(deadline, async move {
                let result = local.store_scope(operation).await?;
                local.wait_for_exclusive_completion().await?;
                Ok(result)
            })
            .await
            .map_err(|_| Error::Deadline)?
        }))
    }
}
