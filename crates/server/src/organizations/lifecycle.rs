//! Current database selection and connection-lifetime fencing, not request history.
//!
//! Restore isolation is an operator prerequisite: old workers must not reach the
//! restored database before activation. A same-database generation switch waits
//! for every admitted SQL session to end; reconnects check the selected generation.
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgConnection, PgPool,
};
use std::time::Duration;
use uuid::Uuid;

const LOCK_DOMAIN: i32 = 1_095_189_836;
const LOCK_KEY: i32 = 1;
const BIND_TIMEOUT: Duration = Duration::from_secs(5);

pub mod configuration;
pub(crate) mod maintenance;
pub(crate) mod proofs;
pub(in crate::organizations) mod runtime;
pub use runtime::{Limits, Runtime};

/// Protected operator input, compared with the selected durable row. Constructing
/// this value alone does not authorize requests or establish database currentness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    deployment: Uuid,
    generation: Uuid,
}

impl Selection {
    pub fn new(deployment: Uuid, generation: Uuid) -> Result<Self, sqlx::Error> {
        if deployment.is_nil() || generation.is_nil() {
            return Err(refused());
        }
        Ok(Self {
            deployment,
            generation,
        })
    }

    pub fn deployment_id(self) -> Uuid {
        self.deployment
    }
    pub fn generation(self) -> Uuid {
        self.generation
    }

    pub fn namespace(
        self,
        environment: Uuid,
    ) -> Result<crate::config::RuntimeStateNamespace, sqlx::Error> {
        if environment.is_nil() {
            return Err(refused());
        }
        Ok(crate::config::RuntimeStateNamespace::from_generation(
            environment,
            self.generation,
        ))
    }

    /// SQLx runs this hook on every new/replacement physical connection, before
    /// making it available. Failure/cancellation drops that connection and its
    /// session lock. Ordinary checkout and SQL transactions do not change the lock.
    /// Transaction-multiplexing proxies and DISCARD ALL are unsupported.
    pub fn pool(self, options: PgPoolOptions, endpoint: PgConnectOptions) -> PgPool {
        options
            .after_connect(move |connection, _| {
                Box::pin(async move {
                    tokio::time::timeout(BIND_TIMEOUT, self.bind(connection))
                        .await
                        .map_err(|_| sqlx::Error::PoolTimedOut)?
                })
            })
            .connect_lazy_with(endpoint)
    }

    async fn bind(self, connection: &mut PgConnection) -> Result<(), sqlx::Error> {
        let locked: bool =
            sqlx::query_scalar("SELECT pg_catalog.pg_try_advisory_lock_shared($1,$2)")
                .bind(LOCK_DOMAIN)
                .bind(LOCK_KEY)
                .fetch_one(&mut *connection)
                .await?;
        if !locked {
            return Err(refused());
        }
        // A separate statement gives a new READ COMMITTED snapshot after lock
        // acquisition. A pre-lock snapshot could observe the previous selection.
        let selected: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM aegaeon_lifecycle.current WHERE singleton AND deployment_id=$1 AND generation=$2) AND NOT pg_catalog.pg_is_in_recovery() AND NOT pg_catalog.has_table_privilege(current_user,'aegaeon_lifecycle.current','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AND NOT pg_catalog.has_any_column_privilege(current_user,'aegaeon_lifecycle.current','INSERT,UPDATE,REFERENCES') AND NOT pg_catalog.has_function_privilege(current_user,'aegaeon_lifecycle.activate_v1(uuid,uuid,uuid,uuid,jsonb)','EXECUTE')"
        ).bind(self.deployment).bind(self.generation).fetch_one(connection).await?;
        if !selected {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> sqlx::Error {
    sqlx::Error::Protocol("runtime lifecycle selection refused".into())
}

/// Drain a lifecycle pool after its owners have released their connections.
///
/// SQLx 0.8.6 can finish its close loop when a concurrent return publishes the
/// final idle connection. The first pass waits for all permits; the second drains
/// those late returns with new acquisitions already disabled. Callers retain
/// their shutdown deadline; database activation still checks actual session locks.
pub async fn close_pool(pool: &PgPool) {
    pool.close().await;
    pool.close().await;
}

#[cfg(test)]
mod tests;
