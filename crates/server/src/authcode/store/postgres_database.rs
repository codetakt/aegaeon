use crate::config::RuntimeStateNamespace;
use sqlx::PgPool;
use std::sync::Arc;

/// Shared database and namespace for atomic PAR/code/grant publication.
///
/// Clone one instance into the participating stores. The private identity checks
/// that in-process commit inputs were prepared for that same configured database;
/// it is not persistent authority, a recovery counter, or a mutation journal.
#[derive(Clone)]
pub struct PostgresGrantDatabase {
    pub(crate) pool: PgPool,
    pub(crate) namespace: Arc<str>,
    identity: Arc<()>,
}

impl PostgresGrantDatabase {
    #[must_use]
    pub fn new(pool: PgPool, namespace: &RuntimeStateNamespace) -> Self {
        Self {
            pool,
            namespace: namespace.flow_namespace("oauth", "grant").into(),
            identity: Arc::new(()),
        }
    }

    /// Check local commit-context compatibility without consulting another store.
    #[must_use]
    pub fn same_database(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}

impl std::fmt::Debug for PostgresGrantDatabase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresGrantDatabase")
            .finish_non_exhaustive()
    }
}
