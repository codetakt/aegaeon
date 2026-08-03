use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use thiserror::Error;

use crate::client_registry::ClientRegistry;
use crate::runtime_clients::{
    self, RuntimeClientProjectionCommit, RuntimeClientSnapshotError, RuntimeClientSynchronization,
};
use crate::runtime_configuration::RuntimeAuthorityRevision;

#[derive(Clone)]
pub struct RuntimeAuthorityState {
    issuer_host: Arc<String>,
    revision: Arc<RwLock<RuntimeAuthorityRevision>>,
    admission_revalidation: RuntimeAuthorityAdmissionRevalidation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeAuthorityAdmissionRevalidation {
    Database,
    #[cfg(test)]
    TestOnly,
}

impl RuntimeAuthorityState {
    #[must_use]
    pub fn from_database_revision(
        issuer_host: Arc<String>,
        revision: RuntimeAuthorityRevision,
    ) -> Self {
        Self {
            issuer_host,
            revision: Arc::new(RwLock::new(revision)),
            admission_revalidation: RuntimeAuthorityAdmissionRevalidation::Database,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests(issuer_host: impl Into<String>) -> Self {
        Self {
            issuer_host: Arc::new(issuer_host.into()),
            revision: Arc::new(RwLock::new(
                RuntimeAuthorityRevision::new_unchecked_for_tests(
                    uuid::Uuid::nil(),
                    "test-only-configuration".to_string(),
                    "test-only-key-set".to_string(),
                    "test-only-clients".to_string(),
                    "test-only-dcr-token".to_string(),
                ),
            )),
            admission_revalidation: RuntimeAuthorityAdmissionRevalidation::TestOnly,
        }
    }

    #[must_use]
    pub fn issuer_host(&self) -> &str {
        self.issuer_host.as_str()
    }

    pub fn revision(&self) -> Result<RuntimeAuthorityRevision, RuntimeAuthorityStateError> {
        self.revision
            .read()
            .map(|revision| revision.clone())
            .map_err(|_| RuntimeAuthorityStateError::RevisionLockPoisoned)
    }

    pub fn try_advance_client_projection_revision_from(
        &self,
        expected: &RuntimeAuthorityRevision,
        revision: RuntimeAuthorityRevision,
    ) -> Result<(), RuntimeAuthorityStateError> {
        let mut loaded = self
            .revision
            .write()
            .map_err(|_| RuntimeAuthorityStateError::RevisionLockPoisoned)?;
        if !expected.stable_authority_matches(&revision)
            || !loaded.stable_authority_matches(&revision)
        {
            return Err(RuntimeAuthorityStateError::StableAuthorityChanged);
        }
        if *loaded == revision {
            return Ok(());
        }
        if *loaded != *expected {
            return Err(RuntimeAuthorityStateError::StaleClientProjectionUpdate);
        }
        *loaded = revision;
        Ok(())
    }

    pub async fn try_synchronize_client_projection_from_database(
        &self,
        pool: &PgPool,
        clients: &ClientRegistry,
    ) -> Result<RuntimeClientSynchronization, RuntimeClientProjectionSyncError> {
        let expected_revision = self.revision()?;
        self.try_synchronize_client_projection_from_database_from(pool, &expected_revision, clients)
            .await
    }

    pub async fn try_synchronize_client_projection_from_database_from(
        &self,
        pool: &PgPool,
        expected_revision: &RuntimeAuthorityRevision,
        clients: &ClientRegistry,
    ) -> Result<RuntimeClientSynchronization, RuntimeClientProjectionSyncError> {
        let projection = runtime_clients::load_runtime_client_projection_from_database_guarded(
            pool,
            self.issuer_host(),
            expected_revision,
        )
        .await?;
        let synchronized_client_count = projection.synchronized_client_count();
        let authority_revision = projection.authority_revision().clone();
        let commit = projection.into_commit();
        self.try_replace_client_projection_from(
            expected_revision,
            authority_revision.clone(),
            clients,
            commit,
        )?;
        Ok(RuntimeClientSynchronization::new(
            synchronized_client_count,
            authority_revision,
        ))
    }

    pub(crate) fn try_replace_client_projection_from(
        &self,
        expected: &RuntimeAuthorityRevision,
        revision: RuntimeAuthorityRevision,
        clients: &ClientRegistry,
        projection: RuntimeClientProjectionCommit,
    ) -> Result<(), RuntimeClientProjectionSyncError> {
        let mut registry_projection = clients
            .try_runtime_projection_write()
            .map_err(RuntimeClientSnapshotError::from)?;
        let mut loaded = self
            .revision
            .write()
            .map_err(|_| RuntimeAuthorityStateError::RevisionLockPoisoned)?;
        if !expected.stable_authority_matches(&revision)
            || !loaded.stable_authority_matches(&revision)
        {
            return Err(RuntimeAuthorityStateError::StableAuthorityChanged.into());
        }
        if *loaded == revision {
            projection.commit_to(&mut registry_projection);
            return Ok(());
        }
        if *loaded != *expected {
            return Err(RuntimeAuthorityStateError::StaleClientProjectionUpdate.into());
        }
        projection.commit_to(&mut registry_projection);
        *loaded = revision;
        Ok(())
    }

    #[must_use]
    pub fn requires_runtime_request_admission(&self) -> bool {
        matches!(
            self.admission_revalidation,
            RuntimeAuthorityAdmissionRevalidation::Database
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAuthorityStateError {
    RevisionLockPoisoned,
    StableAuthorityChanged,
    StaleClientProjectionUpdate,
}

impl std::fmt::Display for RuntimeAuthorityStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RevisionLockPoisoned => write!(f, "runtime authority revision lock poisoned"),
            Self::StableAuthorityChanged => {
                write!(f, "runtime stable authority revision changed")
            }
            Self::StaleClientProjectionUpdate => {
                write!(f, "runtime client projection revision update is stale")
            }
        }
    }
}

impl std::error::Error for RuntimeAuthorityStateError {}

#[derive(Debug, Error)]
pub enum RuntimeClientProjectionSyncError {
    #[error("runtime authority state unavailable: {0}")]
    AuthorityState(#[from] RuntimeAuthorityStateError),

    #[error("runtime client projection unavailable: {0}")]
    RuntimeClients(#[from] RuntimeClientSnapshotError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revision(
        configuration: u128,
        key: &str,
        client: &str,
        dcr: &str,
    ) -> RuntimeAuthorityRevision {
        RuntimeAuthorityRevision::new_unchecked_for_tests(
            uuid::Uuid::from_u128(configuration),
            format!("configuration-{configuration}"),
            key.to_string(),
            client.to_string(),
            dcr.to_string(),
        )
    }

    #[test]
    fn runtime_authority_allows_client_projection_advance_only() -> Result<(), String> {
        let state = RuntimeAuthorityState::from_database_revision(
            Arc::new("auth.example.com".to_string()),
            revision(1, "keys-a", "clients-a", "dcr-a"),
        );

        state
            .try_advance_client_projection_revision_from(
                &revision(1, "keys-a", "clients-a", "dcr-a"),
                revision(1, "keys-a", "clients-b", "dcr-a"),
            )
            .map_err(|err| err.to_string())?;
        assert_eq!(
            state
                .revision()
                .map_err(|err| err.to_string())?
                .active_runtime_client_fingerprint(),
            "clients-b"
        );

        assert_eq!(
            state.try_advance_client_projection_revision_from(
                &revision(1, "keys-a", "clients-b", "dcr-a"),
                revision(1, "keys-b", "clients-c", "dcr-a"),
            ),
            Err(RuntimeAuthorityStateError::StableAuthorityChanged)
        );
        assert_eq!(
            state
                .revision()
                .map_err(|err| err.to_string())?
                .active_runtime_key_set_fingerprint(),
            "keys-a"
        );
        Ok(())
    }

    #[test]
    fn runtime_authority_rejects_stale_client_projection_updates() -> Result<(), String> {
        let state = RuntimeAuthorityState::from_database_revision(
            Arc::new("auth.example.com".to_string()),
            revision(1, "keys-a", "clients-current", "dcr-a"),
        );

        assert_eq!(
            state.try_advance_client_projection_revision_from(
                &revision(1, "keys-a", "clients-old", "dcr-a"),
                revision(1, "keys-a", "clients-next", "dcr-a"),
            ),
            Err(RuntimeAuthorityStateError::StaleClientProjectionUpdate)
        );
        assert_eq!(
            state
                .revision()
                .map_err(|err| err.to_string())?
                .active_runtime_client_fingerprint(),
            "clients-current"
        );

        state
            .try_advance_client_projection_revision_from(
                &revision(1, "keys-a", "clients-old", "dcr-a"),
                revision(1, "keys-a", "clients-current", "dcr-a"),
            )
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    #[test]
    fn runtime_authority_replaces_projection_inside_cas_boundary() -> Result<(), String> {
        let state = RuntimeAuthorityState::from_database_revision(
            Arc::new("auth.example.com".to_string()),
            revision(1, "keys-a", "clients-a", "dcr-a"),
        );
        let clients = ClientRegistry::new_process_local_for_tests();
        state
            .try_replace_client_projection_from(
                &revision(1, "keys-a", "clients-a", "dcr-a"),
                revision(1, "keys-a", "clients-b", "dcr-a"),
                &clients,
                RuntimeClientProjectionCommit::empty_for_tests("clients-b"),
            )
            .map_err(|err| err.to_string())?;
        assert_eq!(
            clients.runtime_snapshot_fingerprint().as_deref(),
            Some("clients-b")
        );
        assert_eq!(
            state
                .revision()
                .map_err(|err| err.to_string())?
                .active_runtime_client_fingerprint(),
            "clients-b"
        );

        assert!(matches!(
            state.try_replace_client_projection_from(
                &revision(1, "keys-a", "clients-a", "dcr-a"),
                revision(1, "keys-a", "clients-c", "dcr-a"),
                &clients,
                RuntimeClientProjectionCommit::empty_for_tests("clients-c"),
            ),
            Err(RuntimeClientProjectionSyncError::AuthorityState(
                RuntimeAuthorityStateError::StaleClientProjectionUpdate
            ))
        ));
        assert_eq!(
            clients.runtime_snapshot_fingerprint().as_deref(),
            Some("clients-b")
        );
        assert_eq!(
            state
                .revision()
                .map_err(|err| err.to_string())?
                .active_runtime_client_fingerprint(),
            "clients-b"
        );
        Ok(())
    }

    #[test]
    fn runtime_authority_commits_projection_even_when_revision_is_already_current(
    ) -> Result<(), String> {
        let state = RuntimeAuthorityState::from_database_revision(
            Arc::new("auth.example.com".to_string()),
            revision(1, "keys-a", "clients-a", "dcr-a"),
        );
        let clients = ClientRegistry::new_process_local_for_tests();

        state
            .try_replace_client_projection_from(
                &revision(1, "keys-a", "clients-a", "dcr-a"),
                revision(1, "keys-a", "clients-a", "dcr-a"),
                &clients,
                RuntimeClientProjectionCommit::empty_for_tests("clients-a"),
            )
            .map_err(|err| err.to_string())?;

        assert_eq!(
            clients.runtime_snapshot_fingerprint().as_deref(),
            Some("clients-a"),
            "initial database-backed runtime client projection must be committed even when the DB revision already matches the loaded authority revision"
        );
        assert_eq!(
            state
                .revision()
                .map_err(|err| err.to_string())?
                .active_runtime_client_fingerprint(),
            "clients-a"
        );
        Ok(())
    }
}
