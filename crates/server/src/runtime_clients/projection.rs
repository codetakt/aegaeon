use std::collections::HashMap;

use crate::client_registry::{
    ClientRegistryRuntimeProjectionWriteGuard, ClientSecretCredential, RegisteredClient,
};
use crate::runtime_configuration::RuntimeAuthorityRevision;

use super::snapshot::RuntimeClientSnapshot;

#[cfg(test)]
use super::error::RuntimeClientSnapshotError;

pub(crate) struct RuntimeClientProjectionCommit {
    pub(super) registry_clients: HashMap<String, RegisteredClient>,
    pub(super) registry_credentials: HashMap<String, Vec<ClientSecretCredential>>,
    pub(super) fingerprint: String,
    pub(super) len: usize,
}

pub struct RuntimeClientProjectionUpdate {
    snapshot: RuntimeClientSnapshot,
    authority_revision: RuntimeAuthorityRevision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeClientSynchronization {
    synchronized_client_count: usize,
    authority_revision: RuntimeAuthorityRevision,
}

impl RuntimeClientSynchronization {
    #[must_use]
    pub(crate) fn new(
        synchronized_client_count: usize,
        authority_revision: RuntimeAuthorityRevision,
    ) -> Self {
        Self {
            synchronized_client_count,
            authority_revision,
        }
    }

    #[must_use]
    pub fn synchronized_client_count(&self) -> usize {
        self.synchronized_client_count
    }

    #[must_use]
    pub fn authority_revision(&self) -> &RuntimeAuthorityRevision {
        &self.authority_revision
    }

    #[must_use]
    pub fn into_authority_revision(self) -> RuntimeAuthorityRevision {
        self.authority_revision
    }
}

impl RuntimeClientProjectionUpdate {
    pub(super) fn new(
        snapshot: RuntimeClientSnapshot,
        authority_revision: RuntimeAuthorityRevision,
    ) -> Self {
        Self {
            snapshot,
            authority_revision,
        }
    }

    #[must_use]
    pub fn synchronized_client_count(&self) -> usize {
        self.snapshot.len()
    }

    #[must_use]
    pub fn authority_revision(&self) -> &RuntimeAuthorityRevision {
        &self.authority_revision
    }

    pub(crate) fn into_commit(self) -> RuntimeClientProjectionCommit {
        self.snapshot.into_projection_commit()
    }
}

impl RuntimeClientProjectionCommit {
    #[cfg(test)]
    pub(crate) fn try_commit(
        self,
        clients: &crate::client_registry::ClientRegistry,
    ) -> Result<usize, RuntimeClientSnapshotError> {
        let mut registry_projection = clients.try_runtime_projection_write()?;
        Ok(self.commit_to(&mut registry_projection))
    }

    pub(crate) fn commit_to(
        self,
        registry_projection: &mut ClientRegistryRuntimeProjectionWriteGuard<'_>,
    ) -> usize {
        let len = self.len;
        registry_projection.replace_all(
            self.registry_clients,
            self.registry_credentials,
            Some(self.fingerprint),
        );
        len
    }

    #[cfg(test)]
    pub(crate) fn empty_for_tests(fingerprint: impl Into<String>) -> Self {
        Self {
            registry_clients: HashMap::new(),
            registry_credentials: HashMap::new(),
            fingerprint: fingerprint.into(),
            len: 0,
        }
    }
}
