use std::collections::HashMap;
use std::sync::{RwLockReadGuard, RwLockWriteGuard};

use super::super::{
    ClientRegistry, ClientRegistryStateError, ClientSecretCredential, RegisteredClient,
};

impl ClientRegistry {
    pub(super) fn try_read_lock(
        &self,
    ) -> Result<RwLockReadGuard<'_, HashMap<String, RegisteredClient>>, ClientRegistryStateError>
    {
        self.clients.read().map_err(|err| {
            tracing::error!(error = %err, "client registry read lock poisoned");
            ClientRegistryStateError::LockPoisoned("clients read")
        })
    }

    pub(super) fn try_write_lock(
        &self,
    ) -> Result<RwLockWriteGuard<'_, HashMap<String, RegisteredClient>>, ClientRegistryStateError>
    {
        self.clients.write().map_err(|err| {
            tracing::error!(error = %err, "client registry write lock poisoned");
            ClientRegistryStateError::LockPoisoned("clients write")
        })
    }

    pub(super) fn try_read_client_secret_credentials(
        &self,
    ) -> Result<
        RwLockReadGuard<'_, HashMap<String, Vec<ClientSecretCredential>>>,
        ClientRegistryStateError,
    > {
        self.client_secret_credentials.read().map_err(|err| {
            tracing::error!(
                error = %err,
                "client registry secret-credential read lock poisoned"
            );
            ClientRegistryStateError::LockPoisoned("client secret credentials read")
        })
    }

    pub(super) fn try_write_client_secret_credentials(
        &self,
    ) -> Result<
        RwLockWriteGuard<'_, HashMap<String, Vec<ClientSecretCredential>>>,
        ClientRegistryStateError,
    > {
        self.client_secret_credentials.write().map_err(|err| {
            tracing::error!(
                error = %err,
                "client registry secret-credential write lock poisoned"
            );
            ClientRegistryStateError::LockPoisoned("client secret credentials write")
        })
    }

    pub(super) fn try_read_runtime_snapshot_fingerprint(
        &self,
    ) -> Result<RwLockReadGuard<'_, Option<String>>, ClientRegistryStateError> {
        self.runtime_snapshot_fingerprint.read().map_err(|err| {
            tracing::error!(
                error = %err,
                "client registry runtime snapshot fingerprint read lock poisoned"
            );
            ClientRegistryStateError::LockPoisoned("runtime snapshot fingerprint read")
        })
    }

    pub(super) fn try_write_runtime_snapshot_fingerprint(
        &self,
    ) -> Result<RwLockWriteGuard<'_, Option<String>>, ClientRegistryStateError> {
        self.runtime_snapshot_fingerprint.write().map_err(|err| {
            tracing::error!(
                error = %err,
                "client registry runtime snapshot fingerprint write lock poisoned"
            );
            ClientRegistryStateError::LockPoisoned("runtime snapshot fingerprint write")
        })
    }
}
