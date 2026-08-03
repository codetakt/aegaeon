mod authentication;
mod state;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::jwks_runtime_state::JwksRuntimeState;
#[cfg(test)]
use super::log_client_registry_state_error;
use super::{
    select_registration_token_match, ClientAssertionRuntimePolicy, ClientRegistry,
    ClientRegistryClientProjectionWriteGuard, ClientRegistryRuntimeProjectionWriteGuard,
    ClientRegistryStateError, ClientSecretCredential, JwksRuntimePolicy, RegisteredClient,
};
use crate::middleware::ReplayStore;

impl ClientRegistry {
    #[cfg(test)]
    pub(super) fn with_replay_store_and_policy(
        jwt_replay_store: Arc<dyn ReplayStore>,
        client_assertion_policy: ClientAssertionRuntimePolicy,
        jwks_policy: JwksRuntimePolicy,
    ) -> Self {
        Self::with_replay_store_policy_and_jwks_state(
            jwt_replay_store,
            client_assertion_policy,
            jwks_policy,
            JwksRuntimeState::default(),
        )
    }

    pub(super) fn with_replay_store_policy_and_jwks_state(
        jwt_replay_store: Arc<dyn ReplayStore>,
        client_assertion_policy: ClientAssertionRuntimePolicy,
        jwks_policy: JwksRuntimePolicy,
        jwks_state: JwksRuntimeState,
    ) -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            client_secret_credentials: Arc::new(RwLock::new(HashMap::new())),
            runtime_snapshot_fingerprint: Arc::new(RwLock::new(None)),
            jwt_replay_store,
            client_assertion_policy,
            jwks_policy,
            jwks_state,
        }
    }

    #[cfg(test)]
    pub fn try_register(&self, client: RegisteredClient) -> Result<bool, ClientRegistryStateError> {
        let mut map = self.try_write_lock()?;
        map.insert(client.client_id.clone(), client);
        Ok(true)
    }

    #[cfg(test)]
    pub fn register(&self, client: RegisteredClient) -> bool {
        self.try_register(client).unwrap_or_else(|error| {
            log_client_registry_state_error("register", &error);
            false
        })
    }

    #[cfg(test)]
    pub fn try_register_client_secret_credentials(
        &self,
        client_id: &str,
        credentials: Vec<ClientSecretCredential>,
    ) -> Result<(), ClientRegistryStateError> {
        let mut map = self.try_write_client_secret_credentials()?;
        map.insert(client_id.to_string(), credentials);
        Ok(())
    }

    #[cfg(test)]
    pub fn register_client_secret_credentials(
        &self,
        client_id: &str,
        credentials: Vec<ClientSecretCredential>,
    ) {
        if let Err(error) = self.try_register_client_secret_credentials(client_id, credentials) {
            log_client_registry_state_error("register_client_secret_credentials", &error);
        }
    }

    #[cfg(test)]
    pub fn try_clear_client_secret_credentials(
        &self,
        client_id: &str,
    ) -> Result<(), ClientRegistryStateError> {
        let mut map = self.try_write_client_secret_credentials()?;
        map.remove(client_id);
        Ok(())
    }

    #[cfg(test)]
    pub fn clear_client_secret_credentials(&self, client_id: &str) {
        if let Err(error) = self.try_clear_client_secret_credentials(client_id) {
            log_client_registry_state_error("clear_client_secret_credentials", &error);
        }
    }

    #[cfg(test)]
    pub fn try_replace_all_clients(
        &self,
        clients: HashMap<String, RegisteredClient>,
        client_secret_credentials: HashMap<String, Vec<ClientSecretCredential>>,
    ) -> Result<(), ClientRegistryStateError> {
        self.try_replace_all_clients_with_fingerprint(clients, client_secret_credentials, None)
    }

    #[cfg(test)]
    pub fn replace_all_clients(
        &self,
        clients: HashMap<String, RegisteredClient>,
        client_secret_credentials: HashMap<String, Vec<ClientSecretCredential>>,
    ) {
        if let Err(error) = self.try_replace_all_clients(clients, client_secret_credentials) {
            log_client_registry_state_error("replace_all_clients", &error);
        }
    }

    #[cfg(test)]
    pub fn try_replace_all_clients_with_fingerprint(
        &self,
        clients: HashMap<String, RegisteredClient>,
        client_secret_credentials: HashMap<String, Vec<ClientSecretCredential>>,
        runtime_snapshot_fingerprint: Option<String>,
    ) -> Result<(), ClientRegistryStateError> {
        self.try_runtime_projection_write()?.replace_all(
            clients,
            client_secret_credentials,
            runtime_snapshot_fingerprint,
        );
        Ok(())
    }

    #[cfg(test)]
    pub fn replace_all_clients_with_fingerprint(
        &self,
        clients: HashMap<String, RegisteredClient>,
        client_secret_credentials: HashMap<String, Vec<ClientSecretCredential>>,
        runtime_snapshot_fingerprint: Option<String>,
    ) {
        if let Err(error) = self.try_replace_all_clients_with_fingerprint(
            clients,
            client_secret_credentials,
            runtime_snapshot_fingerprint,
        ) {
            log_client_registry_state_error("replace_all_clients_with_fingerprint", &error);
        }
    }

    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_runtime_snapshot_fingerprint(
        &self,
    ) -> Result<Option<String>, ClientRegistryStateError> {
        Ok(self.try_read_runtime_snapshot_fingerprint()?.clone())
    }

    #[must_use]
    #[cfg(test)]
    pub fn runtime_snapshot_fingerprint(&self) -> Option<String> {
        self.try_runtime_snapshot_fingerprint()
            .unwrap_or_else(|error| {
                log_client_registry_state_error("runtime_snapshot_fingerprint", &error);
                None
            })
    }

    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_get(
        &self,
        client_id: &str,
    ) -> Result<Option<RegisteredClient>, ClientRegistryStateError> {
        Ok(self.try_read_lock()?.get(client_id).cloned())
    }

    #[must_use]
    #[cfg(test)]
    pub fn get(&self, client_id: &str) -> Option<RegisteredClient> {
        self.try_get(client_id).unwrap_or_else(|error| {
            log_client_registry_state_error("get", &error);
            None
        })
    }

    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_client_secret_credentials(
        &self,
        client_id: &str,
    ) -> Result<Vec<ClientSecretCredential>, ClientRegistryStateError> {
        let credentials = self.try_read_client_secret_credentials()?;
        Ok(match credentials.get(client_id) {
            Some(credentials) => credentials.clone(),
            None => Vec::new(),
        })
    }

    pub(crate) fn try_get_with_client_secret_credentials(
        &self,
        client_id: &str,
    ) -> Result<Option<(RegisteredClient, Vec<ClientSecretCredential>)>, ClientRegistryStateError>
    {
        let clients = self.try_read_lock()?;
        let credentials = self.try_read_client_secret_credentials()?;
        Ok(clients.get(client_id).cloned().map(|client| {
            let credentials = credentials.get(client_id).cloned().unwrap_or_else(Vec::new);
            (client, credentials)
        }))
    }

    #[must_use]
    #[cfg(test)]
    pub fn client_secret_credentials(&self, client_id: &str) -> Vec<ClientSecretCredential> {
        self.try_client_secret_credentials(client_id)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("client_secret_credentials", &error);
                Vec::new()
            })
    }

    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_validate_redirect_uri(
        &self,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<bool, ClientRegistryStateError> {
        Ok(self.try_get(client_id)?.is_some_and(|c| {
            c.redirect_uris
                .iter()
                .any(|registered| registered == redirect_uri)
        }))
    }

    #[must_use]
    #[cfg(test)]
    pub fn validate_redirect_uri(&self, client_id: &str, redirect_uri: &str) -> bool {
        self.try_validate_redirect_uri(client_id, redirect_uri)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("validate_redirect_uri", &error);
                false
            })
    }

    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_validate_post_logout_redirect_uri(
        &self,
        client_id: &str,
        post_logout_redirect_uri: &str,
    ) -> Result<bool, ClientRegistryStateError> {
        Ok(self.try_get(client_id)?.is_some_and(|c| {
            c.post_logout_redirect_uris
                .iter()
                .any(|u| u == post_logout_redirect_uri)
        }))
    }

    #[must_use]
    #[cfg(test)]
    pub fn validate_post_logout_redirect_uri(
        &self,
        client_id: &str,
        post_logout_redirect_uri: &str,
    ) -> bool {
        self.try_validate_post_logout_redirect_uri(client_id, post_logout_redirect_uri)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("validate_post_logout_redirect_uri", &error);
                false
            })
    }

    pub fn try_is_registered_client(
        &self,
        client_id: &str,
    ) -> Result<bool, ClientRegistryStateError> {
        Ok(self.try_get(client_id)?.is_some())
    }

    #[must_use]
    #[cfg(test)]
    pub fn is_registered_client(&self, client_id: &str) -> bool {
        self.try_is_registered_client(client_id)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("is_registered_client", &error);
                false
            })
    }

    /// Update an existing client's metadata (RFC 7592 §2.2).
    /// Returns `true` if the client was found and updated, `false` otherwise.
    #[cfg(test)]
    pub fn try_update(&self, client: RegisteredClient) -> Result<bool, ClientRegistryStateError> {
        let mut map = self.try_write_lock()?;
        Ok(if map.contains_key(&client.client_id) {
            map.insert(client.client_id.clone(), client);
            true
        } else {
            false
        })
    }

    #[must_use]
    #[cfg(test)]
    pub fn update(&self, client: RegisteredClient) -> bool {
        self.try_update(client).unwrap_or_else(|error| {
            log_client_registry_state_error("update", &error);
            false
        })
    }

    /// Remove a client from the registry (RFC 7592 §2.3).
    /// Returns `true` if the client was found and removed, `false` otherwise.
    #[cfg(test)]
    pub fn try_delete(&self, client_id: &str) -> Result<bool, ClientRegistryStateError> {
        Ok(self.try_client_projection_write()?.delete(client_id))
    }

    #[must_use]
    #[cfg(test)]
    pub fn delete(&self, client_id: &str) -> bool {
        self.try_delete(client_id).unwrap_or_else(|error| {
            log_client_registry_state_error("delete", &error);
            false
        })
    }

    /// Look up a client by its RFC 7592 `registration_access_token` using constant-time comparison.
    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_get_by_registration_token(
        &self,
        token: &str,
    ) -> Result<Option<RegisteredClient>, ClientRegistryStateError> {
        let map = self.try_read_lock()?;
        Ok(select_registration_token_match(map.values(), token))
    }

    #[must_use]
    #[cfg(test)]
    pub fn get_by_registration_token(&self, token: &str) -> Option<RegisteredClient> {
        self.try_get_by_registration_token(token)
            .unwrap_or_else(|error| {
                log_client_registry_state_error("get_by_registration_token", &error);
                None
            })
    }

    #[must_use = "handle the registry result to preserve backend failures"]
    pub fn try_all_clients(&self) -> Result<Vec<RegisteredClient>, ClientRegistryStateError> {
        Ok(self.try_read_lock()?.values().cloned().collect())
    }

    #[must_use]
    #[cfg(test)]
    pub fn all_clients(&self) -> Vec<RegisteredClient> {
        self.try_all_clients().unwrap_or_else(|error| {
            log_client_registry_state_error("all_clients", &error);
            Vec::new()
        })
    }
}

impl ClientRegistry {
    pub(crate) fn try_client_projection_write(
        &self,
    ) -> Result<ClientRegistryClientProjectionWriteGuard<'_>, ClientRegistryStateError> {
        Ok(ClientRegistryClientProjectionWriteGuard {
            clients: self.try_write_lock()?,
            client_secret_credentials: self.try_write_client_secret_credentials()?,
        })
    }

    pub(crate) fn try_runtime_projection_write(
        &self,
    ) -> Result<ClientRegistryRuntimeProjectionWriteGuard<'_>, ClientRegistryStateError> {
        Ok(ClientRegistryRuntimeProjectionWriteGuard {
            client_projection: self.try_client_projection_write()?,
            runtime_snapshot_fingerprint: self.try_write_runtime_snapshot_fingerprint()?,
        })
    }
}

impl ClientRegistryClientProjectionWriteGuard<'_> {
    pub(crate) fn replace_all(
        &mut self,
        clients: HashMap<String, RegisteredClient>,
        mut client_secret_credentials: HashMap<String, Vec<ClientSecretCredential>>,
    ) {
        client_secret_credentials.retain(|client_id, _| clients.contains_key(client_id));
        *self.clients = clients;
        *self.client_secret_credentials = client_secret_credentials;
    }

    #[cfg(test)]
    pub(crate) fn register_with_client_secret_credentials(
        &mut self,
        client: RegisteredClient,
        client_secret_credentials: Option<Vec<ClientSecretCredential>>,
    ) {
        let client_id = client.client_id.clone();
        match client_secret_credentials {
            Some(credentials) => {
                self.client_secret_credentials
                    .insert(client_id.clone(), credentials);
            }
            None => {
                self.client_secret_credentials.remove(&client_id);
            }
        }
        self.clients.insert(client_id, client);
    }

    #[cfg(test)]
    pub(crate) fn delete(&mut self, client_id: &str) -> bool {
        let removed = self.clients.remove(client_id).is_some();
        if removed {
            self.client_secret_credentials.remove(client_id);
        }
        removed
    }
}

impl ClientRegistryRuntimeProjectionWriteGuard<'_> {
    pub(crate) fn replace_all(
        &mut self,
        clients: HashMap<String, RegisteredClient>,
        client_secret_credentials: HashMap<String, Vec<ClientSecretCredential>>,
        runtime_snapshot_fingerprint: Option<String>,
    ) {
        self.client_projection
            .replace_all(clients, client_secret_credentials);
        *self.runtime_snapshot_fingerprint = runtime_snapshot_fingerprint;
    }
}
