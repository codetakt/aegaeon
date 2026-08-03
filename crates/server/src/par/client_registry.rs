use super::{
    try_write_lock, Client, ParRuntimeClientProjectionWriteGuard, ParStateError, ParStore,
};
use crate::client_registry::ClientSecretCredential;
use std::collections::HashMap;

impl ParStore {
    /// Register a client in the process-local runtime projection cache.
    pub(crate) fn try_register_client(&self, client: Client) -> Result<(), ParStateError> {
        self.try_runtime_client_projection_write()?
            .register_client(client);
        Ok(())
    }

    /// Register a client in the process-local runtime projection cache.
    #[cfg(test)]
    pub fn register_client(&self, client: Client) {
        if let Err(error) = self.try_register_client(client) {
            tracing::error!(%error, "PAR client registration failed");
        }
    }

    /// Register Argon2id secret credentials for a client whose plaintext secret is never stored.
    ///
    /// An empty vector is significant: it marks a DB-managed confidential client with no active
    /// secrets, preventing a fallback to public-client PAR semantics.
    #[cfg(test)]
    pub(crate) fn try_register_client_secret_credentials(
        &self,
        client_id: &str,
        credentials: Vec<ClientSecretCredential>,
    ) -> Result<(), ParStateError> {
        self.try_runtime_client_projection_write()?
            .register_client_secret_credentials(client_id, credentials);
        Ok(())
    }

    #[cfg(test)]
    pub fn register_client_secret_credentials(
        &self,
        client_id: &str,
        credentials: Vec<ClientSecretCredential>,
    ) {
        if let Err(error) = self.try_register_client_secret_credentials(client_id, credentials) {
            tracing::error!(%error, "PAR client secret credential registration failed");
        }
    }

    #[cfg(test)]
    pub(crate) fn try_clear_client_secret_credentials(
        &self,
        client_id: &str,
    ) -> Result<(), ParStateError> {
        self.try_runtime_client_projection_write()?
            .clear_client_secret_credentials(client_id);
        Ok(())
    }

    #[cfg(test)]
    pub fn clear_client_secret_credentials(&self, client_id: &str) {
        if let Err(error) = self.try_clear_client_secret_credentials(client_id) {
            tracing::error!(%error, "PAR client secret credential removal failed");
        }
    }

    #[cfg(test)]
    pub(crate) fn try_replace_clients(
        &self,
        clients: HashMap<String, Client>,
        client_secret_credentials: HashMap<String, Vec<ClientSecretCredential>>,
    ) -> Result<(), ParStateError> {
        self.try_runtime_client_projection_write()?
            .replace_clients(clients, client_secret_credentials);
        Ok(())
    }

    #[cfg(test)]
    pub fn replace_clients(
        &self,
        clients: HashMap<String, Client>,
        client_secret_credentials: HashMap<String, Vec<ClientSecretCredential>>,
    ) {
        if let Err(error) = self.try_replace_clients(clients, client_secret_credentials) {
            tracing::error!(%error, "PAR client registry replacement failed");
        }
    }

    /// Remove a client from the process-local runtime projection cache (RFC 7592 §2.3).
    #[cfg(test)]
    pub(crate) fn try_deregister_client(&self, client_id: &str) -> Result<(), ParStateError> {
        self.try_runtime_client_projection_write()?
            .deregister_client(client_id);
        Ok(())
    }

    /// Remove a client from the process-local runtime projection cache (RFC 7592 §2.3).
    #[cfg(test)]
    pub fn deregister_client(&self, client_id: &str) {
        if let Err(error) = self.try_deregister_client(client_id) {
            tracing::error!(%error, "PAR client deregistration failed");
        }
    }

    pub(crate) fn try_runtime_client_projection_write(
        &self,
    ) -> Result<ParRuntimeClientProjectionWriteGuard<'_>, ParStateError> {
        Ok(ParRuntimeClientProjectionWriteGuard {
            clients: try_write_lock(&self.clients, "clients write")?,
            client_secret_credentials: try_write_lock(
                &self.client_secret_credentials,
                "client secret credentials write",
            )?,
        })
    }
}

impl ParRuntimeClientProjectionWriteGuard<'_> {
    pub(crate) fn register_client(&mut self, client: Client) {
        self.clients.insert(client.client_id.clone(), client);
    }

    #[cfg(test)]
    pub(crate) fn register_client_secret_credentials(
        &mut self,
        client_id: &str,
        credentials: Vec<ClientSecretCredential>,
    ) {
        self.client_secret_credentials
            .insert(client_id.to_string(), credentials);
    }

    #[cfg(test)]
    pub(crate) fn clear_client_secret_credentials(&mut self, client_id: &str) {
        self.client_secret_credentials.remove(client_id);
    }

    pub(crate) fn replace_clients(
        &mut self,
        clients: HashMap<String, Client>,
        mut client_secret_credentials: HashMap<String, Vec<ClientSecretCredential>>,
    ) {
        client_secret_credentials.retain(|client_id, _| clients.contains_key(client_id));
        *self.clients = clients;
        *self.client_secret_credentials = client_secret_credentials;
    }

    #[cfg(test)]
    pub(crate) fn deregister_client(&mut self, client_id: &str) {
        self.clients.remove(client_id);
        self.client_secret_credentials.remove(client_id);
    }
}
