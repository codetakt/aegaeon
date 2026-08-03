#[cfg(test)]
use crate::client_registry::ClientSecretCredential;
use crate::metrics_integration::MetricsIntegration;
#[cfg(test)]
use crate::par::Client as ParClient;
use crate::par::{process_par_request, ParError, ParRequest, ParResponse, ParStore};
#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// PAR endpoint handler with metrics integration.
pub struct ParEndpoint {
    metrics: Arc<MetricsIntegration>,
    store: Arc<ParStore>,
}

impl ParEndpoint {
    pub fn new(metrics: Arc<MetricsIntegration>, store: Arc<ParStore>) -> Self {
        Self { metrics, store }
    }

    #[cfg(test)]
    pub fn register_client(&self, client: ParClient) {
        self.store.register_client(client);
    }

    #[cfg(test)]
    pub fn register_client_secret_credentials(
        &self,
        client_id: &str,
        credentials: Vec<ClientSecretCredential>,
    ) {
        self.store
            .register_client_secret_credentials(client_id, credentials);
    }

    #[cfg(test)]
    pub fn clear_client_secret_credentials(&self, client_id: &str) {
        self.store.clear_client_secret_credentials(client_id);
    }

    #[cfg(test)]
    pub fn replace_clients(
        &self,
        clients: HashMap<String, ParClient>,
        client_secret_credentials: HashMap<String, Vec<ClientSecretCredential>>,
    ) {
        self.store
            .replace_clients(clients, client_secret_credentials);
    }

    #[cfg(test)]
    pub fn deregister_client(&self, client_id: &str) {
        self.store.deregister_client(client_id);
    }

    #[must_use]
    pub fn store(&self) -> Arc<ParStore> {
        Arc::clone(&self.store)
    }

    /// Handle a pushed authorization request and record PAR metrics.
    ///
    /// # Errors
    ///
    /// Returns [`ParError`] when the incoming request fails PAR validation or storage.
    pub fn handle_par_request(&self, request: ParRequest) -> Result<ParResponse, ParError> {
        let start = Instant::now();
        let client_id = request.client_id.clone();
        let result = process_par_request(&self.store, request);
        let success = result.is_ok();

        self.metrics.record_par_request(&client_id, success);
        self.metrics
            .metrics
            .record_latency("/par", "POST", start.elapsed().as_secs_f64());

        result
    }
}
