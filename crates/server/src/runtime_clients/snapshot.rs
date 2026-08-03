use std::collections::{HashMap, HashSet};

use crate::client_registry::{ClientSecretCredential, RegisteredClient};

use super::error::RuntimeClientSnapshotError;
use super::projection::RuntimeClientProjectionCommit;

#[derive(Clone, Debug)]
pub(super) struct RuntimeClientSnapshotEntry {
    pub(super) client: RegisteredClient,
    pub(super) client_secret_credentials: Vec<ClientSecretCredential>,
}

#[derive(Clone, Debug)]
pub(super) struct RuntimeClientSnapshot {
    entries: Vec<RuntimeClientSnapshotEntry>,
    fingerprint: String,
}

impl RuntimeClientSnapshot {
    #[cfg(test)]
    pub(super) fn try_new(
        entries: Vec<RuntimeClientSnapshotEntry>,
    ) -> Result<Self, RuntimeClientSnapshotError> {
        let fingerprint = runtime_client_entries_fingerprint(&entries);
        Self::try_new_with_fingerprint(entries, fingerprint)
    }

    pub(super) fn try_new_with_fingerprint(
        entries: Vec<RuntimeClientSnapshotEntry>,
        fingerprint: String,
    ) -> Result<Self, RuntimeClientSnapshotError> {
        if let Some(client_id) = duplicate_runtime_client_identifier(&entries) {
            return Err(RuntimeClientSnapshotError::DuplicateClientIdentifier(
                client_id,
            ));
        }
        Ok(Self {
            entries,
            fingerprint,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(super) fn try_replace_runtime(
        &self,
        clients: &crate::client_registry::ClientRegistry,
    ) -> Result<usize, RuntimeClientSnapshotError> {
        self.projection_commit().try_commit(clients)
    }

    #[cfg(test)]
    pub(super) fn try_register_runtime(
        &self,
        clients: &crate::client_registry::ClientRegistry,
    ) -> Result<usize, RuntimeClientSnapshotError> {
        let mut registry_projection = clients.try_client_projection_write()?;
        for entry in &self.entries {
            let client = entry.client.clone();
            let credentials =
                client_secret_auth_method_supported(&client.token_endpoint_auth_method)
                    .then(|| entry.client_secret_credentials.clone());
            registry_projection
                .register_with_client_secret_credentials(client.clone(), credentials.clone());
        }
        Ok(self.len())
    }

    #[cfg(test)]
    fn projection_commit(&self) -> RuntimeClientProjectionCommit {
        RuntimeClientProjectionCommit {
            registry_clients: self
                .entries
                .iter()
                .map(|entry| (entry.client.client_id.clone(), entry.client.clone()))
                .collect(),
            registry_credentials: shared_secret_credentials_by_client(&self.entries),
            fingerprint: self.fingerprint.clone(),
            len: self.len(),
        }
    }

    pub(super) fn into_projection_commit(self) -> RuntimeClientProjectionCommit {
        RuntimeClientProjectionCommit {
            registry_clients: self
                .entries
                .iter()
                .map(|entry| (entry.client.client_id.clone(), entry.client.clone()))
                .collect(),
            registry_credentials: shared_secret_credentials_by_client(&self.entries),
            fingerprint: self.fingerprint,
            len: self.entries.len(),
        }
    }
}

fn shared_secret_credentials_by_client(
    entries: &[RuntimeClientSnapshotEntry],
) -> HashMap<String, Vec<ClientSecretCredential>> {
    entries
        .iter()
        .filter(|entry| {
            client_secret_auth_method_supported(&entry.client.token_endpoint_auth_method)
        })
        .map(|entry| {
            (
                entry.client.client_id.clone(),
                entry.client_secret_credentials.clone(),
            )
        })
        .collect()
}

fn client_secret_auth_method_supported(method: &str) -> bool {
    let method = method.trim();
    method.eq_ignore_ascii_case("client_secret_basic")
        || method.eq_ignore_ascii_case("client_secret_post")
}

#[cfg(test)]
fn runtime_client_entries_fingerprint(entries: &[RuntimeClientSnapshotEntry]) -> String {
    let mut client_ids = entries
        .iter()
        .map(|entry| entry.client.client_id.as_str())
        .collect::<Vec<_>>();
    client_ids.sort_unstable();
    aegaeon_crypto::hash::sha256_hex(client_ids.join("\n").as_bytes())
}

fn duplicate_runtime_client_identifier(entries: &[RuntimeClientSnapshotEntry]) -> Option<String> {
    let mut seen = HashSet::new();
    entries
        .iter()
        .map(|entry| entry.client.client_id.as_str())
        .find(|client_id| !seen.insert((*client_id).to_string()))
        .map(str::to_string)
}
