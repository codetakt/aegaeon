use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::{UpstreamLogoutRelayState, UpstreamLogoutRelayStorageError};

#[derive(Clone, Default)]
pub(super) struct ProcessLocalLogoutRelayBackend {
    entries: Arc<RwLock<HashMap<String, ProcessLocalLogoutRelayEntry>>>,
}

struct ProcessLocalLogoutRelayEntry {
    value: UpstreamLogoutRelayState,
    expires_at: Instant,
}

impl ProcessLocalLogoutRelayBackend {
    pub(super) fn insert(
        &self,
        relay_token: &str,
        value: UpstreamLogoutRelayState,
        ttl: Duration,
    ) -> Result<(), UpstreamLogoutRelayStorageError> {
        let expires_at = Instant::now().checked_add(ttl).ok_or_else(|| {
            UpstreamLogoutRelayStorageError::Codec("logout relay ttl overflow".into())
        })?;
        let mut entries = self
            .entries
            .write()
            .map_err(|err| UpstreamLogoutRelayStorageError::BackendUnavailable(err.to_string()))?;
        if entries
            .get(relay_token)
            .is_some_and(|entry| Instant::now() < entry.expires_at)
        {
            return Err(UpstreamLogoutRelayStorageError::Collision);
        }
        entries.insert(
            relay_token.to_string(),
            ProcessLocalLogoutRelayEntry { value, expires_at },
        );
        Ok(())
    }

    pub(super) fn take(
        &self,
        relay_token: &str,
    ) -> Result<Option<UpstreamLogoutRelayState>, UpstreamLogoutRelayStorageError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|err| UpstreamLogoutRelayStorageError::BackendUnavailable(err.to_string()))?;
        let Some(entry) = entries.remove(relay_token) else {
            return Ok(None);
        };
        Ok((Instant::now() < entry.expires_at).then_some(entry.value))
    }

    pub(super) fn cleanup_expired(&self) -> Result<(), UpstreamLogoutRelayStorageError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|err| UpstreamLogoutRelayStorageError::BackendUnavailable(err.to_string()))?;
        let now = Instant::now();
        entries.retain(|_, entry| entry.expires_at > now);
        Ok(())
    }
}
