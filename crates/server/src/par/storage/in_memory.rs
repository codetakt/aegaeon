use super::{ParRequestStore, ParStorageError};
use crate::par::StoredParRequest;
use std::collections::HashMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, SystemTime};

#[derive(Default)]
pub(in crate::par) struct InMemoryParRequestStore {
    requests: RwLock<HashMap<String, StoredParRequest>>,
}

impl InMemoryParRequestStore {
    pub(in crate::par) fn new() -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
        }
    }

    fn read_requests(
        &self,
    ) -> Result<RwLockReadGuard<'_, HashMap<String, StoredParRequest>>, ParStorageError> {
        self.requests
            .read()
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))
    }

    fn write_requests(
        &self,
    ) -> Result<RwLockWriteGuard<'_, HashMap<String, StoredParRequest>>, ParStorageError> {
        self.requests
            .write()
            .map_err(|err| ParStorageError::BackendUnavailable(err.to_string()))
    }
}

impl ParRequestStore for InMemoryParRequestStore {
    fn insert(
        &self,
        request_uri: &str,
        stored: StoredParRequest,
        _ttl: Duration,
    ) -> Result<(), ParStorageError> {
        self.write_requests()?
            .insert(request_uri.to_string(), stored);
        Ok(())
    }

    fn load(&self, request_uri: &str) -> Result<Option<StoredParRequest>, ParStorageError> {
        Ok(self.read_requests()?.get(request_uri).cloned())
    }

    fn reserve(
        &self,
        request_uri: &str,
        continuation: &str,
        _ttl: Duration,
    ) -> Result<bool, ParStorageError> {
        let mut requests = self.write_requests()?;
        let Some(stored) = requests.get_mut(request_uri) else {
            return Ok(false);
        };
        if stored.authorize_continuation.is_some() {
            return Ok(false);
        }
        stored.authorize_continuation = Some(continuation.to_string());
        Ok(true)
    }

    fn reservation(&self, request_uri: &str) -> Result<Option<String>, ParStorageError> {
        Ok(self
            .read_requests()?
            .get(request_uri)
            .and_then(|stored| stored.authorize_continuation.clone()))
    }

    fn consume(&self, request_uri: &str) -> Result<Option<StoredParRequest>, ParStorageError> {
        Ok(self.write_requests()?.remove(request_uri))
    }

    fn remove(&self, request_uri: &str) -> Result<(), ParStorageError> {
        self.write_requests()?.remove(request_uri);
        Ok(())
    }

    fn cleanup_expired(&self) -> Result<(), ParStorageError> {
        let now = SystemTime::now();
        self.write_requests()?
            .retain(|_, stored| stored.expires_at > now);
        Ok(())
    }
}
