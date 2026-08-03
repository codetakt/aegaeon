use super::*;
use std::fmt::Debug;

mod client_auth;
mod configuration;
mod request_lifecycle;

struct UnavailableParRequestStore;

impl UnavailableParRequestStore {
    fn error() -> ParStorageError {
        ParStorageError::BackendUnavailable("store unavailable".to_string())
    }
}

impl ParRequestStore for UnavailableParRequestStore {
    fn insert(
        &self,
        _request_uri: &str,
        _stored: StoredParRequest,
        _ttl: Duration,
    ) -> Result<(), ParStorageError> {
        Err(Self::error())
    }

    fn load(&self, _request_uri: &str) -> Result<Option<StoredParRequest>, ParStorageError> {
        Err(Self::error())
    }

    fn reserve(
        &self,
        _request_uri: &str,
        _continuation: &str,
        _ttl: Duration,
    ) -> Result<bool, ParStorageError> {
        Err(Self::error())
    }

    fn reservation(&self, _request_uri: &str) -> Result<Option<String>, ParStorageError> {
        Err(Self::error())
    }

    fn consume(&self, _request_uri: &str) -> Result<Option<StoredParRequest>, ParStorageError> {
        Err(Self::error())
    }

    fn remove(&self, _request_uri: &str) -> Result<(), ParStorageError> {
        Err(Self::error())
    }

    fn cleanup_expired(&self) -> Result<(), ParStorageError> {
        Err(Self::error())
    }
}

type TestResult = Result<(), String>;

fn test_context<T, E: Debug>(result: Result<T, E>, context: &str) -> Result<T, String> {
    result.map_err(|err| format!("{context}: {err:?}"))
}

fn test_err<T, E>(result: Result<T, E>, context: &str) -> Result<E, String> {
    result.err().ok_or_else(|| context.to_string())
}

fn consume_request(store: &ParStore, request_uri: &str) -> Result<Option<ParRequest>, String> {
    test_context(
        store.try_consume_request(request_uri),
        "in-memory PAR consume should not fail",
    )
}

fn resolve_request(store: &ParStore, request_uri: &str) -> Result<Option<ParRequest>, String> {
    match store.reserve_request_for_client(request_uri, "test_client") {
        Ok(reserved) => Ok(Some(reserved.request)),
        Err(err) if err.error == "invalid_request" || err.error == "invalid_request_uri" => {
            Ok(None)
        }
        Err(err) => Err(format!("in-memory PAR resolve should not fail: {err:?}")),
    }
}
