use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

use crate::middleware::{replay_key_material, ReplayStore};

mod config;
mod replay;
#[cfg(test)]
mod tests;

const REQUEST_OBJECT_JTI_REPLAY_NAMESPACE: &str = "request-object-jti";

/// Errors returned when checking Request Object `jti` values.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestObjectReplayError {
    #[error("Request Object replay detected")]
    Replay,

    #[error("Request Object replay store backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("Request Object replay retention exceeds runtime clock bounds")]
    RetentionOverflow,
}

/// Tracks Request Object `jti` values to prevent replay.
#[derive(Clone)]
pub struct RequestObjectJtiStore {
    replay_store: Arc<dyn ReplayStore>,
    ttl: Duration,
}

impl From<crate::middleware::ReplayStoreError> for RequestObjectReplayError {
    fn from(err: crate::middleware::ReplayStoreError) -> Self {
        match err {
            crate::middleware::ReplayStoreError::Replay => Self::Replay,
            crate::middleware::ReplayStoreError::BackendUnavailable(message) => {
                Self::BackendUnavailable(message)
            }
            crate::middleware::ReplayStoreError::RetentionOverflow => Self::RetentionOverflow,
        }
    }
}

fn request_object_replay_key_material(client_id: &str, jti: &str) -> Vec<u8> {
    replay_key_material(&[client_id.as_bytes(), jti.as_bytes()])
}
