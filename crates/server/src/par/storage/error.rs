use thiserror::Error;

#[derive(Debug, Error)]
pub(in crate::par) enum ParStorageError {
    #[error("PAR request store backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("PAR request store TTL cannot be represented")]
    RetentionOverflow,

    #[error("PAR request expiry cannot be represented")]
    ExpiryOutOfRange,

    #[error("PAR request payload cannot be serialized: {0}")]
    Serialize(String),
}
