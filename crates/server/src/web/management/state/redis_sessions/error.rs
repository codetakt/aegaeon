#[derive(Debug, thiserror::Error)]
pub(in crate::web::management) enum ManagementSessionStorageError {
    #[error("management session store backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("management session store retention cannot be represented")]
    RetentionOverflow,
}

pub(in crate::web::management::state) fn log_management_session_storage_error(
    error: &ManagementSessionStorageError,
    operation: &str,
) {
    tracing::error!(error = %error, operation, "management session store operation failed");
}

pub(super) fn management_session_redis_error(message: impl Into<String>) -> redis::RedisError {
    redis::RedisError::from((
        redis::ErrorKind::TypeError,
        "management session store state codec error",
        message.into(),
    ))
}
