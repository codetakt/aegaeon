use crate::federation::FederationError;

/// Helper to convert a sqlx error into a `FederationError::Storage`.
///
/// Logs the full error for debugging but returns a generic message to avoid
/// leaking DB internals (table names, constraint names) in error responses.
pub(in crate::federation) fn storage_err(e: &sqlx::Error) -> FederationError {
    tracing::warn!(error = %e, "federation storage error");
    FederationError::Storage("database operation failed".to_string())
}
