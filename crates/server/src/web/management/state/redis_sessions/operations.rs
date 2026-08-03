mod connection;
mod session;

use super::error::ManagementSessionStorageError;

fn backend_unavailable(error: &impl ToString) -> ManagementSessionStorageError {
    ManagementSessionStorageError::BackendUnavailable(error.to_string())
}
