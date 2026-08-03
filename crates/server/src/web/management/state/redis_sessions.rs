mod error;
mod keyspace;
mod model;
mod operations;
mod scripts;

pub(super) use error::log_management_session_storage_error;
pub(in crate::web::management) use keyspace::RedisManagementSessionKeyspace;

#[derive(Clone)]
pub(in crate::web::management) struct RedisManagementSessionBackend {
    client: redis::Client,
    keyspace: RedisManagementSessionKeyspace,
}
