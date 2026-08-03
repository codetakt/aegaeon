mod error;
mod projection;
mod queries;
mod repository;
mod row;
mod snapshot;

pub use error::RuntimeClientSnapshotError;
pub use projection::{RuntimeClientProjectionUpdate, RuntimeClientSynchronization};
pub use repository::{
    load_federation_subordinate_entity_ids_page,
    load_runtime_client_projection_from_database_guarded, FederationSubordinateEntityIdsPage,
};

pub(crate) use projection::RuntimeClientProjectionCommit;
pub(crate) use repository::load_active_runtime_client_fingerprint_for_issuer_host_in_tx;

#[cfg(test)]
use snapshot::{RuntimeClientSnapshot, RuntimeClientSnapshotEntry};

#[cfg(test)]
mod tests;
