use thiserror::Error;

use crate::client_registry::ClientRegistryStateError;
use crate::runtime_configuration::RuntimeFingerprintError;

#[derive(Debug, Error)]
pub enum RuntimeClientSnapshotError {
    #[error("issuer host for runtime client synchronization must not be empty")]
    EmptyIssuerHost,

    #[error("federation runtime client pagination parameter `{0}` is too large")]
    InvalidPagination(&'static str),

    #[error("no ACTIVE management environment/configuration version matched issuer host `{0}`")]
    NotFound(String),

    #[error("multiple ACTIVE management environments matched issuer host `{0}`")]
    AmbiguousIssuerHost(String),

    #[error("failed to query active runtime clients: {0}")]
    DatabaseQuery(#[from] sqlx::Error),

    #[error("duplicate active runtime client_identifier in active issuer environment: {0}")]
    DuplicateClientIdentifier(String),

    #[error("client secret projection is inconsistent for active runtime client `{0}`")]
    InconsistentClientSecretProjection(String),

    #[error(
        "dynamic client registration projection is invalid for active runtime client `{0}`: {1}"
    )]
    InvalidDynamicRegistrationProjection(String, String),

    #[error("runtime client projection changed while loading issuer host `{0}`")]
    ConcurrentModification(String),

    #[error("runtime policy/key/DCR bearer revision changed while syncing issuer host `{0}`")]
    RuntimeRevisionMismatch(String),

    #[error("invalid active runtime authority fingerprint: {0}")]
    InvalidRuntimeFingerprint(#[from] RuntimeFingerprintError),

    #[error("runtime client registry state unavailable: {0}")]
    RegistryState(#[from] ClientRegistryStateError),
}
