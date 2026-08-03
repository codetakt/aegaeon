use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeKeySetError {
    #[error("failed to query runtime keys: {0}")]
    DatabaseQuery(sqlx::Error),

    #[error("failed to decode runtime key column `{0}`")]
    RowDecode(&'static str),

    #[error("invalid runtime key usage `{0}`")]
    InvalidUsage(String),

    #[error("invalid runtime key algorithm `{0}`")]
    InvalidAlgorithm(String),

    #[error("invalid runtime key provider `{0}`")]
    InvalidProvider(String),

    #[error("invalid runtime key status `{0}`")]
    InvalidStatus(String),

    #[error("runtime key public_jwk is invalid: {0}")]
    InvalidPublicJwk(serde_json::Error),

    #[error("runtime key `{kid}` has invalid {field}: {reason}")]
    InvalidKey {
        kid: String,
        field: &'static str,
        reason: &'static str,
    },

    #[error("runtime key set contains duplicate ACTIVE keys for usage `{0}`")]
    DuplicateActiveUsage(&'static str),

    #[error(
        "runtime key set contains {count} RETIRING keys for usage `{usage}`, exceeding limit {max}"
    )]
    TooManyRetiringKeys {
        usage: &'static str,
        count: usize,
        max: usize,
    },

    #[error("runtime key policy contains unsupported signing algorithm `{0}`")]
    InvalidPolicySigningAlgorithm(String),

    #[error("runtime key usage `{usage}` uses signing algorithm `{algorithm}` outside policy")]
    PolicyDisallowedSigningAlgorithm {
        usage: &'static str,
        algorithm: &'static str,
    },
}
