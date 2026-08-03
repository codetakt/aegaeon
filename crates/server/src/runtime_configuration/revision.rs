use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeFingerprint(String);

impl RuntimeFingerprint {
    fn try_from_database_projection(
        value: String,
        column: &'static str,
    ) -> Result<Self, RuntimeFingerprintError> {
        if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(value))
        } else {
            Err(RuntimeFingerprintError { column })
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_unchecked_for_tests(value: String) -> Self {
        Self(value)
    }

    #[must_use]
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("database runtime fingerprint column `{column}` must be a 64-character SHA-256 hex string")]
pub struct RuntimeFingerprintError {
    column: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StableRuntimeAuthorityRevision {
    active_configuration_version_id: Uuid,
    active_configuration_document_fingerprint: RuntimeFingerprint,
    active_runtime_key_set_fingerprint: RuntimeFingerprint,
    active_dcr_bearer_token_fingerprint: RuntimeFingerprint,
}

impl StableRuntimeAuthorityRevision {
    fn try_new(
        active_configuration_version_id: Uuid,
        active_configuration_document_fingerprint: String,
        active_runtime_key_set_fingerprint: String,
        active_dcr_bearer_token_fingerprint: String,
    ) -> Result<Self, RuntimeFingerprintError> {
        Ok(Self {
            active_configuration_version_id,
            active_configuration_document_fingerprint:
                RuntimeFingerprint::try_from_database_projection(
                    active_configuration_document_fingerprint,
                    "active_configuration_document_fingerprint",
                )?,
            active_runtime_key_set_fingerprint: RuntimeFingerprint::try_from_database_projection(
                active_runtime_key_set_fingerprint,
                "active_runtime_key_set_fingerprint",
            )?,
            active_dcr_bearer_token_fingerprint: RuntimeFingerprint::try_from_database_projection(
                active_dcr_bearer_token_fingerprint,
                "active_dcr_bearer_token_fingerprint",
            )?,
        })
    }

    #[cfg(test)]
    #[must_use]
    fn new_unchecked_for_tests(
        active_configuration_version_id: Uuid,
        active_configuration_document_fingerprint: String,
        active_runtime_key_set_fingerprint: String,
        active_dcr_bearer_token_fingerprint: String,
    ) -> Self {
        Self {
            active_configuration_version_id,
            active_configuration_document_fingerprint: RuntimeFingerprint::new_unchecked_for_tests(
                active_configuration_document_fingerprint,
            ),
            active_runtime_key_set_fingerprint: RuntimeFingerprint::new_unchecked_for_tests(
                active_runtime_key_set_fingerprint,
            ),
            active_dcr_bearer_token_fingerprint: RuntimeFingerprint::new_unchecked_for_tests(
                active_dcr_bearer_token_fingerprint,
            ),
        }
    }

    #[must_use]
    fn active_configuration_version_id(&self) -> Uuid {
        self.active_configuration_version_id
    }

    #[must_use]
    fn active_configuration_document_fingerprint(&self) -> &str {
        self.active_configuration_document_fingerprint.as_str()
    }

    #[must_use]
    fn active_runtime_key_set_fingerprint(&self) -> &str {
        self.active_runtime_key_set_fingerprint.as_str()
    }

    #[must_use]
    fn active_dcr_bearer_token_fingerprint(&self) -> &str {
        self.active_dcr_bearer_token_fingerprint.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeClientProjectionRevision {
    fingerprint: RuntimeFingerprint,
}

impl RuntimeClientProjectionRevision {
    fn try_from_database_projection(fingerprint: String) -> Result<Self, RuntimeFingerprintError> {
        Ok(Self {
            fingerprint: RuntimeFingerprint::try_from_database_projection(
                fingerprint,
                "active_runtime_client_fingerprint",
            )?,
        })
    }

    #[cfg(test)]
    #[must_use]
    fn new_unchecked_for_tests(fingerprint: String) -> Self {
        Self {
            fingerprint: RuntimeFingerprint::new_unchecked_for_tests(fingerprint),
        }
    }

    #[must_use]
    fn fingerprint(&self) -> &str {
        self.fingerprint.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAuthorityRevision {
    stable: StableRuntimeAuthorityRevision,
    client_projection: RuntimeClientProjectionRevision,
}

impl RuntimeAuthorityRevision {
    pub(crate) fn try_new(
        active_configuration_version_id: Uuid,
        active_configuration_document_fingerprint: String,
        active_runtime_key_set_fingerprint: String,
        active_runtime_client_fingerprint: String,
        active_dcr_bearer_token_fingerprint: String,
    ) -> Result<Self, RuntimeFingerprintError> {
        Ok(Self {
            stable: StableRuntimeAuthorityRevision::try_new(
                active_configuration_version_id,
                active_configuration_document_fingerprint,
                active_runtime_key_set_fingerprint,
                active_dcr_bearer_token_fingerprint,
            )?,
            client_projection: RuntimeClientProjectionRevision::try_from_database_projection(
                active_runtime_client_fingerprint,
            )?,
        })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_unchecked_for_tests(
        active_configuration_version_id: Uuid,
        active_configuration_document_fingerprint: String,
        active_runtime_key_set_fingerprint: String,
        active_runtime_client_fingerprint: String,
        active_dcr_bearer_token_fingerprint: String,
    ) -> Self {
        Self {
            stable: StableRuntimeAuthorityRevision::new_unchecked_for_tests(
                active_configuration_version_id,
                active_configuration_document_fingerprint,
                active_runtime_key_set_fingerprint,
                active_dcr_bearer_token_fingerprint,
            ),
            client_projection: RuntimeClientProjectionRevision::new_unchecked_for_tests(
                active_runtime_client_fingerprint,
            ),
        }
    }

    #[must_use]
    pub fn active_configuration_version_id(&self) -> Uuid {
        self.stable.active_configuration_version_id()
    }

    #[must_use]
    pub fn active_configuration_document_fingerprint(&self) -> &str {
        self.stable.active_configuration_document_fingerprint()
    }

    #[must_use]
    pub fn active_runtime_key_set_fingerprint(&self) -> &str {
        self.stable.active_runtime_key_set_fingerprint()
    }

    #[must_use]
    pub fn active_runtime_client_fingerprint(&self) -> &str {
        self.client_projection.fingerprint()
    }

    #[must_use]
    pub fn active_dcr_bearer_token_fingerprint(&self) -> &str {
        self.stable.active_dcr_bearer_token_fingerprint()
    }

    #[must_use]
    pub fn stable_authority_matches(&self, other: &Self) -> bool {
        self.stable == other.stable
    }
}
