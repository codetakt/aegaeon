mod configuration;
mod diagnostics;
mod error;
pub(in crate::web::management) use error::SessionStoreError;
#[cfg(test)]
mod in_memory;
mod operations;
mod postgres;
#[cfg(test)]
mod testing;

#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(test)]
use std::sync::RwLock;
use uuid::Uuid;

use crate::management::types::ApiKeyCapability;

#[cfg(test)]
use super::redis_sessions::RedisManagementSessionBackend;

#[derive(Clone, Debug)]
pub(in crate::web::management) struct ManagementSession {
    pub(in crate::web::management) administrator_id: Uuid,
    pub(in crate::web::management) created_at_epoch_secs: u64,
    pub(in crate::web::management) authentication: ManagementAuthentication,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::web::management) enum ManagementAuthentication {
    HumanSession,
    ApiKey {
        api_key_id: Uuid,
        team_id: Uuid,
        capabilities: Vec<ApiKeyCapability>,
    },
}

impl ManagementSession {
    pub(in crate::web::management) fn human(
        administrator_id: Uuid,
        created_at_epoch_secs: u64,
    ) -> Self {
        Self {
            administrator_id,
            created_at_epoch_secs,
            authentication: ManagementAuthentication::HumanSession,
        }
    }

    pub(in crate::web::management) fn api_key(
        administrator_id: Uuid,
        created_at_epoch_secs: u64,
        api_key_id: Uuid,
        team_id: Uuid,
        capabilities: Vec<ApiKeyCapability>,
    ) -> Self {
        Self {
            administrator_id,
            created_at_epoch_secs,
            authentication: ManagementAuthentication::ApiKey {
                api_key_id,
                team_id,
                capabilities,
            },
        }
    }

    pub(in crate::web::management) fn is_human_session(&self) -> bool {
        matches!(self.authentication, ManagementAuthentication::HumanSession)
    }

    pub(in crate::web::management) fn api_key_id(&self) -> Option<Uuid> {
        match self.authentication {
            ManagementAuthentication::ApiKey { api_key_id, .. } => Some(api_key_id),
            ManagementAuthentication::HumanSession => None,
        }
    }

    pub(in crate::web::management) fn api_key_team_id(&self) -> Option<Uuid> {
        match &self.authentication {
            ManagementAuthentication::ApiKey { team_id, .. } => Some(*team_id),
            ManagementAuthentication::HumanSession => None,
        }
    }

    pub(in crate::web::management) fn api_key_has_capability(
        &self,
        capability: ApiKeyCapability,
    ) -> bool {
        match &self.authentication {
            ManagementAuthentication::ApiKey { capabilities, .. } => {
                capabilities.contains(&capability)
                    || (capability != ApiKeyCapability::OrganizationAuditExport
                        && capabilities.contains(&ApiKeyCapability::TeamAdministration))
            }
            ManagementAuthentication::HumanSession => false,
        }
    }
}

#[derive(Clone)]
pub(in crate::web::management) struct ManagementSessionStore {
    pub(in crate::web::management) diagnostics: Arc<diagnostics::Diagnostics>,
    pub(in crate::web::management) backend: ManagementSessionBackend,
    pub(in crate::web::management) session_ttl_secs: u64,
    pub(in crate::web::management) max_sessions: usize,
}

#[derive(Clone)]
pub(in crate::web::management) enum ManagementSessionBackend {
    Postgres(postgres::PostgresManagementSessions),
    #[cfg(test)]
    InMemory(Arc<RwLock<HashMap<String, ManagementSession>>>),
    #[cfg(test)]
    Redis(RedisManagementSessionBackend),
}

#[cfg(test)]
pub(super) const MANAGEMENT_SESSION_REDIS_URL_ENV: &str =
    "AEGAEON_TEST_MANAGEMENT_SESSION_REDIS_URL";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_session_capability_checks_do_not_promote_ordinary_capabilities() {
        let session = ManagementSession::api_key(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            Uuid::new_v4(),
            vec![ApiKeyCapability::AuditRead],
        );

        assert!(session.api_key_has_capability(ApiKeyCapability::AuditRead));
        assert!(!session.api_key_has_capability(ApiKeyCapability::TeamAdministration));
        assert!(!session.api_key_has_capability(ApiKeyCapability::Read));
    }

    #[test]
    fn api_key_session_team_administration_is_super_capability() {
        let session = ManagementSession::api_key(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            Uuid::new_v4(),
            vec![ApiKeyCapability::TeamAdministration],
        );

        for capability in [
            ApiKeyCapability::Read,
            ApiKeyCapability::AuditRead,
            ApiKeyCapability::TeamAdministration,
        ] {
            assert!(session.api_key_has_capability(capability));
        }
        assert!(!session.api_key_has_capability(ApiKeyCapability::OrganizationAuditExport));
    }

    #[test]
    fn audit_export_capability_is_explicit_and_does_not_promote_other_authority() {
        let session = ManagementSession::api_key(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            Uuid::new_v4(),
            vec![ApiKeyCapability::OrganizationAuditExport],
        );
        assert!(session.api_key_has_capability(ApiKeyCapability::OrganizationAuditExport));
        for capability in [
            ApiKeyCapability::Read,
            ApiKeyCapability::AuditRead,
            ApiKeyCapability::TeamAdministration,
        ] {
            assert!(!session.api_key_has_capability(capability));
        }
    }
}

#[cfg(test)]
mod organization_epoch;
