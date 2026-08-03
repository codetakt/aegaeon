use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use super::super::control_plane_policy::{DEFAULT_MAX_SESSIONS, DEFAULT_SESSION_TTL_SECS};
use super::in_memory::in_memory_session_count;
use super::{ManagementSession, ManagementSessionBackend, ManagementSessionStore};

impl ManagementSessionStore {
    #[cfg(test)]
    pub(in crate::web::management) fn new_process_local_for_tests() -> Self {
        Self::new_process_local_with_limits(DEFAULT_SESSION_TTL_SECS, DEFAULT_MAX_SESSIONS)
    }

    #[cfg(test)]
    pub(in crate::web::management) fn new_process_local_with_ttl_for_tests(ttl_secs: u64) -> Self {
        Self::new_process_local_with_limits(ttl_secs, DEFAULT_MAX_SESSIONS)
    }

    pub(in crate::web::management) fn get(
        &self,
        sid: &str,
        now_epoch_secs: u64,
    ) -> Option<ManagementSession> {
        self.try_get(sid, now_epoch_secs).ok().flatten()
    }

    pub(in crate::web::management) fn create(
        &self,
        administrator_id: Uuid,
        now_epoch_secs: u64,
    ) -> Option<String> {
        self.try_create(administrator_id, now_epoch_secs)
            .ok()
            .flatten()
    }

    pub(in crate::web::management) fn try_len(&self) -> Result<usize, String> {
        match &self.backend {
            ManagementSessionBackend::InMemory(sessions) => in_memory_session_count(sessions),
            ManagementSessionBackend::Redis(backend) => {
                backend.len().map_err(|err| err.to_string())
            }
        }
    }

    pub(in crate::web::management) fn len(&self) -> usize {
        self.try_len().unwrap_or(0)
    }

    pub(in crate::web::management) fn in_memory_sessions(
        &self,
    ) -> &RwLock<HashMap<String, ManagementSession>> {
        match &self.backend {
            ManagementSessionBackend::InMemory(sessions) => sessions.as_ref(),
            ManagementSessionBackend::Redis(_) => {
                std::panic::panic_any("expected in-memory management sessions");
            }
        }
    }
}
