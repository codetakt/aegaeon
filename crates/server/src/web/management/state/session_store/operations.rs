#[cfg(test)]
use crate::organizations::request_work::async_store::blocking;
use uuid::Uuid;

#[cfg(test)]
use super::super::redis_sessions::log_management_session_storage_error;
#[cfg(test)]
use super::in_memory::{create_in_memory_session, delete_in_memory_session, get_in_memory_session};
use super::{ManagementSession, ManagementSessionBackend, ManagementSessionStore};

impl ManagementSessionStore {
    pub(in crate::web::management) async fn try_get_admitted(
        &self,
        admission: &crate::organizations::request_work::Admission,
        connection: Option<&mut sqlx::PgConnection>,
        sid: String,
        now: u64,
    ) -> Result<Option<ManagementSession>, String> {
        match &self.backend {
            ManagementSessionBackend::Postgres(backend) => match connection {
                Some(connection) => {
                    backend
                        .get_in_transaction(connection, &sid, now, self.session_ttl_secs)
                        .await
                }
                None => {
                    backend
                        .get_admitted(admission, &sid, now, self.session_ttl_secs)
                        .await
                }
            },
            #[cfg(test)]
            _ => {
                let store = self.clone();
                admission
                    .blocking(move || store.try_get(&sid, now))
                    .await
                    .map_err(|_| "management session read unavailable".to_owned())?
            }
        }
    }

    pub(in crate::web::management) async fn cleanup_async(&self) -> Result<(), String> {
        match &self.backend {
            ManagementSessionBackend::Postgres(backend) => backend.cleanup().await,
            #[cfg(test)]
            _ => Ok(()),
        }
    }

    #[cfg(test)]
    pub(in crate::web::management) fn try_get(
        &self,
        sid: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<ManagementSession>, String> {
        match &self.backend {
            ManagementSessionBackend::Postgres(_) => {
                Err("PostgreSQL management sessions require the async API".into())
            }
            #[cfg(test)]
            ManagementSessionBackend::InMemory(sessions) => {
                get_in_memory_session(sessions, sid, now_epoch_secs, self.session_ttl_secs)
            }
            ManagementSessionBackend::Redis(backend) => backend
                .get(sid, now_epoch_secs, self.session_ttl_secs)
                .map_err(|err| {
                    let message = err.to_string();
                    log_management_session_storage_error(&err, "get");
                    message
                }),
        }
    }

    pub(in crate::web::management) async fn try_get_async(
        &self,
        sid: String,
        now_epoch_secs: u64,
    ) -> Result<Option<ManagementSession>, String> {
        match &self.backend {
            ManagementSessionBackend::Postgres(backend) => {
                backend
                    .get(&sid, now_epoch_secs, self.session_ttl_secs)
                    .await
            }
            #[cfg(test)]
            _ => {
                let store = self.clone();
                blocking(move || store.try_get(&sid, now_epoch_secs))
                    .await
                    .map_err(|err| format!("management session store worker failed: {err}"))?
            }
        }
    }

    #[cfg(test)]
    pub(in crate::web::management) fn try_create(
        &self,
        administrator_id: Uuid,
        now_epoch_secs: u64,
    ) -> Result<Option<String>, String> {
        match &self.backend {
            ManagementSessionBackend::Postgres(_) => {
                Err("PostgreSQL management sessions require the async API".into())
            }
            #[cfg(test)]
            ManagementSessionBackend::InMemory(sessions) => create_in_memory_session(
                sessions,
                administrator_id,
                now_epoch_secs,
                self.session_ttl_secs,
                self.max_sessions,
            ),
            ManagementSessionBackend::Redis(backend) => {
                if now_epoch_secs.checked_add(self.session_ttl_secs).is_none() {
                    return Ok(None);
                }
                let sid = uuid::Builder::from_random_bytes(aegaeon_crypto::rand::random_array())
                    .into_uuid()
                    .to_string();
                let session = ManagementSession::human(administrator_id, now_epoch_secs);
                backend
                    .create(
                        &sid,
                        &session,
                        now_epoch_secs,
                        self.session_ttl_secs,
                        self.max_sessions,
                    )
                    .map(|()| Some(sid.clone()))
                    .map_err(|err| {
                        let message = err.to_string();
                        log_management_session_storage_error(&err, "create");
                        message
                    })
            }
        }
    }

    pub(in crate::web::management) async fn try_create_async(
        &self,
        administrator_id: Uuid,
        now_epoch_secs: u64,
    ) -> Result<Option<String>, String> {
        match &self.backend {
            ManagementSessionBackend::Postgres(backend) => {
                backend
                    .create(
                        administrator_id,
                        now_epoch_secs,
                        self.session_ttl_secs,
                        self.max_sessions,
                    )
                    .await
            }
            #[cfg(test)]
            _ => {
                let store = self.clone();
                blocking(move || store.try_create(administrator_id, now_epoch_secs))
                    .await
                    .map_err(|err| format!("management session store worker failed: {err}"))?
            }
        }
    }

    #[cfg(test)]
    pub(in crate::web::management) fn try_delete(&self, sid: &str) -> Result<bool, String> {
        match &self.backend {
            ManagementSessionBackend::Postgres(_) => {
                Err("PostgreSQL management sessions require the async API".into())
            }
            #[cfg(test)]
            ManagementSessionBackend::InMemory(sessions) => delete_in_memory_session(sessions, sid),
            ManagementSessionBackend::Redis(backend) => backend.delete_sid(sid).map_err(|err| {
                let message = err.to_string();
                log_management_session_storage_error(&err, "delete");
                message
            }),
        }
    }

    pub(in crate::web::management) async fn try_delete_async(
        &self,
        sid: String,
    ) -> Result<bool, String> {
        match &self.backend {
            ManagementSessionBackend::Postgres(backend) => backend.delete(&sid).await,
            #[cfg(test)]
            _ => {
                let store = self.clone();
                blocking(move || store.try_delete(&sid))
                    .await
                    .map_err(|err| format!("management session store worker failed: {err}"))?
            }
        }
    }
}
