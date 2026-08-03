use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::AuthSession;

type SessionMap = HashMap<String, AuthSession>;

#[derive(Clone)]
pub(super) struct ProcessLocalAuthSessionBackend {
    sessions: Arc<RwLock<SessionMap>>,
}

impl ProcessLocalAuthSessionBackend {
    pub(super) fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub(super) fn get(
        &self,
        sid: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<AuthSession>, String> {
        self.with_sessions(|sessions| {
            let session = sessions.get(sid).cloned();
            match session {
                Some(session) if session.expires_at_epoch_secs <= now_epoch_secs => {
                    sessions.remove(sid);
                    None
                }
                session => session,
            }
        })
    }

    pub(super) fn create(
        &self,
        sid: &str,
        session: AuthSession,
        now_epoch_secs: u64,
        max_sessions: usize,
    ) -> Result<(), String> {
        self.with_sessions(|sessions| {
            Self::remove_expired_locked(sessions, now_epoch_secs);
            Self::reserve_capacity_for_insert_locked(sessions, max_sessions);
            sessions.insert(sid.to_string(), session);
            Self::enforce_capacity_locked(sessions, max_sessions);
        })
    }

    pub(super) fn delete_sid(&self, sid: &str) -> Result<bool, String> {
        self.with_sessions(|sessions| sessions.remove(sid).is_some())
    }

    pub(super) fn delete_for_user(
        &self,
        user_id: &str,
        now_epoch_secs: u64,
    ) -> Result<usize, String> {
        self.with_sessions(|sessions| {
            Self::remove_expired_locked(sessions, now_epoch_secs);
            let before = sessions.len();
            sessions.retain(|_, session| session.user_id != user_id);
            before.saturating_sub(sessions.len())
        })
    }

    pub(super) fn list_for_user(
        &self,
        user_id: &str,
        now_epoch_secs: u64,
    ) -> Result<Vec<(String, AuthSession)>, String> {
        self.with_sessions(|sessions| {
            Self::remove_expired_locked(sessions, now_epoch_secs);
            sessions
                .iter()
                .filter(|(_, session)| session.user_id == user_id)
                .map(|(sid, session)| (sid.clone(), session.clone()))
                .collect()
        })
    }

    pub(super) fn delete_for_user_session(
        &self,
        user_id: &str,
        sid: &str,
        now_epoch_secs: u64,
    ) -> Result<bool, String> {
        self.with_sessions(|sessions| {
            Self::remove_expired_locked(sessions, now_epoch_secs);
            if sessions
                .get(sid)
                .is_some_and(|session| session.user_id == user_id)
            {
                sessions.remove(sid).is_some()
            } else {
                false
            }
        })
    }

    pub(super) fn cleanup_expired(&self, now_epoch_secs: u64) -> Result<usize, String> {
        self.with_sessions(|sessions| Self::remove_expired_locked(sessions, now_epoch_secs))
    }

    fn with_sessions<T>(&self, f: impl FnOnce(&mut SessionMap) -> T) -> Result<T, String> {
        let Ok(mut sessions) = self.sessions.write() else {
            return Err("auth session store lock poisoned".to_string());
        };
        Ok(f(&mut sessions))
    }

    fn remove_expired_locked(sessions: &mut SessionMap, now_epoch_secs: u64) -> usize {
        let before = sessions.len();
        sessions.retain(|_, session| session.expires_at_epoch_secs > now_epoch_secs);
        before.saturating_sub(sessions.len())
    }

    fn enforce_capacity_locked(sessions: &mut SessionMap, max_sessions: usize) {
        while sessions.len() > max_sessions {
            if !Self::evict_oldest_locked(sessions) {
                break;
            }
        }
    }

    fn reserve_capacity_for_insert_locked(sessions: &mut SessionMap, max_sessions: usize) {
        while sessions.len() >= max_sessions {
            if !Self::evict_oldest_locked(sessions) {
                break;
            }
        }
    }

    fn evict_oldest_locked(sessions: &mut SessionMap) -> bool {
        let Some(oldest_sid) = sessions
            .iter()
            .min_by_key(|(sid, session)| (session.created_at_epoch_secs, *sid))
            .map(|(sid, _)| sid.clone())
        else {
            return false;
        };
        sessions.remove(&oldest_sid).is_some()
    }
}
