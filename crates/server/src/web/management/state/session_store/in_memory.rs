use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use super::{ManagementSession, ManagementSessionBackend};

pub(super) fn new_in_memory_backend() -> ManagementSessionBackend {
    ManagementSessionBackend::InMemory(Arc::new(RwLock::new(HashMap::new())))
}

fn session_is_live(session: &ManagementSession, now_epoch_secs: u64, ttl_secs: u64) -> bool {
    now_epoch_secs
        .checked_sub(session.created_at_epoch_secs)
        .is_some_and(|age| age < ttl_secs)
}

pub(super) fn get_in_memory_session(
    sessions: &RwLock<HashMap<String, ManagementSession>>,
    sid: &str,
    now_epoch_secs: u64,
    ttl_secs: u64,
) -> Result<Option<ManagementSession>, String> {
    let Ok(mut map) = sessions.write() else {
        return Err("management session store lock poisoned".to_string());
    };
    let Some(session) = map.get(sid).cloned() else {
        return Ok(None);
    };
    if !session_is_live(&session, now_epoch_secs, ttl_secs) {
        map.remove(sid);
        return Ok(None);
    }
    Ok(Some(session))
}

pub(super) fn create_in_memory_session(
    sessions: &RwLock<HashMap<String, ManagementSession>>,
    administrator_id: Uuid,
    now_epoch_secs: u64,
    ttl_secs: u64,
    max_sessions: usize,
) -> Result<Option<String>, String> {
    if now_epoch_secs.checked_add(ttl_secs).is_none() {
        return Ok(None);
    }
    let sid = Uuid::new_v4().to_string();
    let session = ManagementSession::human(administrator_id, now_epoch_secs);
    let Ok(mut map) = sessions.write() else {
        return Err("management session store lock poisoned".to_string());
    };
    if map.len() >= max_sessions {
        map.retain(|_, s| session_is_live(s, now_epoch_secs, ttl_secs));
    }
    while map.len() >= max_sessions {
        if let Some(oldest_sid) = map
            .iter()
            .min_by_key(|(_, s)| s.created_at_epoch_secs)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest_sid);
        } else {
            break;
        }
    }
    map.insert(sid.clone(), session);
    Ok(Some(sid))
}

pub(super) fn delete_in_memory_session(
    sessions: &RwLock<HashMap<String, ManagementSession>>,
    sid: &str,
) -> Result<bool, String> {
    let Ok(mut map) = sessions.write() else {
        return Err("management session store lock poisoned".to_string());
    };
    Ok(map.remove(sid).is_some())
}

#[cfg(test)]
pub(super) fn in_memory_session_count(
    sessions: &RwLock<HashMap<String, ManagementSession>>,
) -> Result<usize, String> {
    let sessions = sessions
        .read()
        .map_err(|_| "management session store test helper could not read sessions".to_string())?;
    Ok(sessions.len())
}
