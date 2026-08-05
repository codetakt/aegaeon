use super::{
    logged_out_session_expired, oidc_session_storage_error_message, OidcSessionStorageError,
};
use crate::oidc::{OidcLogoutEvent, OidcSessionContext};
use std::collections::{HashMap, HashSet};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

pub(super) struct Store {
    pub(super) sessions_by_auth_session: HashMap<String, String>,
    pub(super) sessions_by_user: HashMap<String, HashSet<String>>,
    pub(super) sessions: HashMap<String, Session>,
}

#[derive(Clone, Default)]
pub(super) struct Session {
    pub(super) user_id: String,
    pub(super) auth_session_id: String,
    pub(super) clients: HashSet<String>,
    pub(super) logout_jti: Option<String>,
    pub(super) logged_out_at_epoch_secs: Option<u64>,
}

impl Store {
    pub(super) fn new() -> Self {
        Self {
            sessions_by_auth_session: HashMap::new(),
            sessions_by_user: HashMap::new(),
            sessions: HashMap::new(),
        }
    }
}

fn oidc_session_lock_error(
    error: impl std::fmt::Display,
    operation: &'static str,
    lock_kind: &str,
) -> String {
    let error =
        OidcSessionStorageError::BackendUnavailable(format!("{lock_kind} lock poisoned: {error}"));
    oidc_session_storage_error_message(&error, operation)
}

pub(super) fn read_lock<'a, T>(
    lock: &'a RwLock<T>,
    operation: &'static str,
) -> Result<RwLockReadGuard<'a, T>, String> {
    lock.read()
        .map_err(|err| oidc_session_lock_error(err, operation, "read"))
}

pub(super) fn write_lock<'a, T>(
    lock: &'a RwLock<T>,
    operation: &'static str,
) -> Result<RwLockWriteGuard<'a, T>, String> {
    lock.write()
        .map_err(|err| oidc_session_lock_error(err, operation, "write"))
}

pub(super) fn prune_expired_sessions(store: &mut Store, now: u64, ttl: u64) {
    if ttl == 0 {
        return;
    }

    let expired: Vec<String> = store
        .sessions
        .iter()
        .filter_map(|(sid, session)| {
            let logged_out_at = session.logged_out_at_epoch_secs?;
            if session.logout_jti.is_some() && logged_out_session_expired(logged_out_at, now, ttl) {
                Some(sid.clone())
            } else {
                None
            }
        })
        .collect();

    for sid in expired {
        store.sessions.remove(&sid);
    }

    store
        .sessions_by_auth_session
        .retain(|_, sid| store.sessions.contains_key(sid));
    store.sessions_by_user.retain(|_, sids| {
        sids.retain(|sid| store.sessions.contains_key(sid));
        !sids.is_empty()
    });
}

pub(super) fn get_or_create_session(
    store: &RwLock<Store>,
    context: OidcSessionContext<'_>,
    now: u64,
    ttl: u64,
) -> Result<String, String> {
    let mut store = write_lock(store, "try_get_or_create_session")?;
    prune_expired_sessions(&mut store, now, ttl);

    if let Some(sid) = store
        .sessions_by_auth_session
        .get(context.auth_session_id)
        .cloned()
    {
        if let Some(sess) = store.sessions.get(&sid) {
            if sess.logout_jti.is_none() {
                return Ok(sid);
            }
        }
    }

    let sid = uuid::Builder::from_random_bytes(
        aegaeon_crypto::rand::random_bytes(16)
            .try_into()
            .expect("random_bytes(16) yields exactly 16 bytes"),
    )
    .into_uuid()
    .to_string();
    store
        .sessions_by_auth_session
        .insert(context.auth_session_id.to_string(), sid.clone());
    store
        .sessions_by_user
        .entry(context.user_id.to_string())
        .or_default()
        .insert(sid.clone());
    store.sessions.insert(
        sid.clone(),
        Session {
            user_id: context.user_id.to_string(),
            auth_session_id: context.auth_session_id.to_string(),
            ..Default::default()
        },
    );
    Ok(sid)
}

pub(super) fn add_client(
    store: &RwLock<Store>,
    sid: &str,
    client_id: &str,
    now: u64,
    ttl: u64,
) -> Result<bool, String> {
    let mut store = write_lock(store, "try_add_client")?;
    prune_expired_sessions(&mut store, now, ttl);

    let Some(session) = store.sessions.get_mut(sid) else {
        return Ok(false);
    };
    if session.logout_jti.is_some() {
        return Ok(false);
    }
    session.clients.insert(client_id.to_string());
    Ok(true)
}

pub(super) fn sid_for_auth_session(
    store: &RwLock<Store>,
    auth_session_id: &str,
) -> Result<Option<String>, String> {
    let store = read_lock(store, "logout_by_auth_session_id")?;
    Ok(store.sessions_by_auth_session.get(auth_session_id).cloned())
}

pub(super) fn logout_by_sid_at(
    store: &RwLock<Store>,
    sid: &str,
    now: u64,
    ttl: u64,
) -> Result<Option<OidcLogoutEvent>, String> {
    let mut store = write_lock(store, "logout_by_sid_at")?;
    prune_expired_sessions(&mut store, now, ttl);

    let (user_id, auth_session_id, jti, mut client_ids) = {
        let Some(session) = store.sessions.get_mut(sid) else {
            return Ok(None);
        };
        if session.logout_jti.is_none() {
            session.logout_jti = Some(uuid::Uuid::new_v4().to_string());
            session.logged_out_at_epoch_secs = Some(now);
        }

        let user_id = session.user_id.clone();
        let auth_session_id = session.auth_session_id.clone();
        let jti = session
            .logout_jti
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let client_ids: Vec<String> = session.clients.iter().cloned().collect();
        (user_id, auth_session_id, jti, client_ids)
    };

    if store
        .sessions_by_auth_session
        .get(&auth_session_id)
        .is_some_and(|current| current == sid)
    {
        store.sessions_by_auth_session.remove(&auth_session_id);
    }
    let remove_user_index = if let Some(user_sessions) = store.sessions_by_user.get_mut(&user_id) {
        user_sessions.remove(sid);
        user_sessions.is_empty()
    } else {
        false
    };
    if remove_user_index {
        store.sessions_by_user.remove(&user_id);
    }

    client_ids.sort();

    Ok(Some(OidcLogoutEvent {
        sid: sid.to_string(),
        user_id,
        jti,
        client_ids,
    }))
}

pub(super) fn prune_expired_at(store: &RwLock<Store>, now: u64, ttl: u64) {
    if let Ok(mut store) = write_lock(store, "prune_expired_at") {
        prune_expired_sessions(&mut store, now, ttl);
    }
}

pub(super) fn logout_by_user_at(
    store: &RwLock<Store>,
    user_id: &str,
    now: u64,
    ttl: u64,
) -> Result<Vec<OidcLogoutEvent>, String> {
    let mut sids = {
        let store = read_lock(store, "logout_by_user")?;
        store
            .sessions_by_user
            .get(user_id)
            .map(|sids| sids.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    };
    sids.sort();
    let mut events = Vec::new();
    for sid in sids {
        if let Some(event) = logout_by_sid_at(store, &sid, now, ttl)? {
            events.push(event);
        }
    }
    Ok(events)
}
