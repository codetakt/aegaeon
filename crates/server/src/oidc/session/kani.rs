use super::{
    normalize_logout_session_ttl_secs, OidcLogoutEvent, OidcSessionContext, OidcSessionGrantCommit,
};
use crate::config::ConfigError;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

const MAX_SESSIONS: usize = 4;
const MAX_CLIENTS_PER_SESSION: usize = 4;

#[derive(Clone)]
pub struct OidcSessionStore(Arc<RwLock<Store>>);

#[cfg(kani)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundedKaniLogoutEvent {
    pub sid: u8,
    pub user_id: u8,
    pub jti: u8,
    pub client_ids: [Option<u8>; MAX_CLIENTS_PER_SESSION],
}

#[cfg(kani)]
#[derive(Clone, Copy)]
struct BoundedKaniSession {
    sid: u8,
    user_id: u8,
    auth_session_id: u8,
    clients: [Option<u8>; MAX_CLIENTS_PER_SESSION],
    logout_jti: Option<u8>,
    logged_out_at_epoch_secs: Option<u64>,
}

#[cfg(kani)]
pub(crate) struct BoundedKaniSessionStore {
    sessions_by_auth_session: [Option<(u8, u8)>; MAX_SESSIONS],
    sessions: [Option<BoundedKaniSession>; MAX_SESSIONS],
    logout_session_ttl_secs: u64,
    next_sid: u8,
    next_jti: u8,
}

#[derive(Clone)]
struct Store {
    sessions_by_auth_session: FixedMap<MAX_SESSIONS, String>,
    sessions: FixedMap<MAX_SESSIONS, Session>,
    logout_session_ttl_secs: u64,
    next_sid: u64,
    next_jti: u64,
}

#[derive(Clone, Default)]
struct Session {
    user_id: String,
    auth_session_id: String,
    clients: FixedSet<MAX_CLIENTS_PER_SESSION>,
    logout_jti: Option<String>,
    logged_out_at_epoch_secs: Option<u64>,
}

impl Store {
    fn new(logout_session_ttl_secs: u64) -> Self {
        Self {
            sessions_by_auth_session: FixedMap::new(),
            sessions: FixedMap::new(),
            logout_session_ttl_secs: normalize_logout_session_ttl_secs(logout_session_ttl_secs),
            next_sid: 1,
            next_jti: 1,
        }
    }

    fn next_sid(&mut self) -> String {
        let sid = self.next_sid;
        self.next_sid = self.next_sid.saturating_add(1);
        format!("sid-{}", sid)
    }

    fn next_jti(&mut self) -> String {
        let jti = self.next_jti;
        self.next_jti = self.next_jti.saturating_add(1);
        format!("jti-{}", jti)
    }
}

fn logged_out_session_expired(logged_out_at: u64, now: u64, ttl: u64) -> bool {
    logged_out_at > now || now.saturating_sub(logged_out_at) >= ttl
}

#[cfg(kani)]
impl BoundedKaniSessionStore {
    pub(crate) fn new_with_ttl(logout_session_ttl_secs: u64) -> Self {
        Self {
            sessions_by_auth_session: [None; MAX_SESSIONS],
            sessions: [None; MAX_SESSIONS],
            logout_session_ttl_secs: normalize_logout_session_ttl_secs(logout_session_ttl_secs),
            next_sid: 1,
            next_jti: 1,
        }
    }

    fn next_sid(&mut self) -> Option<u8> {
        let sid = self.next_sid;
        self.next_sid = self.next_sid.checked_add(1)?;
        Some(sid)
    }

    fn next_jti(&mut self) -> Option<u8> {
        let jti = self.next_jti;
        self.next_jti = self.next_jti.checked_add(1)?;
        Some(jti)
    }

    fn session_index(&self, sid: u8) -> Option<usize> {
        let mut idx = 0;
        while idx < MAX_SESSIONS {
            if let Some(session) = self.sessions[idx] {
                if session.sid == sid {
                    return Some(idx);
                }
            }
            idx += 1;
        }
        None
    }

    fn auth_session_sid(&self, auth_session_id: u8) -> Option<u8> {
        let mut idx = 0;
        while idx < MAX_SESSIONS {
            if let Some((stored_auth_session, sid)) = self.sessions_by_auth_session[idx] {
                if stored_auth_session == auth_session_id {
                    return Some(sid);
                }
            }
            idx += 1;
        }
        None
    }

    fn set_auth_session_sid(&mut self, auth_session_id: u8, sid: u8) -> bool {
        let mut first_empty = None;
        let mut idx = 0;
        while idx < MAX_SESSIONS {
            match self.sessions_by_auth_session[idx] {
                Some((stored_auth_session, _)) if stored_auth_session == auth_session_id => {
                    self.sessions_by_auth_session[idx] = Some((auth_session_id, sid));
                    return true;
                }
                None if first_empty.is_none() => first_empty = Some(idx),
                _ => {}
            }
            idx += 1;
        }
        let Some(empty_idx) = first_empty else {
            return false;
        };
        self.sessions_by_auth_session[empty_idx] = Some((auth_session_id, sid));
        true
    }

    fn remove_auth_session_if_current(&mut self, auth_session_id: u8, sid: u8) {
        let mut idx = 0;
        while idx < MAX_SESSIONS {
            if self.sessions_by_auth_session[idx] == Some((auth_session_id, sid)) {
                self.sessions_by_auth_session[idx] = None;
            }
            idx += 1;
        }
    }

    fn remove_session(&mut self, sid: u8) {
        if let Some(idx) = self.session_index(sid) {
            self.sessions[idx] = None;
        }
    }

    fn upsert_session(&mut self, session: BoundedKaniSession) -> bool {
        if let Some(idx) = self.session_index(session.sid) {
            self.sessions[idx] = Some(session);
            return true;
        }

        let mut first_empty = None;
        let mut idx = 0;
        while idx < MAX_SESSIONS {
            if self.sessions[idx].is_none() && first_empty.is_none() {
                first_empty = Some(idx);
            }
            idx += 1;
        }
        let Some(empty_idx) = first_empty else {
            return false;
        };
        self.sessions[empty_idx] = Some(session);
        true
    }

    fn client_ids(session: &BoundedKaniSession) -> [Option<u8>; MAX_CLIENTS_PER_SESSION] {
        session.clients
    }

    pub(crate) fn mapped_sid(&self, auth_session_id: u8) -> Option<u8> {
        self.auth_session_sid(auth_session_id)
    }

    pub(crate) fn session_exists(&self, sid: u8) -> bool {
        self.session_index(sid)
            .is_some_and(|idx| self.sessions[idx].is_some())
    }

    pub(crate) fn client_ids_for(&self, sid: u8) -> Option<[Option<u8>; MAX_CLIENTS_PER_SESSION]> {
        let idx = self.session_index(sid)?;
        self.sessions[idx].map(|session| session.clients)
    }

    pub(crate) fn get_or_create_session(&mut self, user_id: u8, auth_session_id: u8) -> Option<u8> {
        self.prune_expired_at(0);
        if let Some(sid) = self.auth_session_sid(auth_session_id) {
            if let Some(idx) = self.session_index(sid) {
                if self.sessions[idx].is_some_and(|session| session.logout_jti.is_none()) {
                    return Some(sid);
                }
            }
        }

        let sid = self.next_sid()?;
        if !self.upsert_session(BoundedKaniSession {
            sid,
            user_id,
            auth_session_id,
            clients: [None; MAX_CLIENTS_PER_SESSION],
            logout_jti: None,
            logged_out_at_epoch_secs: None,
        }) {
            return None;
        }
        if !self.set_auth_session_sid(auth_session_id, sid) {
            self.remove_session(sid);
            return None;
        }
        Some(sid)
    }

    pub(crate) fn add_client(&mut self, sid: u8, client_id: u8) -> bool {
        self.prune_expired_at(0);
        let Some(idx) = self.session_index(sid) else {
            return false;
        };
        let Some(mut session) = self.sessions[idx] else {
            return false;
        };
        if session.logout_jti.is_some() {
            return false;
        }

        let mut first_empty = None;
        let mut client_idx = 0;
        while client_idx < MAX_CLIENTS_PER_SESSION {
            match session.clients[client_idx] {
                Some(existing) if existing == client_id => return true,
                None if first_empty.is_none() => first_empty = Some(client_idx),
                _ => {}
            }
            client_idx += 1;
        }
        let Some(empty_idx) = first_empty else {
            return false;
        };
        session.clients[empty_idx] = Some(client_id);
        self.sessions[idx] = Some(session);
        true
    }

    pub(crate) fn logout_by_sid_at(
        &mut self,
        sid: u8,
        now_epoch_secs: u64,
    ) -> Option<BoundedKaniLogoutEvent> {
        self.prune_expired_at(now_epoch_secs);
        let idx = self.session_index(sid)?;
        let mut session = self.sessions[idx]?;
        if session.logout_jti.is_none() {
            let candidate_jti = self.next_jti()?;
            session.logout_jti = Some(candidate_jti);
            session.logged_out_at_epoch_secs = Some(now_epoch_secs);
        }
        self.sessions[idx] = Some(session);
        self.remove_auth_session_if_current(session.auth_session_id, sid);

        Some(BoundedKaniLogoutEvent {
            sid,
            user_id: session.user_id,
            jti: session.logout_jti?,
            client_ids: Self::client_ids(&session),
        })
    }

    pub(crate) fn prune_expired_at(&mut self, now_epoch_secs: u64) {
        let ttl = self.logout_session_ttl_secs;
        let mut idx = 0;
        while idx < MAX_SESSIONS {
            let remove = self.sessions[idx].is_some_and(|session| {
                session.logout_jti.is_some()
                    && session
                        .logged_out_at_epoch_secs
                        .is_some_and(|logged_out_at| {
                            logged_out_session_expired(logged_out_at, now_epoch_secs, ttl)
                        })
            });
            if remove {
                self.sessions[idx] = None;
            }
            idx += 1;
        }

        let mut auth_session_idx = 0;
        while auth_session_idx < MAX_SESSIONS {
            if let Some((_, sid)) = self.sessions_by_auth_session[auth_session_idx] {
                if self.session_index(sid).is_none() {
                    self.sessions_by_auth_session[auth_session_idx] = None;
                }
            }
            auth_session_idx += 1;
        }
    }

    pub(crate) fn logout_by_user(&mut self, user_id: u8) -> Option<BoundedKaniLogoutEvent> {
        let mut idx = 0;
        while idx < MAX_SESSIONS {
            if let Some(session) = self.sessions[idx] {
                if session.user_id == user_id && session.logout_jti.is_none() {
                    return self.logout_by_sid_at(session.sid, 0);
                }
            }
            idx += 1;
        }
        None
    }
}

fn read_lock<T>(lock: &RwLock<T>) -> Result<RwLockReadGuard<'_, T>, String> {
    lock.read().map_err(|err| {
        let message = format!("OIDC session store read lock poisoned: {err}");
        tracing::error!(error = %err, "OIDC session store read lock poisoned");
        message
    })
}

fn write_lock<T>(lock: &RwLock<T>) -> Result<RwLockWriteGuard<'_, T>, String> {
    lock.write().map_err(|err| {
        let message = format!("OIDC session store write lock poisoned: {err}");
        tracing::error!(error = %err, "OIDC session store write lock poisoned");
        message
    })
}

#[derive(Clone)]
struct FixedSet<const N: usize> {
    entries: [Option<String>; N],
}

impl<const N: usize> Default for FixedSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FixedSet<N> {
    fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
        }
    }

    fn insert(&mut self, value: String) -> bool {
        if self
            .entries
            .iter()
            .any(|existing| existing.as_deref() == Some(value.as_str()))
        {
            return true;
        }
        if let Some(slot) = self.entries.iter_mut().find(|e| e.is_none()) {
            *slot = Some(value);
            return true;
        }
        false
    }

    fn iter(&self) -> impl Iterator<Item = &String> {
        self.entries.iter().filter_map(|v| v.as_ref())
    }
}

#[derive(Clone)]
struct FixedMap<const N: usize, V> {
    entries: [Option<(String, V)>; N],
}

impl<const N: usize, V> FixedMap<N, V> {
    fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
        }
    }

    fn get(&self, key: &str) -> Option<&V> {
        self.entries
            .iter()
            .find_map(|entry| entry.as_ref().filter(|(k, _)| k == key).map(|(_, v)| v))
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.entries
            .iter_mut()
            .find_map(|entry| entry.as_mut().filter(|(k, _)| k == key).map(|(_, v)| v))
    }

    fn insert(&mut self, key: String, value: V) -> bool {
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|(existing, _)| existing == &key))
        {
            *slot = Some((key, value));
            return true;
        }

        if let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) {
            *slot = Some((key, value));
            return true;
        }

        false
    }

    fn remove(&mut self, key: &str) -> Option<V> {
        let pos = self
            .entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|(existing, _)| existing == key))?;
        self.entries[pos].take().map(|(_, v)| v)
    }

    fn retain(&mut self, mut keep: impl FnMut(&String, &V) -> bool) {
        for entry in &mut self.entries {
            if let Some((k, v)) = entry.as_ref() {
                if !keep(k, v) {
                    *entry = None;
                }
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.entries
            .iter()
            .filter_map(|entry| entry.as_ref().map(|(k, v)| (k, v)))
    }
}

fn prune_expired_sessions(store: &mut Store, now: u64) {
    let ttl = store.logout_session_ttl_secs;
    if ttl == 0 {
        return;
    }

    let _ = store.sessions.iter().count();

    for entry in store.sessions.entries.iter_mut() {
        let remove = match entry.as_ref() {
            Some((_, session)) => match session.logged_out_at_epoch_secs {
                Some(logged_out_at) => {
                    session.logout_jti.is_some()
                        && logged_out_session_expired(logged_out_at, now, ttl)
                }
                None => false,
            },
            None => false,
        };
        if remove {
            *entry = None;
        }
    }

    store
        .sessions_by_auth_session
        .retain(|_, sid| store.sessions.get(sid).is_some());
}

impl OidcSessionStore {
    fn new_process_local_with_ttl(logout_session_ttl_secs: u64) -> Self {
        Self(Arc::new(RwLock::new(Store::new(logout_session_ttl_secs))))
    }

    #[cfg(test)]
    pub fn new_process_local_for_tests() -> Self {
        Self::new_process_local_with_ttl(super::DEFAULT_LOGOUT_SESSION_TTL_SECS)
    }

    #[cfg(test)]
    pub fn new_process_local_with_ttl_for_tests(logout_session_ttl_secs: u64) -> Self {
        Self::new_process_local_with_ttl(logout_session_ttl_secs)
    }

    pub fn try_new_from_shared_store_env_with_ttl_secs(
        logout_session_ttl_secs: u64,
        _runtime_state_namespace: &crate::config::RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        Ok(Self::new_process_local_with_ttl(logout_session_ttl_secs))
    }

    /// Try to get the current session ID for the browser/auth session or create a new one.
    pub fn try_get_or_create_session(
        &self,
        context: OidcSessionContext<'_>,
    ) -> Result<String, String> {
        let mut store = write_lock(&self.0)?;
        prune_expired_sessions(&mut store, 0);

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

        let sid = store.next_sid();
        if !store.sessions.insert(
            sid.clone(),
            Session {
                user_id: context.user_id.to_string(),
                auth_session_id: context.auth_session_id.to_string(),
                ..Default::default()
            },
        ) {
            return Err("bounded OIDC session store capacity exhausted".to_string());
        }
        if !store
            .sessions_by_auth_session
            .insert(context.auth_session_id.to_string(), sid.clone())
        {
            store.sessions.remove(&sid);
            return Err("bounded OIDC session auth-session index capacity exhausted".to_string());
        }
        Ok(sid)
    }

    pub(crate) fn prepare_authorization_code_grant_commit(
        &self,
        context: OidcSessionContext<'_>,
        client_id: &str,
    ) -> Result<OidcSessionGrantCommit, String> {
        if client_id.is_empty() {
            return Err("OIDC session client_id must not be blank".to_string());
        }
        let sid = self.try_get_or_create_session(context)?;
        match self.try_add_client(&sid, client_id)? {
            true => Ok(OidcSessionGrantCommit::process_local_for_tests(sid)),
            false => Err("OIDC session client association failed".to_string()),
        }
    }

    pub(crate) async fn prepare_authorization_code_grant_commit_async(
        &self,
        context: OidcSessionContext<'_>,
        client_id: &str,
    ) -> Result<OidcSessionGrantCommit, String> {
        self.prepare_authorization_code_grant_commit(context, client_id)
    }

    /// Get the current session ID for the user or create a new one.
    pub fn get_or_create_session(&self, user_id: &str, auth_session_id: &str) -> String {
        self.try_get_or_create_session(OidcSessionContext {
            user_id,
            auth_session_id,
        })
        .unwrap_or_else(|err| {
            tracing::error!(
                error = %err,
                "bounded OIDC session model failed to allocate a session"
            );
            String::new()
        })
    }

    /// Try to associate a client with an existing live session.
    pub fn try_add_client(&self, sid: &str, client_id: &str) -> Result<bool, String> {
        let mut store = write_lock(&self.0)?;
        prune_expired_sessions(&mut store, 0);

        let Some(session) = store.sessions.get_mut(sid) else {
            return Ok(false);
        };
        if session.logout_jti.is_some() {
            return Ok(false);
        }
        Ok(session.clients.insert(client_id.to_string()))
    }

    /// Associate a client with an existing session.
    pub fn add_client(&self, sid: &str, client_id: &str) {
        self.try_add_client(sid, client_id).unwrap_or_else(|err| {
            tracing::error!(error = %err, "bounded OIDC session model add_client failed");
            false
        });
    }

    /// Log out a session. Returns the logout event (idempotent per session).
    pub fn try_logout_by_sid(&self, sid: &str) -> Result<Option<OidcLogoutEvent>, String> {
        self.try_logout_by_sid_at(sid, 0)
    }

    /// Async facade mirroring the production store; the bounded model has no
    /// blocking backend, so it delegates to the synchronous path directly.
    pub async fn try_logout_by_sid_async(
        &self,
        sid: String,
    ) -> Result<Option<OidcLogoutEvent>, String> {
        self.try_logout_by_sid(&sid)
    }

    /// Log out the OIDC session linked to an auth-session id.
    pub fn try_logout_by_auth_session_id(
        &self,
        auth_session_id: &str,
    ) -> Result<Option<OidcLogoutEvent>, String> {
        let sid = {
            let store = read_lock(&self.0)?;
            store.sessions_by_auth_session.get(auth_session_id).cloned()
        };
        sid.map_or(Ok(None), |sid| self.try_logout_by_sid_at(&sid, 0))
    }

    /// Async facade mirroring the production store; the bounded model has no
    /// blocking backend, so it delegates to the synchronous path directly.
    pub async fn try_logout_by_auth_session_id_async(
        &self,
        auth_session_id: String,
    ) -> Result<Option<OidcLogoutEvent>, String> {
        self.try_logout_by_auth_session_id(&auth_session_id)
    }

    /// Log out a session. Returns the logout event (idempotent per session).
    pub fn logout_by_sid(&self, sid: &str) -> Option<OidcLogoutEvent> {
        self.logout_by_sid_at(sid, 0)
    }

    /// Log out a session at the supplied timestamp. Intended for Kani harnesses.
    pub(crate) fn try_logout_by_sid_at(
        &self,
        sid: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<OidcLogoutEvent>, String> {
        let mut store = write_lock(&self.0)?;
        prune_expired_sessions(&mut store, now_epoch_secs);

        let candidate_jti = store.next_jti();
        let (user_id, auth_session_id, jti, client_ids) = {
            let Some(session) = store.sessions.get_mut(sid) else {
                return Ok(None);
            };
            if session.logout_jti.is_none() {
                session.logout_jti = Some(candidate_jti.clone());
                session.logged_out_at_epoch_secs = Some(now_epoch_secs);
            }

            let user_id = session.user_id.clone();
            let auth_session_id = session.auth_session_id.clone();
            let jti = session.logout_jti.clone().unwrap_or(candidate_jti.clone());
            let _ = session.clients.iter().count();
            let mut client_ids: Vec<String> = Vec::new();
            for slot in session.clients.entries.iter() {
                if let Some(client_id) = slot.as_ref() {
                    client_ids.push(client_id.clone());
                }
            }
            (user_id, auth_session_id, jti, client_ids)
        };

        if store
            .sessions_by_auth_session
            .get(&auth_session_id)
            .is_some_and(|current| current == sid)
        {
            store.sessions_by_auth_session.remove(&auth_session_id);
        }

        Ok(Some(OidcLogoutEvent {
            sid: sid.to_string(),
            user_id,
            jti,
            client_ids,
        }))
    }

    /// Log out a session at the supplied timestamp. Intended for Kani harnesses.
    pub(crate) fn logout_by_sid_at(
        &self,
        sid: &str,
        now_epoch_secs: u64,
    ) -> Option<OidcLogoutEvent> {
        self.try_logout_by_sid_at(sid, now_epoch_secs)
            .unwrap_or_else(|err| {
                tracing::error!(error = %err, "bounded OIDC session model logout failed");
                None
            })
    }

    #[allow(dead_code)]
    pub(crate) fn prune_expired_at(&self, now_epoch_secs: u64) {
        if let Ok(mut store) = write_lock(&self.0) {
            prune_expired_sessions(&mut store, now_epoch_secs);
        }
    }

    /// Log out all current sessions for a user.
    pub fn try_logout_by_user(&self, user_id: &str) -> Result<Vec<OidcLogoutEvent>, String> {
        let mut sids = {
            let store = read_lock(&self.0)?;
            store
                .sessions
                .iter()
                .filter_map(|(sid, session)| {
                    (session.user_id == user_id && session.logout_jti.is_none())
                        .then(|| sid.clone())
                })
                .collect::<Vec<_>>()
        };
        sids.sort();
        let mut events = Vec::new();
        for sid in sids {
            if let Some(event) = self.try_logout_by_sid(&sid)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    /// Async facade mirroring the production store; the bounded model has no
    /// blocking backend, so it delegates to the synchronous path directly.
    pub async fn try_logout_by_user_async(
        &self,
        user_id: String,
    ) -> Result<Vec<OidcLogoutEvent>, String> {
        self.try_logout_by_user(&user_id)
    }

    /// Log out all current sessions for a user.
    pub fn logout_by_user(&self, user_id: &str) -> Vec<OidcLogoutEvent> {
        self.try_logout_by_user(user_id).unwrap_or_else(|err| {
            tracing::error!(error = %err, "bounded OIDC session model logout_by_user failed");
            Vec::new()
        })
    }
}
