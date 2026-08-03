use std::collections::HashMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use tracing::info;

use super::{
    AuthCodeBackend, AuthCodeSnapshot, AuthCodeStorageError, AuthorizationCode, StoreCodeError,
};

#[derive(Default)]
struct AuthCodeStoreState {
    codes: HashMap<String, AuthorizationCode>,
    used_states: HashMap<String, Instant>,
    used_nonces: HashMap<String, Instant>,
    version: u64,
}

pub(in crate::authcode) struct InMemoryAuthCodeBackend {
    state: RwLock<AuthCodeStoreState>,
    state_nonce_ttl: Duration,
}

impl InMemoryAuthCodeBackend {
    pub(in crate::authcode) fn new(state_nonce_ttl: Duration) -> Self {
        Self {
            state: RwLock::new(AuthCodeStoreState::default()),
            state_nonce_ttl,
        }
    }

    fn read_state(&self) -> Result<RwLockReadGuard<'_, AuthCodeStoreState>, AuthCodeStorageError> {
        self.state
            .read()
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))
    }

    fn write_state(
        &self,
    ) -> Result<RwLockWriteGuard<'_, AuthCodeStoreState>, AuthCodeStorageError> {
        self.state
            .write()
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))
    }

    fn cleanup_state_nonce_locked(&self, state: &mut AuthCodeStoreState, now: Instant) -> bool {
        let before_states = state.used_states.len();
        state
            .used_states
            .retain(|_, inserted| now.duration_since(*inserted) <= self.state_nonce_ttl);
        let before_nonces = state.used_nonces.len();
        state
            .used_nonces
            .retain(|_, inserted| now.duration_since(*inserted) <= self.state_nonce_ttl);
        before_states != state.used_states.len() || before_nonces != state.used_nonces.len()
    }

    fn cleanup_expired_codes_locked(state: &mut AuthCodeStoreState) -> bool {
        let before_codes = state.codes.len();
        state.codes.retain(|_, code| !code.is_expired());
        state.codes.len() != before_codes
    }
}

impl AuthCodeBackend for InMemoryAuthCodeBackend {
    #[cfg(test)]
    fn snapshot(&self) -> Result<AuthCodeSnapshot, AuthCodeStorageError> {
        let state = self.read_state()?;
        Ok(AuthCodeSnapshot {
            codes: state.codes.clone(),
            used_states: state.used_states.keys().cloned().collect(),
            used_nonces: state.used_nonces.keys().cloned().collect(),
            version: state.version,
        })
    }

    fn get_code(&self, code_str: &str) -> Result<Option<AuthorizationCode>, AuthCodeStorageError> {
        let state = self.read_state()?;
        let Some(code) = state.codes.get(code_str) else {
            return Ok(None);
        };
        Ok((!code.used && !code.is_expired()).then(|| code.clone()))
    }

    fn store_code(&self, code: AuthorizationCode) -> Result<String, StoreCodeError> {
        if code.is_expired() {
            return Err(StoreCodeError::Expired);
        }

        let now = Instant::now();
        let mut state = self.write_state()?;
        let state_nonce_cleanup_changed = self.cleanup_state_nonce_locked(&mut state, now);
        let code_cleanup_changed = Self::cleanup_expired_codes_locked(&mut state);
        let cleanup_changed = state_nonce_cleanup_changed || code_cleanup_changed;

        if code
            .state
            .as_ref()
            .is_some_and(|state_value| state.used_states.contains_key(state_value))
        {
            if cleanup_changed {
                state.version = state.version.saturating_add(1);
            }
            return Err(StoreCodeError::StateUsed);
        }
        if code
            .nonce
            .as_ref()
            .is_some_and(|nonce_value| state.used_nonces.contains_key(nonce_value))
        {
            if cleanup_changed {
                state.version = state.version.saturating_add(1);
            }
            return Err(StoreCodeError::NonceUsed);
        }
        if state.codes.contains_key(&code.code) {
            if cleanup_changed {
                state.version = state.version.saturating_add(1);
            }
            return Err(StoreCodeError::CodeCollision);
        }

        if let Some(state_value) = code.state.as_ref() {
            state.used_states.insert(state_value.clone(), now);
        }
        if let Some(nonce_value) = code.nonce.as_ref() {
            state.used_nonces.insert(nonce_value.clone(), now);
        }
        let code_str = code.code.clone();
        state.codes.insert(code_str.clone(), code);
        state.version = state.version.saturating_add(1);
        Ok(code_str)
    }

    fn use_code(&self, code_str: &str) -> Result<Option<AuthorizationCode>, AuthCodeStorageError> {
        let mut state = self.write_state()?;
        let Some(code) = state.codes.get_mut(code_str) else {
            return Ok(None);
        };
        if code.used {
            return Ok(None);
        }
        if code.is_expired() {
            state.codes.remove(code_str);
            state.version = state.version.saturating_add(1);
            return Ok(None);
        }

        code.mark_used();
        let used_code = code.clone();
        state.version = state.version.saturating_add(1);
        Ok(Some(used_code))
    }

    #[cfg(test)]
    fn use_code_if_payload_matches(
        &self,
        code_str: &str,
        expected_payload: &str,
    ) -> Result<Option<AuthorizationCode>, AuthCodeStorageError> {
        let mut state = self.write_state()?;
        let Some(code) = state.codes.get_mut(code_str) else {
            return Ok(None);
        };
        if code.used {
            return Ok(None);
        }
        if code.is_expired() {
            state.codes.remove(code_str);
            state.version = state.version.saturating_add(1);
            return Ok(None);
        }

        let current_payload = serde_json::to_string(code)
            .map_err(|err| AuthCodeStorageError::Serialize(err.to_string()))?;
        if current_payload != expected_payload {
            return Err(AuthCodeStorageError::PayloadMismatch);
        }

        code.mark_used();
        let used_code = code.clone();
        state.version = state.version.saturating_add(1);
        Ok(Some(used_code))
    }

    fn cleanup_expired(&self) -> Result<(), AuthCodeStorageError> {
        let now = Instant::now();
        let mut state = self.write_state()?;
        let mut changed = false;

        changed |= Self::cleanup_expired_codes_locked(&mut state);

        let before_states = state.used_states.len();
        state
            .used_states
            .retain(|_, inserted| now.duration_since(*inserted) <= self.state_nonce_ttl);
        if state.used_states.len() != before_states {
            changed = true;
            info!(target: "authcode", removed = before_states - state.used_states.len(), "expired states cleaned up");
        }

        let before_nonces = state.used_nonces.len();
        state
            .used_nonces
            .retain(|_, inserted| now.duration_since(*inserted) <= self.state_nonce_ttl);
        if state.used_nonces.len() != before_nonces {
            changed = true;
            info!(target: "authcode", removed = before_nonces - state.used_nonces.len(), "expired nonces cleaned up");
        }

        if changed {
            state.version = state.version.saturating_add(1);
        }
        Ok(())
    }

    fn state_count(&self) -> Result<usize, AuthCodeStorageError> {
        Ok(self.read_state()?.used_states.len())
    }

    fn nonce_count(&self) -> Result<usize, AuthCodeStorageError> {
        Ok(self.read_state()?.used_nonces.len())
    }
}
