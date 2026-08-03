use crate::device_authz::codes::normalize_user_code;
use crate::device_authz::types::DeviceCodeEntry;
use crate::device_authz::{
    read_lock, write_lock, DeviceAuthzStatus, DevicePollResult, DeviceUserCodeLookup,
    SLOW_DOWN_INCREMENT_SECS,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone)]
pub(in crate::device_authz) struct InMemoryDeviceCodeStore {
    by_hash: Arc<RwLock<HashMap<String, DeviceCodeEntry>>>,
    by_user_code: Arc<RwLock<HashMap<String, String>>>,
}

pub(super) enum InMemoryInsertResult {
    Inserted,
    Collision,
    Unavailable,
}

impl InMemoryDeviceCodeStore {
    pub(super) fn new() -> Self {
        Self {
            by_hash: Arc::new(RwLock::new(HashMap::new())),
            by_user_code: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub(super) fn insert_entry(
        &self,
        device_code_hash: &str,
        normalized_user_code: &str,
        entry: DeviceCodeEntry,
    ) -> InMemoryInsertResult {
        let Ok(mut by_hash) = write_lock(&self.by_hash, "create") else {
            return InMemoryInsertResult::Unavailable;
        };
        let Ok(mut by_user_code) = write_lock(&self.by_user_code, "create") else {
            return InMemoryInsertResult::Unavailable;
        };
        if by_hash.contains_key(device_code_hash) || by_user_code.contains_key(normalized_user_code)
        {
            return InMemoryInsertResult::Collision;
        }
        by_hash.insert(device_code_hash.to_string(), entry);
        by_user_code.insert(
            normalized_user_code.to_string(),
            device_code_hash.to_string(),
        );
        InMemoryInsertResult::Inserted
    }

    pub(super) fn poll(
        &self,
        hash: &str,
        client_id: &str,
        environment_id: Option<&str>,
        requested_resource: Option<&str>,
    ) -> DevicePollResult {
        let Ok(mut map) = write_lock(&self.by_hash, "poll") else {
            return DevicePollResult::ExpiredToken;
        };
        let Some(entry) = map.get_mut(hash) else {
            return DevicePollResult::ExpiredToken;
        };

        if entry.environment_id.as_deref() != environment_id {
            return DevicePollResult::ExpiredToken;
        }

        if entry.client_id != client_id {
            return DevicePollResult::ExpiredToken;
        }

        if SystemTime::now() >= entry.expires_at {
            let user_code_normalized = normalize_user_code(&entry.user_code);
            drop(map);
            self.remove_entry(hash, &user_code_normalized);
            return DevicePollResult::ExpiredToken;
        }

        if !resource_request_matches(entry.resource.as_deref(), requested_resource) {
            return DevicePollResult::InvalidTarget;
        }

        let now = Instant::now();
        if let Some(last) = entry.last_poll_at {
            let elapsed = now.duration_since(last);
            if elapsed < Duration::from_secs(entry.poll_interval_secs) {
                entry.poll_interval_secs = entry
                    .poll_interval_secs
                    .saturating_add(SLOW_DOWN_INCREMENT_SECS);
                entry.last_poll_at = Some(now);
                return DevicePollResult::SlowDown;
            }
        }
        entry.last_poll_at = Some(now);

        match &entry.status {
            DeviceAuthzStatus::Pending => DevicePollResult::AuthorizationPending,
            DeviceAuthzStatus::Denied => {
                let user_code_normalized = normalize_user_code(&entry.user_code);
                let hash = hash.to_string();
                drop(map);
                self.remove_entry(&hash, &user_code_normalized);
                DevicePollResult::AccessDenied
            }
            DeviceAuthzStatus::Approved { user_id, scope } => {
                if entry.consumed {
                    return DevicePollResult::ExpiredToken;
                }
                entry.consumed = true;
                let result = DevicePollResult::Approved {
                    user_id: user_id.clone(),
                    scope: scope.clone(),
                    resource: entry.resource.clone(),
                    client_id: entry.client_id.clone(),
                };
                let user_code_normalized = normalize_user_code(&entry.user_code);
                let hash = hash.to_string();
                drop(map);
                self.remove_entry(&hash, &user_code_normalized);
                result
            }
            DeviceAuthzStatus::Expired => {
                let user_code_normalized = normalize_user_code(&entry.user_code);
                let hash = hash.to_string();
                drop(map);
                self.remove_entry(&hash, &user_code_normalized);
                DevicePollResult::ExpiredToken
            }
        }
    }

    pub(super) fn approve(
        &self,
        normalized_user_code: &str,
        user_id: &str,
    ) -> Result<bool, String> {
        let hash = {
            let map = read_lock(&self.by_user_code, "approve")?;
            let Some(hash) = map.get(normalized_user_code) else {
                return Ok(false);
            };
            hash.clone()
        };

        let mut map = write_lock(&self.by_hash, "approve")?;
        let Some(entry) = map.get_mut(&hash) else {
            return Ok(false);
        };

        if SystemTime::now() >= entry.expires_at {
            return Ok(false);
        }

        if entry.status != DeviceAuthzStatus::Pending {
            return Ok(false);
        }

        entry.status = DeviceAuthzStatus::Approved {
            user_id: user_id.to_string(),
            scope: entry.scope.clone(),
        };
        Ok(true)
    }

    pub(super) fn deny(&self, normalized_user_code: &str) -> Result<bool, String> {
        let hash = {
            let map = read_lock(&self.by_user_code, "deny")?;
            let Some(hash) = map.get(normalized_user_code) else {
                return Ok(false);
            };
            hash.clone()
        };

        let mut map = write_lock(&self.by_hash, "deny")?;
        let Some(entry) = map.get_mut(&hash) else {
            return Ok(false);
        };

        if SystemTime::now() >= entry.expires_at {
            return Ok(false);
        }

        if entry.status != DeviceAuthzStatus::Pending {
            return Ok(false);
        }

        entry.status = DeviceAuthzStatus::Denied;
        Ok(true)
    }

    pub(super) fn lookup_by_user_code(
        &self,
        normalized_user_code: &str,
    ) -> Result<Option<DeviceUserCodeLookup>, String> {
        let hash = {
            let map = read_lock(&self.by_user_code, "lookup_by_user_code")?;
            let Some(hash) = map.get(normalized_user_code) else {
                return Ok(None);
            };
            hash.clone()
        };
        let map = read_lock(&self.by_hash, "lookup_by_user_code")?;
        let Some(entry) = map.get(&hash) else {
            return Ok(None);
        };

        if SystemTime::now() >= entry.expires_at {
            return Ok(None);
        }
        if entry.status != DeviceAuthzStatus::Pending {
            return Ok(None);
        }

        Ok(Some(DeviceUserCodeLookup {
            client_id: entry.client_id.clone(),
            scope: entry.scope.clone(),
            resource: entry.resource.clone(),
        }))
    }

    pub(super) fn cleanup_expired(&self) {
        let now = SystemTime::now();
        let Ok(mut by_hash) = write_lock(&self.by_hash, "cleanup_expired") else {
            return;
        };
        let Ok(mut by_user_code) = write_lock(&self.by_user_code, "cleanup_expired") else {
            return;
        };

        let expired_hashes: Vec<String> = by_hash
            .iter()
            .filter(|(_, entry)| now >= entry.expires_at)
            .map(|(hash, _)| hash.clone())
            .collect();

        for hash in &expired_hashes {
            if let Some(entry) = by_hash.remove(hash) {
                by_user_code.remove(&normalize_user_code(&entry.user_code));
            }
        }
    }

    pub(super) fn try_active_count(&self) -> Result<usize, String> {
        read_lock(&self.by_hash, "active_count").map(|entries| entries.len())
    }

    #[cfg(test)]
    pub(super) fn by_hash(&self) -> &RwLock<HashMap<String, DeviceCodeEntry>> {
        self.by_hash.as_ref()
    }

    fn remove_entry(&self, hash: &str, user_code_normalized: &str) {
        let Ok(mut by_hash) = write_lock(&self.by_hash, "remove_entry") else {
            return;
        };
        by_hash.remove(hash);
        drop(by_hash);
        let Ok(mut by_user_code) = write_lock(&self.by_user_code, "remove_entry") else {
            return;
        };
        by_user_code.remove(user_code_normalized);
    }
}

fn resource_request_matches(
    bound_resource: Option<&str>,
    requested_resource: Option<&str>,
) -> bool {
    match (bound_resource, requested_resource) {
        (Some(bound), Some(requested)) => bound == requested,
        (Some(_) | None, None) => true,
        (None, Some(_)) => false,
    }
}
