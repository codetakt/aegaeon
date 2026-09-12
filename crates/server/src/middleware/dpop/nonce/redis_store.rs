use super::{DpopEndpointRole, DpopError, DpopNonceStore, Duration, ReplayStoreError};
use crate::middleware::replay_store::{replay_key_material, ttl_millis_i64};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::sync::Arc;

// Redis TIME makes rotation independent of application-instance clocks. A
// challenge reuses the current nonce until rotation; it never extends validity.
// At most two values occupy one expiring record per namespace and endpoint role.
const ISSUE_NONCE: &str = r"
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local retention = tonumber(ARGV[3])
-- Redis cjson uses 14 significant digits; keep millisecond deadlines exact.
if retention > 99999999999999 - now then
    return redis.error_reply('nonce retention outside supported range')
end
local raw = redis.call('GET', KEYS[1])
local record = raw and cjson.decode(raw) or nil
if record and redis.call('PTTL', KEYS[1]) <= 0 then
    return redis.error_reply('nonce record has no bounded retention')
end
if record and now < record.rotate_at then return record.current end
local fresh = {current = ARGV[1], rotate_at = now + tonumber(ARGV[2]), valid_until = now + retention}
if record and now < record.valid_until then
    fresh.previous = record.current
    fresh.previous_until = record.valid_until
end
-- SET with PX is the only mutation. A rejected expiry or denied write cannot
-- leave a partially published nonce that a later request mistakes for success.
redis.call('SET', KEYS[1], cjson.encode(fresh), 'PX', ARGV[3])
return ARGV[1]
";

// Validation is read-only. Invalid requests and idle periods cannot extend a
// nonce's deadline or recreate an expired namespace.
const VALIDATE_NONCE: &str = r"
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
if redis.call('PTTL', KEYS[1]) <= 0 then
    return redis.error_reply('nonce record has no bounded retention')
end
local record = cjson.decode(raw)
if record.current == ARGV[1] and now < record.valid_until then return 1 end
if record.previous == ARGV[1] and now < record.previous_until then return 1 end
return 0
";

pub(super) struct RedisDpopNonceStore {
    client: redis::Client,
    namespace: Arc<str>,
}

impl RedisDpopNonceStore {
    pub(super) fn new(url: &str, namespace: Arc<str>) -> Result<Self, ReplayStoreError> {
        redis::Client::open(url)
            .map(|client| Self { client, namespace })
            .map_err(|err| ReplayStoreError::BackendUnavailable(err.to_string()))
    }

    fn nonce_key(&self, role: DpopEndpointRole) -> String {
        let material = replay_key_material(&[self.namespace.as_bytes()]);
        let digest = aegaeon_crypto::hash::sha256_digest(&material);
        format!(
            "dpop:nonce:v2:{}:{}",
            URL_SAFE_NO_PAD.encode(digest),
            role.nonce_scope()
        )
    }

    fn connection(&self) -> Result<redis::Connection, DpopError> {
        self.client
            .get_connection()
            .map_err(|err| DpopError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn issue_nonce(
        &self,
        role: DpopEndpointRole,
        ttl: Duration,
    ) -> Result<String, DpopError> {
        let ttl_ms =
            ttl_millis_i64(ttl).map_err(|err| DpopError::BackendUnavailable(err.to_string()))?;
        let retention_ms = ttl_ms.checked_mul(2).ok_or_else(|| {
            DpopError::BackendUnavailable(
                "DPoP nonce retention exceeds supported range".to_string(),
            )
        })?;
        redis::Script::new(ISSUE_NONCE)
            .key(self.nonce_key(role))
            .arg(DpopNonceStore::generate_nonce())
            .arg(ttl_ms)
            .arg(retention_ms)
            .invoke(&mut self.connection()?)
            .map_err(|err| DpopError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn validate_nonce(
        &self,
        role: DpopEndpointRole,
        nonce: &str,
    ) -> Result<bool, DpopError> {
        redis::Script::new(VALIDATE_NONCE)
            .key(self.nonce_key(role))
            .arg(nonce)
            .invoke::<bool>(&mut self.connection()?)
            .map_err(|err| DpopError::BackendUnavailable(err.to_string()))
    }
}

#[cfg(test)]
mod tests;
