use std::collections::HashMap;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct FetchedJwks {
    pub(super) keys: Vec<FetchedJwk>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct FetchedJwk {
    pub(super) kty: String,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub(super) key_use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) key_ops: Option<Vec<String>>,
    pub(super) kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) alg: Option<String>,
    pub(super) n: Option<String>,
    pub(super) e: Option<String>,
    pub(super) x: Option<String>,
    pub(super) y: Option<String>,
    pub(super) crv: Option<String>,
}

#[derive(Clone)]
pub(super) struct CacheEntry {
    pub(super) validators: super::jwks_validators::JwksValidators,
    pub(super) effective_target: Option<String>,
    pub(super) metadata: super::jwks_cache_control::CacheMetadata,
    pub(super) freshness: super::jwks_cache_control::Freshness,
    pub(super) retain_until: std::time::Instant,
    pub(super) fetched_at: std::time::Instant,
    pub(super) jwks: FetchedJwks,
    pub(super) guard: std::sync::Arc<KidGuard>,
}

#[derive(Debug)]
pub(super) struct KidGuard {
    pub(super) kid_fps: HashMap<String, String>,
    pub(super) admitted_at: std::time::Instant,
    pub(super) deadline: std::time::Instant,
}

impl KidGuard {
    pub(super) fn live(&self, now: std::time::Instant) -> Result<bool, ()> {
        now.checked_duration_since(self.admitted_at).ok_or(())?;
        Ok(now < self.deadline)
    }

    pub(super) fn conflicts(&self, incoming: &HashMap<String, String>) -> bool {
        incoming
            .iter()
            .any(|(kid, fingerprint)| self.kid_fps.get(kid).is_some_and(|old| old != fingerprint))
    }
}
