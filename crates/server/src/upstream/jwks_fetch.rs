use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;

pub(crate) const JWKS_FETCH_COOLDOWN: Duration = Duration::from_secs(30);
pub(crate) type JwksFetchSlot = Arc<AsyncMutex<Option<Instant>>>;

/// Process-local retrieval admission, separate from the non-authoritative key cache.
pub struct UpstreamJwksFetchCoordinator {
    entries: Mutex<HashMap<String, JwksFetchSlot>>,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl Default for UpstreamJwksFetchCoordinator {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            clock: Arc::new(Instant::now),
        }
    }
}

impl UpstreamJwksFetchCoordinator {
    pub(crate) fn now(&self) -> Instant {
        (self.clock)()
    }

    pub(crate) fn slot(&self, url: &str, max_entries: usize) -> Result<JwksFetchSlot, String> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "upstream jwks retrieval unavailable".to_string())?;
        if let Some(slot) = entries.get(url) {
            return Ok(Arc::clone(slot));
        }
        let now = self.now();
        entries.retain(|_, slot| {
            // A caller retains its reference from map lookup through lock acquisition and I/O.
            // Removing such a slot would permit another coordinator for the same URL.
            if Arc::strong_count(slot) != 1 {
                return true;
            }
            let Ok(last_attempt) = slot.try_lock() else {
                return true;
            };
            last_attempt.is_some_and(|start| now.duration_since(start) < JWKS_FETCH_COOLDOWN)
        });
        if entries.len() >= max_entries {
            return Err("upstream jwks retrieval capacity exhausted".to_string());
        }
        let slot = Arc::new(AsyncMutex::new(None));
        entries.insert(url.to_string(), Arc::clone(&slot));
        Ok(slot)
    }

    #[cfg(test)]
    pub(crate) fn with_clock(clock: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        Self {
            clock,
            ..Self::default()
        }
    }
}
