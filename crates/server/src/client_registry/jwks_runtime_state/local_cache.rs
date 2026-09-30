use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::client_registry::jwks_types::{CacheEntry, KidGuard};

#[derive(Default)]
pub(in crate::client_registry) struct JwksLocalCache {
    pub(in crate::client_registry) representations: HashMap<String, CacheEntry>,
    pub(in crate::client_registry) guards: HashMap<String, Arc<KidGuard>>,
}

impl JwksLocalCache {
    pub(in crate::client_registry) fn prune(&mut self, now: Instant) -> Result<(), ()> {
        // Validate all time comparisons before changing security state.
        for guard in self.guards.values() {
            guard.live(now)?;
        }
        self.guards.retain(|_, guard| now < guard.deadline);
        self.representations.retain(|uri, entry| {
            now.checked_duration_since(entry.fetched_at).is_some()
                && now < entry.retain_until
                && self
                    .guards
                    .get(uri)
                    .is_some_and(|guard| Arc::ptr_eq(guard, &entry.guard))
        });
        Ok(())
    }

    pub(in crate::client_registry) fn capture(
        &mut self,
        uri: &str,
        now: Instant,
    ) -> Result<(Option<CacheEntry>, Option<Arc<KidGuard>>), ()> {
        self.prune(now)?;
        Ok((
            self.representations.get(uri).cloned(),
            self.guards.get(uri).cloned(),
        ))
    }

    pub(in crate::client_registry) fn reusable(
        &self,
        uri: &str,
        now: Instant,
    ) -> Option<&CacheEntry> {
        let entry = self.representations.get(uri)?;
        let guard = self.guards.get(uri)?;
        (Arc::ptr_eq(guard, &entry.guard)
            && guard.live(now).ok()?
            && now < entry.retain_until
            && now.checked_duration_since(entry.fetched_at).is_some()
            && entry.freshness.reusable(now))
        .then_some(entry)
    }

    pub(in crate::client_registry) fn publish(
        &mut self,
        uri: &str,
        guard: Arc<KidGuard>,
        entry: Option<CacheEntry>,
        now: Instant,
        capacity: usize,
    ) -> Result<(), ()> {
        let new_guard_live = guard.live(now)?;
        self.prune(now)?;
        // Replacement of security identity invalidates its old body atomically.
        self.representations.remove(uri);
        self.guards.remove(uri);
        if new_guard_live {
            let capacity = capacity.max(1);
            // The adopted policy evicts the least recently admitted *stored*
            // entry before insertion. A delayed incoming admission is not yet
            // a stored eviction candidate, even if its timestamp is older.
            while self.guards.len() >= capacity {
                self.evict_oldest_guard();
            }
            self.guards.insert(uri.to_owned(), guard);
            if let Some(entry) = entry.filter(|entry| now < entry.retain_until) {
                while self.representations.len() >= capacity {
                    self.evict_oldest_body();
                }
                self.representations.insert(uri.to_owned(), entry);
            }
        }
        self.prune_to_capacity(capacity);
        Ok(())
    }

    pub(in crate::client_registry) fn prune_to_capacity(&mut self, capacity: usize) {
        let capacity = capacity.max(1);
        while self.guards.len() > capacity {
            self.evict_oldest_guard();
        }
        while self.representations.len() > capacity {
            self.evict_oldest_body();
        }
    }

    fn evict_oldest_guard(&mut self) {
        if let Some(key) = self
            .guards
            .iter()
            .min_by(|(ka, a), (kb, b)| a.admitted_at.cmp(&b.admitted_at).then_with(|| ka.cmp(kb)))
            .map(|(key, _)| key.clone())
        {
            self.guards.remove(&key);
            self.representations.remove(&key);
        }
    }

    fn evict_oldest_body(&mut self) {
        if let Some(key) = self
            .representations
            .iter()
            .min_by(|(ka, a), (kb, b)| a.fetched_at.cmp(&b.fetched_at).then_with(|| ka.cmp(kb)))
            .map(|(key, _)| key.clone())
        {
            self.representations.remove(&key);
        }
    }

    // Controlled fixture insertion establishes the same body/guard identity.
    // Test removals through DerefMut remove only body state, as independently
    // permitted GC/eviction does. Production has no unchecked insertion API.
    #[cfg(any(test, kani))]
    pub(in crate::client_registry) fn insert(
        &mut self,
        uri: String,
        entry: CacheEntry,
    ) -> Option<CacheEntry> {
        self.guards.insert(uri.clone(), entry.guard.clone());
        self.representations.insert(uri, entry)
    }
}

#[cfg(any(test, kani))]
impl std::ops::Deref for JwksLocalCache {
    type Target = HashMap<String, CacheEntry>;
    fn deref(&self) -> &Self::Target {
        &self.representations
    }
}
#[cfg(any(test, kani))]
impl std::ops::DerefMut for JwksLocalCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.representations
    }
}
