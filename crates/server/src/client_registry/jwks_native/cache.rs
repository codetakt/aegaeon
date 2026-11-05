use super::*;
use std::collections::BTreeMap;

// An accounting bound, not an allocator/RSS measurement. Bodies charge 16 times
// their bounded wire length; metadata and URI storage are charged separately.
const MAX_CHARGE: usize = 64 * 1024 * 1024;
#[derive(Default)]
pub(super) struct BodyCache {
    entries: BTreeMap<String, Arc<Entry>>,
    charge: usize,
}
impl BodyCache {
    pub(super) fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            now.checked_duration_since(entry.admitted_at).is_some() && now < entry.retain_until
        });
        self.charge = self.entries.values().map(|e| e.charge).sum();
    }
    fn remove(&mut self, uri: &str) {
        if let Some(old) = self.entries.remove(uri) {
            self.charge = self.charge.saturating_sub(old.charge);
        }
    }
    pub(super) fn capture(&mut self, uri: &str, now: Instant) -> Option<Arc<Entry>> {
        let entry = self.entries.get(uri)?;
        if now.checked_duration_since(entry.admitted_at).is_none() || now >= entry.retain_until {
            self.remove(uri);
            return None;
        }
        Some(entry.clone())
    }
    pub(super) fn publish(
        &mut self,
        uri: &str,
        entry: Option<Arc<Entry>>,
        now: Instant,
        capacity: usize,
    ) {
        self.remove(uri);
        let Some(entry) = entry.filter(|v| v.charge <= MAX_CHARGE && now < v.retain_until) else {
            return;
        };
        while self.entries.len() >= capacity.max(1)
            || self.charge.saturating_add(entry.charge) > MAX_CHARGE
        {
            let Some(key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.admitted_at)
                .map(|(k, _)| k.clone())
            else {
                return;
            };
            self.remove(&key);
        }
        self.charge += entry.charge;
        self.entries.insert(uri.into(), entry);
    }
}
