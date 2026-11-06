use super::*;
use crate::organizations::request_work::async_store::{current_owner, task_owner};
impl NativeJwksRuntime {
    pub(super) fn schedule_refresh(self: &Arc<Self>, uri: &str) {
        let owner = match current_owner() {
            Ok(owner) => Some(owner),
            Err(_) => match task_owner() {
                Ok(None) => None,
                _ => return,
            },
        };
        let Ok(mut tasks) = self.background.try_lock() else {
            return;
        };
        while tasks.try_join_next().is_some() {}
        if tasks.len() >= 32 {
            return;
        }
        let Ok(mut active) = self.background_uris.lock() else {
            return;
        };
        if !active.insert(uri.to_string()) {
            return;
        }
        drop(active);
        let marker = Marker {
            uris: self.background_uris.clone(),
            uri: uri.to_string(),
        };
        let runtime = self.clone();
        let uri = uri.to_string();
        tasks.spawn(async move {
            let refresh = async {
                let candidate = runtime.cache_guard().capture(&uri, Instant::now());
                let _ = runtime.refresh_candidate(&uri, candidate).await;
            };
            if let Some(owner) = owner {
                let _ = owner.store_scope(refresh).await;
            } else {
                refresh.await;
            }
            drop(marker);
        });
    }
}

struct Marker {
    uris: Arc<Mutex<std::collections::HashSet<String>>>,
    uri: String,
}
impl Drop for Marker {
    fn drop(&mut self) {
        if let Ok(mut active) = self.uris.lock() {
            active.remove(&self.uri);
        }
    }
}
