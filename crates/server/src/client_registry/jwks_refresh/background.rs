use super::super::jwks_circuit::record_jwks_in_memory_runtime_state_failure;
#[cfg(test)]
use super::super::jwks_runtime_state;
use super::super::jwks_runtime_state::JwksRuntimeState;
use super::super::JwksRuntimePolicy;
use super::refresh_jwks_with_state;
use crate::organizations::request_work::async_store::{current_owner, task_owner};

struct RefreshMarker {
    state: JwksRuntimeState,
    uri: String,
}

impl Drop for RefreshMarker {
    fn drop(&mut self) {
        if let Err(err) = self
            .state
            .inner
            .coordination
            .mark_background_refresh_finished(&self.uri)
        {
            record_jwks_in_memory_runtime_state_failure(
                "background_refresh_cleanup_lock",
                &self.uri,
                err,
            );
        }
    }
}

#[cfg(test)]
pub(in crate::client_registry) fn spawn_jwks_refresh_once(policy: JwksRuntimePolicy, uri: &str) {
    spawn_jwks_refresh_once_with_state(jwks_runtime_state(), policy, uri);
}

pub(in crate::client_registry) fn spawn_jwks_refresh_once_with_state(
    state: &JwksRuntimeState,
    policy: JwksRuntimePolicy,
    uri: &str,
) {
    // Synchronous workers expose their owner through the thread scope. A task
    // scope may also call this helper directly; invalid/conflicting scopes must
    // never turn into ordinary unowned background work.
    let owner = match current_owner() {
        Ok(owner) => Some(owner),
        Err(_) => match task_owner() {
            Ok(None) => None,
            Ok(Some(_)) | Err(_) => return,
        },
    };
    let inserted = match state
        .inner
        .coordination
        .mark_background_refresh_started(policy.local_cache_max_entries, uri)
    {
        Ok(inserted) => inserted,
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("background_refresh_lock", uri, err);
            false
        }
    };
    if !inserted {
        return;
    }

    // The marker is owned by the closure, so spawn failure and unwinding also
    // remove it. The admission clone retains witness completion through the
    // refresh and the Redis driver's independently owned protocol cleanup.
    let marker = RefreshMarker {
        state: state.clone(),
        uri: uri.to_owned(),
    };
    let _ = std::thread::Builder::new()
        .name("aegaeon-jwks-refresh".to_string())
        .spawn(move || {
            let refresh = move || {
                let _ = refresh_jwks_with_state(&marker.state, &policy, &marker.uri);
                drop(marker);
            };
            if let Some(owner) = owner {
                let _ = crate::redis_io::organization::scope(owner, refresh);
            } else {
                refresh();
            }
        });
}

#[cfg(test)]
mod organization_epoch;
