use super::super::jwks_circuit::record_jwks_in_memory_runtime_state_failure;
#[cfg(test)]
use super::super::jwks_runtime_state;
use super::super::jwks_runtime_state::JwksRuntimeState;
use super::super::JwksRuntimePolicy;
use super::refresh_jwks_with_state;

#[cfg(test)]
pub(in crate::client_registry) fn spawn_jwks_refresh_once(
    policy: JwksRuntimePolicy,
    uri: &str,
    etag: Option<String>,
    last_modified: Option<String>,
) {
    spawn_jwks_refresh_once_with_state(jwks_runtime_state(), policy, uri, etag, last_modified);
}

pub(in crate::client_registry) fn spawn_jwks_refresh_once_with_state(
    state: &JwksRuntimeState,
    policy: JwksRuntimePolicy,
    uri: &str,
    etag: Option<String>,
    last_modified: Option<String>,
) {
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

    let uri_for_refresh = uri.to_string();
    let uri_for_cleanup = uri.to_string();
    let refresh_state = state.clone();
    let cleanup_state = state.clone();
    if std::thread::Builder::new()
        .name("aegaeon-jwks-refresh".to_string())
        .spawn(move || {
            let _ = refresh_jwks_with_state(
                &refresh_state,
                &policy,
                &uri_for_refresh,
                etag,
                last_modified,
            );
            match cleanup_state
                .inner
                .coordination
                .mark_background_refresh_finished(&uri_for_cleanup)
            {
                Ok(()) => {}
                Err(err) => {
                    record_jwks_in_memory_runtime_state_failure(
                        "background_refresh_cleanup_lock",
                        &uri_for_cleanup,
                        err,
                    );
                }
            }
        })
        .is_err()
    {
        match state
            .inner
            .coordination
            .mark_background_refresh_finished(uri)
        {
            Ok(()) => {}
            Err(err) => {
                record_jwks_in_memory_runtime_state_failure(
                    "background_refresh_spawn_cleanup_lock",
                    uri,
                    err,
                );
            }
        }
    }
}
