use std::sync::Arc;
use std::time::Duration;

use super::super::clock::current_unix_epoch_secs;
use super::super::traits::{EntityCacheRepository, TrustChainCacheRepository};

/// Spawn a background task that periodically cleans up expired federation
/// cache entries.
///
/// Returns a `tokio::task::AbortHandle` that can be used to cancel the
/// cleanup task on server shutdown.
///
/// Runs every `interval` (recommended: 5 minutes). Each sweep calls
/// `cleanup_expired` on both repositories.
pub fn spawn_cache_cleanup(
    entity_cache: Arc<dyn EntityCacheRepository>,
    chain_cache: Arc<dyn TrustChainCacheRepository>,
    interval: Duration,
) -> tokio::task::AbortHandle {
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now = match current_unix_epoch_secs() {
                Ok(now) => now,
                Err(err) => {
                    tracing::warn!(error = %err, "federation cache cleanup skipped");
                    continue;
                }
            };

            match entity_cache.cleanup_expired(now).await {
                Ok(n) if n > 0 => {
                    tracing::debug!(removed = n, "federation entity cache cleanup");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "federation entity cache cleanup failed");
                }
                _ => {}
            }

            match chain_cache.cleanup_expired(now).await {
                Ok(n) if n > 0 => {
                    tracing::debug!(removed = n, "federation trust chain cache cleanup");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "federation trust chain cache cleanup failed");
                }
                _ => {}
            }
        }
    });

    handle.abort_handle()
}
