//! Middleware admission tests use the claims-only DPoP double. Real signed
//! freshness-boundary controls live in ffi/tests/dpop_proof_test.rs.
use super::*;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

type TestResult = Result<(), String>;

#[derive(Default)]
struct ControlledStore {
    millis: AtomicU64,
    entries: Mutex<HashMap<String, u64>>,
    retained: Mutex<Vec<Duration>>,
}

impl ReplayStore for ControlledStore {
    fn check_and_store(&self, entry: ReplayEntry<'_>) -> Result<(), ReplayStoreError> {
        let now = self.millis.load(Ordering::SeqCst);
        let ttl: u64 = entry
            .ttl
            .as_millis()
            .try_into()
            .map_err(|_| ReplayStoreError::RetentionOverflow)?;
        let expiry = now
            .checked_add(ttl)
            .ok_or(ReplayStoreError::RetentionOverflow)?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|e| ReplayStoreError::BackendUnavailable(e.to_string()))?;
        entries.retain(|_, expiry| *expiry > now);
        let key = entry.encoded_key();
        if entries.contains_key(&key) {
            return Err(ReplayStoreError::Replay);
        }
        entries.insert(key, expiry);
        self.retained
            .lock()
            .map_err(|e| ReplayStoreError::BackendUnavailable(e.to_string()))?
            .push(entry.ttl);
        Ok(())
    }
}

fn proof(iat: u64, nonce: Option<&str>) -> String {
    let header = serde_json::json!({"typ":"dpop+jwt", "alg":"EdDSA", "jwk":{"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode([1u8; 32])}});
    let payload = serde_json::json!({"htm":"GET", "htu":"https://issuer.example/resource", "iat":iat, "jti":"retained-proof", "nonce":nonce});
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string()),
        URL_SAFE_NO_PAD.encode(b"claims-only-double")
    )
}

fn verify_at(
    middleware: &DpopMiddleware,
    proof: &str,
    millis: u64,
) -> Result<DpopBinding, DpopError> {
    middleware.verify_components_at(
        DpopEndpointRole::AuthorizationServer,
        &Method::GET,
        &Uri::from_static("/resource"),
        proof,
        None,
        millis / 1000,
    )
}

#[test]
fn dpop_retention_covers_future_edge_old_ttl_and_inclusive_final_second_with_nonce_on_off(
) -> TestResult {
    let start = 1_700_000_000_999u64;
    for nonce_enabled in [false, true] {
        let store = Arc::new(ControlledStore::default());
        store.millis.store(start, Ordering::SeqCst);
        let mut middleware = DpopMiddleware::new(
            "retention",
            "https://issuer.example",
            store.clone(),
            Duration::from_secs(1),
        );
        let nonce = if nonce_enabled {
            // A shorter nonce lifetime must not shorten replay retention.
            let nonce_store = Arc::new(DpopNonceStore::new_process_local(Duration::from_secs(60)));
            let nonce = nonce_store
                .get_current_nonce()
                .map_err(|e| format!("{e:?}"))?;
            middleware = middleware.with_nonce_store(nonce_store);
            Some(nonce)
        } else {
            None
        };
        let token = proof(start / 1000 + MAX_DPOP_IAT_WINDOW_SECS, nonce.as_deref());
        assert!(verify_at(&middleware, &token, start).is_ok());
        for elapsed in [0, 361_000, 600_000] {
            store.millis.store(start + elapsed, Ordering::SeqCst);
            assert_eq!(
                verify_at(&middleware, &token, start + elapsed),
                Err(DpopError::Replay)
            );
        }
        store.millis.store(start + 601_000, Ordering::SeqCst);
        assert_eq!(
            verify_at(&middleware, &token, start + 601_000),
            Err(DpopError::InvalidProof)
        );
        assert_eq!(
            *store.retained.lock().map_err(|e| e.to_string())?,
            vec![Duration::from_secs(601)]
        );
    }
    Ok(())
}

#[test]
fn dpop_retention_survives_supported_window_increase_between_instances() {
    let start = 1_700_000_000_000u64;
    let store = Arc::new(ControlledStore::default());
    store.millis.store(start, Ordering::SeqCst);
    let first = DpopMiddleware::new(
        "shared",
        "https://issuer.example",
        store.clone(),
        Duration::from_secs(1),
    )
    .with_iat_window_secs(30);
    let second = DpopMiddleware::new(
        "shared",
        "https://issuer.example",
        store.clone(),
        Duration::from_secs(1),
    )
    .with_iat_window_secs(MAX_DPOP_IAT_WINDOW_SECS);
    let token = proof(start / 1000 + 30, None);
    assert!(verify_at(&first, &token, start).is_ok());
    store.millis.store(start + 330_999, Ordering::SeqCst);
    assert_eq!(
        verify_at(&second, &token, start + 330_999),
        Err(DpopError::Replay)
    );
    assert_eq!(
        verify_at(&second, &token, start + 331_000),
        Err(DpopError::InvalidProof)
    );
}

#[test]
fn dpop_retention_preserves_longer_caller_ttl_and_direct_larger_window() -> TestResult {
    for (window, requested, expected) in [(300, 1, 601), (600, 1, 1201), (300, 2400, 2400)] {
        let store = Arc::new(ControlledStore::default());
        let middleware = DpopMiddleware::new(
            "bounds",
            "https://issuer.example",
            store.clone(),
            Duration::from_secs(requested),
        )
        .with_iat_window_secs(window);
        assert!(verify_at(&middleware, &proof(0, None), 0).is_ok());
        assert_eq!(
            *store.retained.lock().map_err(|e| e.to_string())?,
            vec![Duration::from_secs(expected)]
        );
    }
    Ok(())
}

#[test]
fn dpop_retention_overflow_fails_before_replay_insertion() -> TestResult {
    assert_eq!(
        DpopMiddleware::minimum_replay_ttl(u64::MAX / 2),
        Ok(Duration::from_secs(u64::MAX))
    );
    for window in [u64::MAX / 2 + 1, u64::MAX] {
        let store = Arc::new(ControlledStore::default());
        let middleware = DpopMiddleware::new(
            "overflow",
            "https://issuer.example",
            store.clone(),
            Duration::ZERO,
        )
        .with_iat_window_secs(window);
        assert!(matches!(
            verify_at(&middleware, &proof(0, None), 0),
            Err(DpopError::BackendUnavailable(_))
        ));
        assert!(store.entries.lock().map_err(|e| e.to_string())?.is_empty());
    }
    Ok(())
}

#[path = "retention_redis_tests.rs"]
mod redis;
