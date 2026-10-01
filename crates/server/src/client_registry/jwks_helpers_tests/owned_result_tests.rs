use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

fn body(kid: &str, modulus: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"keys":[{
        "kty":"RSA", "kid":kid, "alg":"RS256", "n":crate::test_utils::jwk_usage::public_shape_modulus(modulus), "e":"AQAB"
    }]}))
    .expect("test JWKS encoding")
}

fn entry(kid: &str, modulus: &str) -> CacheEntry {
    let jwks: FetchedJwks = serde_json::from_slice(&body(kid, modulus)).expect("test JWKS");
    let mut entry = cache_test_entry(jwks, Instant::now());
    fixture_fresh_for(&mut entry, Duration::from_secs(60));
    entry
}

fn policy() -> JwksRuntimePolicy {
    JwksRuntimePolicy {
        allow_http_loopback_for_tests: true,
        http_retries: 0,
        http_timeout_secs: 3,
        log_sample_percent: 100,
        circuit_open_fails: 1,
        ..JwksRuntimePolicy::default()
    }
}

// Each fixture serves exactly one bounded local request; it cannot hang forever
// when the client fails before reaching the listener.
pub(super) fn response_fixture(
    status: u16,
    bytes: Vec<u8>,
    cache_control: &str,
) -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local JWKS listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let uri = format!(
        "http://{}/jwks.json",
        listener.local_addr().expect("local address")
    );
    let cache_control = cache_control.to_owned();
    let thread = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "client never reached local fixture"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("local accept: {err}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .expect("write timeout");
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 8192, "bounded request headers");
            let mut byte = [0u8];
            stream.read_exact(&mut byte).expect("request header byte");
            request.push(byte[0]);
        }
        let request = String::from_utf8(request).expect("ASCII fixture request");
        assert!(request.starts_with("GET /jwks.json HTTP/1.1\r\n"));
        let headers = format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nContent-Type: application/json\r\nCache-Control: {cache_control}\r\nConnection: close\r\n\r\n", bytes.len());
        stream
            .write_all(headers.as_bytes())
            .expect("response headers");
        stream.write_all(&bytes).expect("response body");
        stream.flush().expect("response flush");
        request
    });
    (uri, thread)
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    NonRetainable,
    Prune,
    Replace,
    Gc,
}

struct SuccessMutation {
    state: JwksRuntimeState,
    policy: JwksRuntimePolicy,
    uri: String,
    mutation: Mutation,
    observed: Arc<AtomicUsize>,
}

#[derive(Default)]
struct Outcome {
    success: bool,
}
impl Visit for Outcome {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" {
            self.success = value == "200";
        }
    }
    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

impl<S: tracing::Subscriber> Layer<S> for SuccessMutation {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() != "jwks_event" {
            return;
        }
        let mut outcome = Outcome::default();
        event.record(&mut outcome);
        if !outcome.success {
            return;
        }
        assert_eq!(self.observed.fetch_add(1, Ordering::SeqCst), 0);
        let uri_lock = self
            .state
            .inner
            .coordination
            .fetch_locks
            .lock()
            .expect("lock map")
            .get(&self.uri)
            .expect("active URI lock")
            .clone();
        assert!(
            matches!(
                uri_lock.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ),
            "actual refresh must still own its URI lock at success publication"
        );
        if !matches!(self.mutation, Mutation::NonRetainable) {
            let cache = self
                .state
                .inner
                .cache
                .lock()
                .expect("cache before intervention");
            assert_eq!(
                cache
                    .get(&self.uri)
                    .expect("actual admitted publication")
                    .jwks
                    .keys[0]
                    .kid
                    .as_deref(),
                Some("A")
            );
        }
        match self.mutation {
            Mutation::NonRetainable => {
                let cache = self.state.inner.cache.lock().unwrap();
                assert!(!cache.contains_key(&self.uri));
                assert!(cache.guards.contains_key(&self.uri));
            }
            Mutation::Prune => {
                let mut cache = self
                    .state
                    .inner
                    .cache
                    .lock()
                    .expect("cache for capacity GC");
                cache.insert(format!("{}/newer", self.uri), entry("B", "AQ"));
                super::super::jwks_gc::prune_cache_to_capacity(&mut cache, 1);
                assert!(
                    !cache.contains_key(&self.uri),
                    "actual capacity prune removes A"
                );
            }
            Mutation::Replace => {
                self.state
                    .inner
                    .cache
                    .lock()
                    .expect("cache for replacement")
                    .insert(self.uri.clone(), entry("B", "AQ"));
            }
            Mutation::Gc => {
                // D6 successor: freshness expiry does not imply retention expiry.
                self.state
                    .inner
                    .cache
                    .lock()
                    .unwrap()
                    .get_mut(&self.uri)
                    .unwrap()
                    .retain_until = Instant::now();
                *self.state.inner.last_gc.lock().expect("GC timer") = None;
                super::super::jwks_gc::maybe_run_gc_with_state(&self.state, &self.policy);
                assert!(!self
                    .state
                    .inner
                    .cache
                    .lock()
                    .expect("cache after GC")
                    .contains_key(&self.uri));
            }
        }
    }
}

fn admitted_with_intervention(
    status: u16,
    max_age: u64,
    mutation: Mutation,
) -> (Option<FetchedJwks>, usize) {
    // Keep assertions outside the environment guard to avoid poisoning later tests.
    let _env = env_lock().expect("test env guard");
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    let state = JwksRuntimeState::default();
    let policy = policy();
    let (uri, server) = response_fixture(status, body("A", "AA"), &format!("max-age={max_age}"));
    let observed = Arc::new(AtomicUsize::new(0));
    let layer = SuccessMutation {
        state: state.clone(),
        policy: policy.clone(),
        uri: uri.clone(),
        mutation,
        observed: observed.clone(),
    };
    let result =
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            fetch_jwks_with_state(&state, &policy, &uri)
        });
    let request = server.join().expect("one local request completed");
    assert!(!request.to_ascii_lowercase().contains("if-none-match:"));
    (result, observed.load(Ordering::SeqCst))
}

fn assert_admitted_a(result: Option<FetchedJwks>, observed: usize) {
    assert_eq!(observed, 1, "real post-admission event must run");
    assert_eq!(
        result
            .as_ref()
            .and_then(|set| set.keys.first())
            .and_then(|key| key.kid.as_deref()),
        Some("A"),
        "the invocation must return admitted A despite later optional-cache mutation"
    );
}

#[test]
fn admitted_body_survives_actual_capacity_pruning() {
    let (result, observed) = admitted_with_intervention(200, 60, Mutation::Prune);
    assert_admitted_a(result, observed);
}
#[test]
fn admitted_body_survives_cache_replacement() {
    let (result, observed) = admitted_with_intervention(200, 60, Mutation::Replace);
    assert_admitted_a(result, observed);
}
#[test]
fn max_age_zero_owned_body_survives_retention_expiry_gc() {
    let (result, observed) = admitted_with_intervention(200, 0, Mutation::Gc);
    assert_admitted_a(result, observed);
}
#[test]
fn other_2xx_owned_body_needs_no_cache_publication() {
    let (result, observed) = admitted_with_intervention(201, 60, Mutation::NonRetainable);
    assert_admitted_a(result, observed);
}

fn response_result(
    bytes: Vec<u8>,
    policy: JwksRuntimePolicy,
    previous: Option<CacheEntry>,
) -> (Option<FetchedJwks>, JwksRuntimeState, String) {
    let _env = env_lock().expect("test env guard");
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    let state = JwksRuntimeState::default();
    let (uri, server) = response_fixture(200, bytes, "max-age=0");
    *state.inner.last_gc.lock().expect("GC timer") = Some(Instant::now());
    if let Some(previous) = previous {
        state
            .inner
            .cache
            .lock()
            .expect("seed cache")
            .insert(uri.clone(), previous);
    }
    let result = fetch_jwks_with_state(&state, &policy, &uri);
    server.join().expect("fixture completed");
    (result, state, uri)
}

#[test]
fn max_age_zero_body_is_immediately_usable() {
    let (result, state, uri) = response_result(body("A", "AA"), policy(), None);
    assert_eq!(
        result.expect("admitted max-age0 body").keys[0]
            .kid
            .as_deref(),
        Some("A")
    );
    let cache = state.inner.cache.lock().expect("cache");
    assert!(!cache
        .get(&uri)
        .expect("published body")
        .freshness
        .reusable(Instant::now()));
}

#[test]
fn malformed_body_is_not_admitted() {
    let (result, state, uri) = response_result(b"not-json".to_vec(), policy(), None);
    assert!(result.is_none());
    assert!(!state.inner.cache.lock().expect("cache").contains_key(&uri));
    assert!(matches!(
        circuit_phase_with_state(&state, &uri),
        CircuitPhase::Open
    ));
}

#[test]
fn structurally_invalid_body_is_not_admitted() {
    let (result, state, uri) = response_result(br#"{"keys":[]}"#.to_vec(), policy(), None);
    assert!(result.is_none());
    assert!(!state.inner.cache.lock().expect("cache").contains_key(&uri));
    assert!(matches!(
        circuit_phase_with_state(&state, &uri),
        CircuitPhase::Open
    ));
}

#[test]
fn oversized_body_is_not_admitted() {
    let mut policy = policy();
    policy.max_body_bytes = 16;
    let (result, state, uri) = response_result(body("A", "AA"), policy, None);
    assert!(result.is_none());
    assert!(!state.inner.cache.lock().expect("cache").contains_key(&uri));
}

#[test]
fn changed_local_kid_material_is_not_admitted_or_returned_as_stale() {
    let mut previous = entry("A", "AA");
    fixture_fresh_for(&mut previous, Duration::ZERO);
    let (result, state, uri) = response_result(body("A", "AQ"), policy(), Some(previous));
    assert!(result.is_none());
    assert_eq!(
        state
            .inner
            .cache
            .lock()
            .expect("cache")
            .get(&uri)
            .expect("old cache retained")
            .jwks
            .keys[0]
            .n
            .as_deref(),
        Some(crate::test_utils::jwk_usage::public_shape_modulus("AA").as_str())
    );
    assert!(matches!(
        circuit_phase_with_state(&state, &uri),
        CircuitPhase::Open
    ));
}

#[test]
fn shared_kid_admission_error_cannot_return_http_body() {
    let result = {
        let _env = env_lock().expect("test env guard");
        let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
        let state = JwksRuntimeState::with_shared_state(JwksSharedRuntimeState::Redis(
            RedisJwksRuntimeState::new_for_tests("redis://127.0.0.1:1/")
                .expect("syntactic Redis URL"),
        ));
        let mut policy = policy();
        policy.shared_state_max_age_secs = u64::MAX;
        let (uri, server) = response_fixture(200, body("A", "AA"), "max-age=60");
        // Exercise the actual refresh caller after circuit admission. The shared
        // TTL guard fails before any Redis connection; no shared service is used.
        let ctx = super::super::jwks_fetch_context::JwksFetchContext::new(&state, &policy, &uri);
        let result = super::super::jwks_fetch_memory::refresh_and_read_memory_cache(&ctx);
        server
            .join()
            .expect("actual HTTP completed before shared guard");
        assert!(!state.inner.cache.lock().expect("cache").contains_key(&uri));
        result
    };
    assert!(
        result.is_none(),
        "shared admission failure is not an admitted body"
    );
}

#[test]
fn unsolicited_304_cannot_reuse_unassociated_legacy_cache() {
    let result = {
        let _env = env_lock().expect("test env guard");
        let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
        let state = JwksRuntimeState::default();
        let policy = policy();
        let (uri, server) = response_fixture(304, Vec::new(), "max-age=0");
        let mut previous = entry("legacy", "AA");
        fixture_fresh_for(&mut previous, Duration::ZERO);
        state
            .inner
            .cache
            .lock()
            .expect("cache")
            .insert(uri.clone(), previous);
        *state.inner.last_gc.lock().expect("GC timer") = Some(Instant::now());
        let result = fetch_jwks_with_state(&state, &policy, &uri);
        let request = server.join().expect("304 fixture");
        assert!(!request.to_ascii_lowercase().contains("if-none-match:"));
        result
    };
    assert!(
        result.is_none(),
        "unsolicited 304 cannot identify the old body"
    );
}

#[test]
fn background_owned_result_is_discarded_and_coordination_is_cleaned() {
    let _env = env_lock().expect("test env guard");
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    let state = JwksRuntimeState::default();
    let policy = policy();
    let (uri, server) = response_fixture(200, body("A", "AA"), "max-age=60");
    super::super::jwks_refresh::spawn_jwks_refresh_once_with_state(&state, policy, &uri);
    server.join().expect("background HTTP fixture");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !state
            .inner
            .coordination
            .background_refreshes
            .lock()
            .expect("background set")
            .contains(&uri)
        {
            break;
        }
        assert!(Instant::now() < deadline, "background cleanup deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        state
            .inner
            .cache
            .lock()
            .expect("cache")
            .get(&uri)
            .expect("background publication")
            .jwks
            .keys[0]
            .kid
            .as_deref(),
        Some("A")
    );
}
