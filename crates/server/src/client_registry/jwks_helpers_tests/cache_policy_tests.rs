use super::super::jwks_types::KidGuard;
use super::https_fixture::*;
use super::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn cached(kid: &str, policy: &str) -> Step {
    Step::new(200, body(kid))
        .header("Cache-Control", policy)
        .header("ETag", format!("\"{kid}\""))
}
fn refresh_kid(state: &JwksRuntimeState, policy: &JwksRuntimePolicy) -> Option<String> {
    match super::super::jwks_refresh::refresh_jwks_with_state(state, policy, ORIGINAL)? {
        super::super::jwks_refresh::JwksRefreshOutcome::AdmittedBody(jwks)
        | super::super::jwks_refresh::JwksRefreshOutcome::RevalidatedBody(jwks) => kid(Some(jwks)),
    }
}
fn typed_entry(name: &str) -> CacheEntry {
    cache_test_entry(serde_json::from_slice(&body(name)).unwrap(), Instant::now())
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn explicit_quoted_multiline_and_default_cache_hits_are_normal() {
    let _env = env_lock().unwrap();
    for response in [
        cached("A", "max-age=60"),
        Step::new(200, body("A"))
            .header("Cache-Control", b"extension=\"x,y\\\"z\"")
            .header("Cache-Control", b"mAx-aGe=\"60\""),
        Step::new(200, body("A")),
        cached("A", "s-maxage=120,max-age=60,must-revalidate"),
    ] {
        let fixture = Fixture::new(vec![response], false);
        let state = new_state();
        let mut policy = fixture.policy();
        policy.refresh_skew_secs = 0;
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        assert_eq!(
            fixture.finish().len(),
            1,
            "normal reuse must avoid second request"
        );
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn no_retention_drops_previous_body_but_preserves_security_guard() {
    let _env = env_lock().unwrap();
    for response in [
        cached("A", "no-store,max-age=60,must-understand"),
        cached("A", "private,max-age=60"),
        cached("A", "max-age=1,max-age=1"),
        cached("A", "max-age=60").header("Vary", "Accept-Encoding"),
    ] {
        let fixture = Fixture::new(
            vec![cached("B", "max-age=60"), response, Step::ok("C")],
            false,
        );
        let state = new_state();
        let mut policy = fixture.policy();
        policy.refresh_skew_secs = 0;
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("B")
        );
        assert_eq!(refresh_kid(&state, &policy).as_deref(), Some("A"));
        {
            let cache = state.inner.cache.lock().unwrap();
            assert!(!cache.contains_key(ORIGINAL));
            assert!(cache
                .guards
                .get(ORIGINAL)
                .unwrap()
                .kid_fps
                .contains_key("A"));
        }
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("C")
        );
        assert_eq!(fixture.finish().len(), 3);
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn no_cache_requires_validation_and_rejects_failed_validation() {
    let _env = env_lock().unwrap();
    for directive in [
        "no-cache,max-age=60",
        "no-cache=\"ETag, Last-Modified\",max-age=60",
    ] {
        let fixture = Fixture::new(
            vec![
                cached("A", directive),
                Step::new(304, vec![]).header("ETag", "\"A\""),
                Step::new(503, vec![]),
            ],
            false,
        );
        let state = new_state();
        let policy = fixture.policy();
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        assert!(fetch_jwks_with_state(&state, &policy, ORIGINAL).is_none());
        let obs = fixture.finish();
        assert_eq!(obs.len(), 3);
        assert_eq!(
            obs[1].header("if-none-match").as_deref(),
            Some(b"\"A\"".as_slice())
        );
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn actual_body_residence_consumes_remaining_lifetime() {
    let _env = env_lock().unwrap();
    let mut first = cached("A", "max-age=1");
    first.body.clear();
    first.chunks = vec![(Duration::from_millis(1100), body("A"))];
    let fixture = Fixture::new(vec![first, Step::ok("B")], false);
    let state = new_state();
    let mut policy = fixture.policy();
    policy.http_timeout_secs = 3;
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("B")
    );
    assert_eq!(fixture.finish().len(), 2);
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn response_304_inherits_positive_lifetime_and_applies_new_restriction() {
    let _env = env_lock().unwrap();
    for restriction in [false, true] {
        let mut revalidation = Step::new(304, vec![]).header("ETag", "\"A\"");
        if restriction {
            revalidation = revalidation.header("Cache-Control", "no-store");
        }
        let mut steps = vec![cached("A", "max-age=60"), revalidation];
        if restriction {
            steps.push(Step::ok("B"));
        }
        let fixture = Fixture::new(steps, false);
        let state = new_state();
        let mut policy = fixture.policy();
        policy.refresh_skew_secs = 0;
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        let old_guard = state.inner.cache.lock().unwrap().guards[ORIGINAL].clone();
        assert_eq!(refresh_kid(&state, &policy).as_deref(), Some("A"));
        assert!(!Arc::ptr_eq(
            &old_guard,
            &state.inner.cache.lock().unwrap().guards[ORIGINAL]
        ));
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some(if restriction { "B" } else { "A" })
        );
        assert_eq!(fixture.finish().len(), if restriction { 3 } else { 2 });
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn non200_and_redirect_current_use_do_not_create_reuse_right() {
    let _env = env_lock().unwrap();
    for (steps, count) in [
        (
            vec![
                Step::new(201, body("A")).header("Cache-Control", "max-age=60"),
                Step::ok("B"),
            ],
            2,
        ),
        (
            vec![
                Step::redirect(OTHER),
                cached("A", "max-age=60"),
                Step::ok("B"),
            ],
            3,
        ),
        (
            vec![
                Step::redirect(OTHER),
                Step::redirect(ORIGINAL),
                cached("A", "max-age=60"),
                Step::ok("B"),
            ],
            4,
        ),
    ] {
        let fixture = Fixture::new(steps, false);
        let state = new_state();
        let policy = fixture.policy();
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        assert!(!state.inner.cache.lock().unwrap().contains_key(ORIGINAL));
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("B")
        );
        assert_eq!(fixture.finish().len(), count);
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn no_store_does_not_disable_local_kid_conflict_protection() {
    let _env = env_lock().unwrap();
    let changed = serde_json::to_vec(
        &serde_json::json!({"keys":[{"kty":"RSA","kid":"A","n":"AQ","e":"AQAB","alg":"RS256"}]}),
    )
    .unwrap();
    let fixture = Fixture::new(
        vec![
            cached("A", "no-store"),
            Step::new(200, changed).header("Cache-Control", "no-store"),
        ],
        false,
    );
    let state = new_state();
    let policy = fixture.policy();
    assert_eq!(
        kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
        Some("A")
    );
    assert!(fetch_jwks_with_state(&state, &policy, ORIGINAL).is_none());
    assert!(state.inner.cache.lock().unwrap().is_empty());
    assert_eq!(fixture.finish().len(), 2);
}

#[test]
fn mutex_wait_is_included_before_reuse_decision() {
    let state = new_state();
    let policy = JwksRuntimePolicy::default();
    let mut entry = typed_entry("A");
    fixture_fresh_for(&mut entry, Duration::from_millis(40));
    state
        .inner
        .cache
        .lock()
        .unwrap()
        .insert(ORIGINAL.to_owned(), entry);
    let lock = state.inner.cache.lock().unwrap();
    let cloned = state.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let ctx =
            super::super::jwks_fetch_context::JwksFetchContext::new(&cloned, &policy, ORIGINAL);
        tx.send(()).unwrap();
        super::super::jwks_fetch_memory::probe_memory_cache(&ctx)
            .hit
            .is_some()
    });
    rx.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::sleep(Duration::from_millis(60));
    drop(lock);
    assert!(!thread.join().unwrap());
}

#[test]
fn guard_identity_horizon_capacity_and_owned_capture() {
    let mut cache = super::super::jwks_runtime_state::JwksLocalCache::default();
    let now = Instant::now();
    let mut a = typed_entry("A");
    a.guard = Arc::new(KidGuard {
        kid_fps: a.guard.kid_fps.clone(),
        admitted_at: now,
        deadline: now + Duration::from_secs(10),
    });
    a.freshness.receipt = now;
    a.freshness.lifetime = Some(300_000_000_000);
    a.fetched_at = now;
    cache.insert("a".into(), a.clone());
    assert!(cache.reusable("a", now + Duration::from_secs(9)).is_some());
    assert!(cache.reusable("a", now + Duration::from_secs(10)).is_none());
    let (owned, captured) = cache.capture("a", now + Duration::from_secs(9)).unwrap();
    assert!(owned.is_some());
    let (expired, guard) = cache.capture("a", now + Duration::from_secs(10)).unwrap();
    assert!(expired.is_none());
    assert!(guard.is_none());
    assert!(captured
        .unwrap()
        .conflicts(&HashMap::from([("A".to_owned(), "changed".to_owned())])));
    cache.insert("a".into(), a.clone());
    cache.representations.remove("a");
    assert!(cache.guards.contains_key("a"));
    cache.insert("a".into(), a.clone());
    let mut b = typed_entry("B");
    b.guard = Arc::new(KidGuard {
        kid_fps: b.guard.kid_fps.clone(),
        admitted_at: now,
        deadline: now + Duration::from_secs(60),
    });
    b.fetched_at = now;
    cache.insert("b".into(), b);
    cache.prune_to_capacity(1);
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.guards.len(), 1);
    assert!(!cache.guards.contains_key("a"));
    assert!(!cache.contains_key("a"));
    // Same timestamps break ties by URI; active owned Arc remains readable.
    assert!(a.guard.kid_fps.contains_key("A"));
}

#[test]
fn unavailable_new_guard_time_preserves_existing_pair() {
    let mut cache = super::super::jwks_runtime_state::JwksLocalCache::default();
    let old = typed_entry("A");
    cache.insert("a".into(), old.clone());
    let now = Instant::now();
    let future = Arc::new(KidGuard {
        kid_fps: HashMap::new(),
        admitted_at: now + Duration::from_secs(1),
        deadline: now + Duration::from_secs(2),
    });
    assert!(cache.publish("a", future, None, now, 1).is_err());
    assert!(Arc::ptr_eq(&cache.guards["a"], &old.guard));
    assert!(Arc::ptr_eq(&cache.get("a").unwrap().guard, &old.guard));
}

fn poison(state: &JwksRuntimeState) {
    let cloned = state.clone();
    assert!(std::thread::spawn(move || {
        let _held = cloned.inner.cache.lock().unwrap();
        panic!("intentional fixture poison");
    })
    .join()
    .is_err());
}

struct PoisonAfterAdmission(JwksRuntimeState);
impl<S: tracing::Subscriber> tracing_subscriber::layer::Layer<S> for PoisonAfterAdmission {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() == "jwks_admission" {
            poison(&self.0);
        }
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn poison_before_admission_fails_but_after_admission_keeps_owned_result() {
    use tracing_subscriber::prelude::*;
    let _env = env_lock().unwrap();
    for after in [false, true] {
        let state = new_state();
        let mut step = cached("A", "max-age=60");
        if !after {
            let cloned = state.clone();
            step.before_response = Some(Box::new(move || poison(&cloned)));
        }
        let fixture = Fixture::new(vec![step], false);
        let policy = fixture.policy();
        let result = if after {
            tracing::subscriber::with_default(
                tracing_subscriber::registry().with(PoisonAfterAdmission(state.clone())),
                || fetch_jwks_with_state(&state, &policy, ORIGINAL),
            )
        } else {
            fetch_jwks_with_state(&state, &policy, ORIGINAL)
        };
        assert_eq!(kid(result).as_deref(), if after { Some("A") } else { None });
        assert!(state.inner.cache.is_poisoned());
        assert_eq!(fixture.finish().len(), 1);
        assert!(fetch_jwks_with_state(&state, &policy, ORIGINAL).is_none());
    }
}

// Disposable Redis fixture: dedicated Unix socket, port 0, no RDB
// saves/AOF, and shutdown nosave. Starts only after the HTTPS namespace gate.
struct RedisFixture {
    dir: std::path::PathBuf,
    url: String,
    child: std::process::Child,
}
impl RedisFixture {
    fn new() -> Self {
        assert_eq!(
            std::fs::read_link("/proc/self/ns/net")
                .unwrap()
                .to_string_lossy(),
            std::env::var("JWKS_TEST_NETNS").unwrap()
        );
        let dir = std::env::temp_dir().join(format!("aegaeon-jwks-cache-redis-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let log = std::path::PathBuf::from(std::env::var_os("JWKS_TEST_DIR").unwrap())
            .join(format!("redis-{}.log", Uuid::new_v4()));
        let backend =
            std::env::var("JWKS_LEDGER_TEST_SERVER").unwrap_or_else(|_| "redis-server".to_owned());
        let child = std::process::Command::new(backend)
            .args(["--port", "0", "--unixsocket"])
            .arg(dir.join("redis.sock"))
            .args([
                "--unixsocketperm",
                "700",
                "--save",
                "",
                "--appendonly",
                "no",
                "--daemonize",
                "no",
                "--pidfile",
            ])
            .arg(dir.join("redis.pid"))
            .arg("--logfile")
            .arg(log)
            .arg("--dir")
            .arg(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let url = format!("redis+unix://{}", dir.join("redis.sock").display());
        let mut fixture = Self { dir, url, child };
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if redis::Client::open(fixture.url.as_str())
                .unwrap()
                .get_connection()
                .is_ok()
            {
                break;
            }
            assert!(
                fixture.child.try_wait().unwrap().is_none(),
                "Redis exited before readiness"
            );
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        fixture
    }
    fn connection(&self) -> redis::Connection {
        redis::Client::open(self.url.as_str())
            .unwrap()
            .get_connection()
            .unwrap()
    }
}
impl Drop for RedisFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn real_shared_304_renewal_conflict_and_backend_error() {
    let _env = env_lock().unwrap();
    let redis = RedisFixture::new();
    for mode in [0, 1, 2] {
        let fixture = Fixture::new(
            vec![cached("A", "max-age=0"), Step::not_modified("\"A\"")],
            false,
        );
        let shared = RedisJwksRuntimeState::new_for_tests(&redis.url).unwrap();
        let key = shared.key("kid-fps", ORIGINAL);
        let state = JwksRuntimeState::with_shared_state(JwksSharedRuntimeState::Redis(shared));
        let mut policy = fixture.policy();
        policy.shared_state_max_age_secs = 60;
        let mut connection = redis.connection();
        redis::cmd("FLUSHDB").query::<()>(&mut connection).unwrap();
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        let old = state
            .inner
            .cache
            .lock()
            .unwrap()
            .get(ORIGINAL)
            .unwrap()
            .clone();
        if mode == 0 {
            redis::cmd("PEXPIRE")
                .arg(&key)
                .arg(5000)
                .query::<i32>(&mut connection)
                .unwrap();
        }
        if mode == 1 {
            redis::cmd("HSET")
                .arg(&key)
                .arg("A")
                .arg("conflict")
                .query::<i32>(&mut connection)
                .unwrap();
        }
        if mode == 2 {
            redis::cmd("SET")
                .arg(&key)
                .arg("wrong-type")
                .query::<()>(&mut connection)
                .unwrap();
        }
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            if mode == 0 { Some("A") } else { None }
        );
        let cache = state.inner.cache.lock().unwrap();
        let current = cache.get(ORIGINAL).unwrap();
        if mode == 0 {
            assert!(!Arc::ptr_eq(&old.guard, &current.guard));
            let ttl: i64 = redis::cmd("PTTL").arg(&key).query(&mut connection).unwrap();
            assert!(ttl > 59_000 && ttl <= 300_000);
        } else {
            assert!(Arc::ptr_eq(&old.guard, &current.guard));
            assert_eq!(old.freshness.receipt, current.freshness.receipt);
            let value: String = if mode == 1 {
                redis::cmd("HGET")
                    .arg(&key)
                    .arg("A")
                    .query(&mut connection)
                    .unwrap()
            } else {
                redis::cmd("GET").arg(&key).query(&mut connection).unwrap()
            };
            assert_eq!(value, if mode == 1 { "conflict" } else { "wrong-type" });
        }
        drop(cache);
        assert_eq!(fixture.finish().len(), 2);
    }
}

#[test]
#[ignore = "requires scripts/validation/test_client_jwks_cache.py"]
fn owned_live_guard_survives_eviction_during_current_acquisition() {
    let _env = env_lock().unwrap();
    for conflict in [false, true] {
        let state = new_state();
        let mut response = if conflict {
            let changed = serde_json::to_vec(&serde_json::json!({"keys":[{"kty":"RSA","kid":"A","n":"AQ","e":"AQAB","alg":"RS256"}]})).unwrap();
            Step::new(200, changed).header("Cache-Control", "max-age=60")
        } else {
            Step::not_modified("\"A\"")
        };
        let intervention = state.clone();
        response.before_response = Some(Box::new(move || {
            let mut cache = intervention.inner.cache.lock().unwrap();
            cache.guards.remove(ORIGINAL);
            cache.representations.remove(ORIGINAL);
        }));
        let fixture = Fixture::new(vec![cached("A", "max-age=0"), response], false);
        let policy = fixture.policy();
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            Some("A")
        );
        assert_eq!(
            kid(fetch_jwks_with_state(&state, &policy, ORIGINAL)).as_deref(),
            if conflict { None } else { Some("A") }
        );
        assert_eq!(fixture.finish().len(), 2);
        assert_eq!(
            state
                .inner
                .cache
                .lock()
                .unwrap()
                .guards
                .contains_key(ORIGINAL),
            !conflict
        );
    }
}

#[test]
fn capacity_evicts_stored_oldest_before_delayed_incoming_admission() {
    let mut cache = super::super::jwks_runtime_state::JwksLocalCache::default();
    let now = Instant::now();
    let mut existing = typed_entry("B");
    existing.guard = Arc::new(KidGuard {
        kid_fps: existing.guard.kid_fps.clone(),
        admitted_at: now + Duration::from_secs(1),
        deadline: now + Duration::from_secs(60),
    });
    existing.fetched_at = now + Duration::from_secs(1);
    cache.insert("b".into(), existing);
    let mut incoming = typed_entry("A");
    incoming.fetched_at = now;
    incoming.guard = Arc::new(KidGuard {
        kid_fps: incoming.guard.kid_fps.clone(),
        admitted_at: now,
        deadline: now + Duration::from_secs(60),
    });
    let accepted_owned = incoming.jwks.clone();
    let guard = incoming.guard.clone();
    cache
        .publish(
            "a",
            guard.clone(),
            Some(incoming),
            now + Duration::from_secs(2),
            1,
        )
        .unwrap();
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.guards.len(), 1);
    assert!(!cache.contains_key("b"));
    assert!(!cache.guards.contains_key("b"));
    assert!(Arc::ptr_eq(&cache.guards["a"], &guard));
    assert!(Arc::ptr_eq(&cache.get("a").unwrap().guard, &guard));
    assert_eq!(kid(Some(accepted_owned)).as_deref(), Some("A"));
}
