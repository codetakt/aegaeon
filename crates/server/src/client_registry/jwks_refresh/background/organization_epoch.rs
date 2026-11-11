//! Focused Organizations background ownership regressions.
use super::*;
use crate::client_registry::{
    jwks_cache_control::{CacheMetadata, Freshness},
    jwks_fetch::fetch_jwks_with_state,
    jwks_runtime_state::{JwksSharedRuntimeState, RedisJwksRuntimeState},
    jwks_types::{CacheEntry, FetchedJwks, KidGuard},
    jwks_validation::build_kid_fingerprints,
    jwks_validators::{DateContext, JwksValidators},
};
use crate::organizations::{
    request_work::{async_store, Admission},
    witness::tests::caller_fixture::CallerFixture,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

fn policy() -> JwksRuntimePolicy {
    JwksRuntimePolicy {
        allow_http_loopback_for_tests: true,
        http_retries: 0,
        http_timeout_secs: 3,
        cache_ttl_secs: 60,
        shared_state_max_age_secs: 60,
        circuit_reset_secs: 15,
        refresh_skew_secs: 120,
        ..JwksRuntimePolicy::default()
    }
}

fn body(kid: &str) -> serde_json::Value {
    let (mut key, _) = crate::test_utils::jwk_usage::material(jsonwebtoken::Algorithm::RS256);
    key["kid"] = serde_json::json!(kid);
    serde_json::json!({"keys": [key]})
}

fn seed(state: &JwksRuntimeState, uri: &str) -> anyhow::Result<CacheEntry> {
    let now = Instant::now();
    let jwks: FetchedJwks = serde_json::from_value(body("cached"))?;
    let entry = CacheEntry {
        validators: JwksValidators::default(),
        effective_target: None,
        metadata: CacheMetadata::from_headers(
            &reqwest::header::HeaderMap::new(),
            DateContext::capture(),
        ),
        freshness: Freshness {
            receipt: now,
            initial_age: Some(0),
            lifetime: Some(Duration::from_secs(60).as_nanos()),
            no_cache: false,
        },
        retain_until: now + Duration::from_secs(60),
        fetched_at: now,
        guard: Arc::new(KidGuard {
            kid_fps: build_kid_fingerprints(&jwks),
            admitted_at: now,
            deadline: now + Duration::from_secs(60),
        }),
        jwks,
    };
    state
        .inner
        .cache
        .lock()
        .unwrap()
        .insert(uri.to_owned(), entry.clone());
    Ok(entry)
}

struct Response {
    uri: String,
    reached: Option<tokio::sync::oneshot::Receiver<()>>,
    release: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<anyhow::Result<()>>>,
}

impl Response {
    fn new() -> anyhow::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let uri = format!("http://{}/{}", listener.local_addr()?, uuid::Uuid::new_v4());
        let bytes = serde_json::to_vec(&body("refreshed"))?;
        let (reached, receiver) = tokio::sync::oneshot::channel();
        let (release, wait) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        anyhow::ensure!(Instant::now() < deadline, "JWKS request deadline");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            stream.set_write_timeout(Some(Duration::from_secs(3)))?;
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                anyhow::ensure!(request.len() < 8192, "bounded JWKS request");
                let mut byte = [0];
                stream.read_exact(&mut byte)?;
                request.push(byte[0]);
            }
            let _ = reached.send(());
            wait.recv_timeout(Duration::from_secs(5))?;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nCache-Control: max-age=60\r\nConnection: close\r\n\r\n", bytes.len())?;
            stream.write_all(&bytes)?;
            stream.flush()?;
            Ok(())
        });
        Ok(Self {
            uri,
            reached: Some(receiver),
            release: Some(release),
            thread: Some(thread),
        })
    }

    async fn wait(&mut self) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(3), self.reached.take().unwrap()).await??;
        Ok(())
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("JWKS fixture panicked"))??;
        }
        Ok(())
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[tokio::test]
async fn organizations_jwks_background_refuses_closed_and_conflicting_owners() -> anyhow::Result<()>
{
    let state = JwksRuntimeState::default();
    let uri = "http://127.0.0.1:1/refused";
    let policy = policy();
    let refuse = || -> anyhow::Result<()> {
        let lock = state
            .inner
            .coordination
            .fetch_lock(1, uri)
            .unwrap()
            .unwrap();
        let _guard = lock.lock().unwrap();
        spawn_jwks_refresh_once_with_state(&state, policy.clone(), uri);
        anyhow::ensure!(state
            .inner
            .coordination
            .background_refreshes
            .lock()
            .unwrap()
            .is_empty());
        anyhow::ensure!(
            Arc::strong_count(&lock) == 2,
            "invalid scope must not start a refresh"
        );
        Ok(())
    };
    let first = Admission::isolated_for_test()?;
    crate::redis_io::organization::scope(first.clone(), || {
        first.close_until_restart();
        refuse()
    })??;
    let second = Admission::isolated_for_test()?;
    let third = Admission::isolated_for_test()?;
    second
        .store_scope(async { crate::redis_io::organization::scope(third, refuse) })
        .await???;
    Ok(())
}

#[test]
fn organizations_jwks_refresh_marker_cleans_dropped_or_panicking_closure() {
    let state = JwksRuntimeState::default();
    let uri = "https://example.com/unstarted";
    for panic in [false, true] {
        assert!(state
            .inner
            .coordination
            .mark_background_refresh_started(1, uri)
            .unwrap());
        let marker = RefreshMarker {
            state: state.clone(),
            uri: uri.into(),
        };
        let operation = move || {
            let _marker = marker;
            assert!(!panic, "injected refresh panic");
        };
        if panic {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).is_err());
        } else {
            // A rejected thread spawn drops its unexecuted closure.
            drop(operation);
        }
        assert!(state
            .inner
            .coordination
            .background_refreshes
            .lock()
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL witness and isolated Redis with multiple databases"]
async fn shared_redis_organizations_jwks_background_retains_parent_and_refuses_foreign_database(
) -> anyhow::Result<()> {
    let witness = CallerFixture::with_test_stores(
        uuid::Uuid::new_v4(),
        std::env::var("AEGAEON_DATABASE_URL")?.parse()?,
    )
    .await?;
    let selected = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let mut foreign = url::Url::parse(&selected)?;
    let db = redis::Client::open(selected.as_str())?
        .get_connection_info()
        .redis
        .db;
    foreign.set_path(if db == 0 { "/1" } else { "/0" });
    let mut result = Ok(());
    for is_foreign in [false, true] {
        if result.is_err() {
            break;
        }
        let endpoint = if is_foreign {
            foreign.as_str()
        } else {
            &selected
        };
        let mut response = Response::new()?;
        let redis = RedisJwksRuntimeState::new_for_tests(endpoint)?;
        let keys = [
            redis.key("kid-fps", &response.uri),
            redis.key("circuit", &response.uri),
        ];
        let state = JwksRuntimeState::with_shared_state(JwksSharedRuntimeState::Redis(redis));
        result = observed_refresh(&witness, &state, &mut response, is_foreign).await;
        let cleanup = clean(endpoint, &keys, is_foreign).await;
        result = result.and(cleanup);
    }
    let finish = witness.finish().await;
    result.and(finish)
}

async fn observed_refresh(
    witness: &CallerFixture,
    state: &JwksRuntimeState,
    response: &mut Response,
    foreign: bool,
) -> anyhow::Result<()> {
    let before = seed(state, &response.uri)?;
    let work = witness.begin().await?;
    let closed = work.admission().closure_probe_for_test();
    let fetch_state = state.clone();
    let uri = response.uri.clone();
    let hit = work
        .store_scope(async_store::blocking(move || {
            fetch_jwks_with_state(&fetch_state, &policy(), &uri)
        }))
        .await??
        .ok_or_else(|| anyhow::anyhow!("fresh cached body required"))?;
    anyhow::ensure!(hit.keys()[0].kid.as_deref() == Some("cached"));
    response.wait().await?;
    {
        let cache = state.inner.cache.lock().unwrap();
        let current = cache.get(&response.uri).unwrap();
        anyhow::ensure!(Arc::ptr_eq(&before.guard, &current.guard));
        anyhow::ensure!(
            before.fetched_at == current.fetched_at && before.retain_until == current.retain_until,
            "fresh hit and pending refresh must not renew cached authority"
        );
    }
    let completion = tokio::spawn(work.complete());
    tokio::time::sleep(Duration::from_millis(50)).await;
    let retained = !completion.is_finished() && witness.pending().await? == 1;
    response.finish()?;
    let completed = tokio::time::timeout(Duration::from_secs(10), completion).await??;
    anyhow::ensure!(
        retained,
        "background refresh must retain child and parent completion"
    );
    if foreign {
        anyhow::ensure!(completed.is_err() && closed.is_closed());
        // Refusal closes admission before the rejected worker necessarily exits.
        // Wait for every retained owner to release the isolated permit before
        // checking its marker or cleaning the real stores; do not reopen admission.
        tokio::time::timeout(Duration::from_secs(10), async {
            while closed.available_permits() != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("JWKS refresh owners did not finish"))?;
        anyhow::ensure!(witness.pending().await? == 1);
    } else {
        anyhow::ensure!(completed?.pending == 0 && !closed.is_closed());
    }
    anyhow::ensure!(state
        .inner
        .coordination
        .background_refreshes
        .lock()
        .unwrap()
        .is_empty());
    let cache = state.inner.cache.lock().unwrap();
    let current = cache.get(&response.uri).unwrap();
    if foreign {
        anyhow::ensure!(
            Arc::ptr_eq(&before.guard, &current.guard),
            "foreign result must not replace cache"
        );
    } else {
        anyhow::ensure!(current.jwks.keys()[0].kid.as_deref() == Some("refreshed"));
        anyhow::ensure!(current.freshness.lifetime == Some(Duration::from_secs(60).as_nanos()));
        anyhow::ensure!(current.freshness.reusable(Instant::now()));
        anyhow::ensure!(
            current
                .guard
                .deadline
                .duration_since(current.guard.admitted_at)
                == Duration::from_secs(60)
        );
    }
    Ok(())
}

async fn clean(endpoint: &str, keys: &[String], foreign: bool) -> anyhow::Result<()> {
    let client = redis::Client::open(endpoint)?;
    let keys = keys.to_vec();
    tokio::task::spawn_blocking(move || {
        let mut connection = crate::redis_io::connect(&client)?;
        let pong: String = redis::cmd("PING").query(&mut connection)?;
        let present: i64 = redis::cmd("EXISTS").arg(&keys).query(&mut connection)?;
        redis::cmd("DEL").arg(keys).query::<i64>(&mut connection)?;
        anyhow::ensure!(
            pong == "PONG" && (!foreign || present == 0),
            "foreign ledger and circuit must remain untouched on a usable backend"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
