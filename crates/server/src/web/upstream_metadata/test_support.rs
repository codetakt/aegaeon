use axum::{extract::State, http::StatusCode, routing::any, Router};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub(in crate::web) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
pub(in crate::web) struct ManualClock {
    origin: Instant,
    millis: Arc<AtomicU64>,
}
impl ManualClock {
    pub(in crate::web) fn new() -> Self {
        Self {
            origin: Instant::now(),
            millis: Arc::new(AtomicU64::new(0)),
        }
    }
    pub(in crate::web) fn advance(&self, millis: u64) {
        self.millis.fetch_add(millis, Ordering::SeqCst);
    }
    pub(in crate::web) fn coordinator(&self) -> crate::upstream::UpstreamJwksFetchCoordinator {
        let clock = self.clone();
        crate::upstream::UpstreamJwksFetchCoordinator::with_clock(Arc::new(move || {
            clock.origin + Duration::from_millis(clock.millis.load(Ordering::SeqCst))
        }))
    }
}

pub(in crate::web) struct HttpState {
    pub(in crate::web) hits: AtomicUsize,
    response: Mutex<(StatusCode, String)>,
    pub(in crate::web) hold: AtomicBool,
    pub(in crate::web) release: Semaphore,
}

pub(in crate::web) struct HttpFixture {
    pub(in crate::web) url: String,
    pub(in crate::web) state: Arc<HttpState>,
    server: tokio::task::JoinHandle<()>,
}
impl HttpFixture {
    pub(in crate::web) async fn new(body: String) -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let state = Arc::new(HttpState {
            hits: AtomicUsize::new(0),
            response: Mutex::new((StatusCode::OK, body)),
            hold: AtomicBool::new(false),
            release: Semaphore::new(0),
        });
        let app = Router::new()
            .fallback(any(reply))
            .with_state(Arc::clone(&state));
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { url, state, server })
    }
    pub(in crate::web) fn respond(&self, status: StatusCode, body: String) {
        *self.state.response.lock().expect("response lock") = (status, body);
    }
    pub(in crate::web) fn hits(&self) -> usize {
        self.state.hits.load(Ordering::SeqCst)
    }
    pub(in crate::web) async fn wait_hits(&self, count: usize) -> TestResult {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.hits() < count {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
}
impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn reply(State(state): State<Arc<HttpState>>) -> (StatusCode, String) {
    state.hits.fetch_add(1, Ordering::SeqCst);
    if state.hold.load(Ordering::SeqCst) {
        let permit = state.release.acquire().await.expect("fixture semaphore");
        permit.forget();
    }
    state.response.lock().expect("response lock").clone()
}
