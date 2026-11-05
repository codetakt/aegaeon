use super::*;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use sqlx::{postgres::PgPoolOptions, Executor};
use std::collections::VecDeque;
use tokio::task::JoinHandle;

#[derive(Clone)]
struct Reply {
    status: StatusCode,
    headers: Vec<(&'static str, &'static str)>,
    body: String,
}
#[derive(Clone, Default)]
struct ServerState {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    requests: Arc<Mutex<Vec<HeaderMap>>>,
    hold: Option<Arc<tokio::sync::Notify>>,
    entered: Option<Arc<tokio::sync::Notify>>,
}
async fn respond(State(state): State<ServerState>, headers: HeaderMap) -> impl IntoResponse {
    state.requests.lock().unwrap().push(headers);
    if let Some(entered) = &state.entered {
        entered.notify_one();
    }
    if let Some(hold) = &state.hold {
        let _ = tokio::time::timeout(Duration::from_secs(10), hold.notified()).await;
    }
    let reply = state.replies.lock().unwrap().pop_front().unwrap_or(Reply {
        status: StatusCode::SERVICE_UNAVAILABLE,
        headers: vec![],
        body: String::new(),
    });
    let mut response = (reply.status, reply.body).into_response();
    for (name, value) in reply.headers {
        response.headers_mut().insert(name, value.parse().unwrap());
    }
    response
}
struct Server {
    uri: String,
    state: ServerState,
    task: JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn new(replies: Vec<Reply>, hold: bool) -> anyhow::Result<Self> {
        let state = ServerState {
            replies: Arc::new(Mutex::new(replies.into())),
            hold: hold.then(|| Arc::new(tokio::sync::Notify::new())),
            entered: hold.then(|| Arc::new(tokio::sync::Notify::new())),
            ..Default::default()
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let uri = format!("http://{}/keys", listener.local_addr()?);
        let app = Router::new()
            .route("/keys", get(respond))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { uri, state, task })
    }
    fn count(&self) -> usize {
        self.state.requests.lock().unwrap().len()
    }
}
struct Fixture {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    name: String,
    runtime: Arc<NativeJwksRuntime>,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
            .await?;
        let name = format!("jwks_native_{}", uuid::Uuid::new_v4().simple());
        admin
            .execute(format!("CREATE DATABASE {name}").as_str())
            .await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(admin.connect_options().as_ref().clone().database(&name))
            .await?;
        pool.execute("CREATE SCHEMA aegaeon").await?;
        sqlx::raw_sql(crate::organization_schema::component!(
            "runtime_jwks_admission"
        ))
        .execute(&pool)
        .await?;
        let runtime = NativeJwksRuntime::new(
            pool.clone(),
            &crate::config::RuntimeStateNamespace::from_environment_id(uuid::Uuid::new_v4()),
            JwksRuntimePolicy {
                allow_http_loopback_for_tests: true,
                http_retries: 0,
                ..Default::default()
            },
        )
        .map_err(anyhow::Error::msg)?;
        Ok(Self {
            admin,
            pool,
            name,
            runtime: Arc::new(runtime),
        })
    }
    async fn cleanup(self) -> anyhow::Result<()> {
        self.pool.close().await;
        self.admin
            .execute(format!("DROP DATABASE {}", self.name).as_str())
            .await?;
        self.admin.close().await;
        Ok(())
    }
}
fn body(kid: &str, alg: jsonwebtoken::Algorithm) -> String {
    let (mut key, _) = crate::test_utils::jwk_usage::material(alg);
    key["kid"] = serde_json::json!(kid);
    serde_json::json!({"keys":[key]}).to_string()
}
fn ok(body: String, control: &'static str) -> Reply {
    Reply {
        status: StatusCode::OK,
        headers: vec![("etag", "\"A\""), ("cache-control", control)],
        body,
    }
}
async fn fetch(runtime: &Arc<NativeJwksRuntime>, uri: &str) -> anyhow::Result<Arc<Body>> {
    runtime
        .fetch(uri)
        .await
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("JWKS refused"))
}

#[tokio::test]
#[ignore = "requires PostgreSQL; native HTTP, positive authority, one-connection pool"]
async fn pg_jwks_native_cache_requires_database() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let server = Server::new(
            vec![
                ok(body("A", jsonwebtoken::Algorithm::RS256), "max-age=60"),
                ok(body("A", jsonwebtoken::Algorithm::RS256), "max-age=60"),
                Reply {
                    status: StatusCode::NOT_MODIFIED,
                    headers: vec![("etag", "\"A\"")],
                    body: String::new(),
                },
            ],
            false,
        )
        .await?;
        let first = fetch(&f.runtime, &server.uri).await?;
        let second = fetch(&f.runtime, &server.uri).await?;
        anyhow::ensure!(Arc::ptr_eq(&first, &second) && server.count() == 1);
        let runtime = f.runtime.clone();
        anyhow::ensure!(std::thread::spawn(move || {
            let _guard = runtime.cache.lock().unwrap();
            panic!("intentional optional cache poison");
        })
        .join()
        .is_err());
        let recovered = fetch(&f.runtime, &server.uri).await?;
        anyhow::ensure!(
            !f.runtime.cache.is_poisoned()
                && !Arc::ptr_eq(&first, &recovered)
                && server.count() == 2
        );
        f.pool
            .execute("DELETE FROM aegaeon.runtime_jwks_bindings")
            .await?;
        let third = fetch(&f.runtime, &server.uri).await?;
        anyhow::ensure!(
            Arc::ptr_eq(&recovered, &third) && server.count() == 3,
            "missing DB authority requires actual 304 exchange"
        );
        anyhow::ensure!(server.state.requests.lock().unwrap()[2]
            .get("if-none-match")
            .is_some());
        f.runtime.cleanup().await.map_err(anyhow::Error::msg)?;
        f.pool.close().await;
        anyhow::ensure!(f.runtime.fetch(&server.uri).await.is_err() && server.count() == 3);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    f.cleanup().await?;
    result
}
#[tokio::test]
#[ignore = "requires PostgreSQL; conditional downgrade and redirect isolation"]
async fn pg_jwks_native_conditional_downgrade() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let server = Server::new(
            vec![
                ok(body("A", jsonwebtoken::Algorithm::RS256), "no-cache"),
                Reply {
                    status: StatusCode::NOT_MODIFIED,
                    headers: vec![("etag", "\"wrong\"")],
                    body: String::new(),
                },
                ok(body("B", jsonwebtoken::Algorithm::ES256), "no-cache"),
                Reply {
                    status: StatusCode::FOUND,
                    headers: vec![("location", "/other")],
                    body: String::new(),
                },
                Reply {
                    status: StatusCode::FOUND,
                    headers: vec![("location", "/other")],
                    body: String::new(),
                },
            ],
            false,
        )
        .await?;
        fetch(&f.runtime, &server.uri).await?;
        let next = fetch(&f.runtime, &server.uri).await?;
        anyhow::ensure!(next.jwks.keys()[0].kid.as_deref() == Some("B"));
        anyhow::ensure!(f.runtime.fetch(&server.uri).await.is_err());
        let requests = server.state.requests.lock().unwrap();
        anyhow::ensure!(requests.len() == 5);
        for (index, request) in requests.iter().enumerate() {
            anyhow::ensure!(request.contains_key("if-none-match") == matches!(index, 1 | 3));
            anyhow::ensure!(!request.contains_key("referer"));
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    f.cleanup().await?;
    result
}
#[tokio::test]
#[ignore = "requires PostgreSQL; duplicate JSON and changed retained key refusal"]
async fn pg_jwks_native_invalid_body_and_kid_change() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let server = Server::new(
            vec![
                ok(body("A", jsonwebtoken::Algorithm::RS256), "no-store"),
                ok("{\"keys\":[],\"keys\":[]}".into(), "no-store"),
                ok(body("A", jsonwebtoken::Algorithm::ES256), "no-store"),
            ],
            false,
        )
        .await?;
        let first = fetch(&f.runtime, &server.uri).await?;
        anyhow::ensure!(f.runtime.fetch(&server.uri).await.is_err());
        anyhow::ensure!(f
            .runtime
            .fetch(&server.uri)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        anyhow::ensure!(f
            .runtime
            .state
            .current_body(&server.uri, &first.admission.body_digest())
            .await
            .map_err(anyhow::Error::msg)?);
        anyhow::ensure!(server.count() == 3);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    f.cleanup().await?;
    result
}
#[tokio::test]
#[ignore = "requires PostgreSQL; no connection across HTTP and bounded cancellation lease"]
async fn pg_jwks_native_cancelled_fetch_is_bounded() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let server = Server::new(
            vec![ok(body("A", jsonwebtoken::Algorithm::RS256), "max-age=60")],
            true,
        )
        .await?;
        let runtime = f.runtime.clone();
        let uri = server.uri.clone();
        let task = tokio::spawn(async move { runtime.fetch(&uri).await });
        tokio::time::timeout(
            Duration::from_secs(5),
            server.state.entered.as_ref().unwrap().notified(),
        )
        .await?;
        let available = tokio::time::timeout(
            Duration::from_secs(1),
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&f.pool),
        )
        .await??;
        anyhow::ensure!(
            available == 1,
            "network must not hold the only SQL connection"
        );
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..31 {
            let runtime = f.runtime.clone();
            let uri = server.uri.clone();
            tasks.spawn(async move { runtime.fetch(&uri).await.map(|v| v.is_none()) });
        }
        while let Some(result) = tasks.join_next().await {
            anyhow::ensure!(result?.map_err(anyhow::Error::msg)?);
        }
        anyhow::ensure!(server.count() == 1);
        task.abort();
        anyhow::ensure!(matches!(task.await, Err(error) if error.is_cancelled()));
        anyhow::ensure!(f
            .runtime
            .fetch(&server.uri)
            .await
            .map_err(anyhow::Error::msg)?
            .is_none());
        // Controlled persisted expiry, not an assertion about wall-clock recovery latency.
        f.pool
            .execute("UPDATE aegaeon.runtime_jwks_fetches SET lease_until_us=1")
            .await?;
        server.state.hold.as_ref().unwrap().notify_one();
        server.state.hold.as_ref().unwrap().notify_one();
        // The cancelled server handler may consume a notification; release the
        // remaining owned handler while the replacement request is pending.
        let runtime = f.runtime.clone();
        let uri = server.uri.clone();
        let next = tokio::spawn(async move { runtime.fetch(&uri).await });
        tokio::time::timeout(
            Duration::from_secs(5),
            server.state.entered.as_ref().unwrap().notified(),
        )
        .await?;
        server
            .state
            .replies
            .lock()
            .unwrap()
            .push_back(ok(body("A", jsonwebtoken::Algorithm::RS256), "max-age=60"));
        server.state.hold.as_ref().unwrap().notify_waiters();
        anyhow::ensure!(tokio::time::timeout(Duration::from_secs(5), next)
            .await??
            .map_err(anyhow::Error::msg)?
            .is_some());
        Ok::<_, anyhow::Error>(())
    }
    .await;
    f.cleanup().await?;
    result
}

mod consumers;
