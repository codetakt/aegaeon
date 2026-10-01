use super::*;
use axum::{
    extract::{Form, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use std::collections::{HashMap, VecDeque};
use tokio::sync::Notify;

mod scenarios;

#[derive(Clone)]
enum Reply {
    Status(u16, Vec<String>),
    Hold,
    BeforeAck(Arc<dyn Fn() + Send + Sync>),
}
#[derive(Clone)]
struct Recipient {
    key: crate::oidc::OidcSigningKey,
    tokens: Arc<Mutex<Vec<(String, String)>>>,
    replies: Arc<Mutex<HashMap<String, VecDeque<Reply>>>>,
    entered: Arc<Notify>,
}
async fn receive(
    State(state): State<Recipient>,
    Form(form): Form<HashMap<String, String>>,
) -> axum::response::Response {
    let token = form.get("logout_token").expect("token").clone();
    let claims = verify_token(&state.key, &token, "logout+jwt").expect("recipient real signature");
    assert_eq!(claims["iss"], ISSUER);
    assert!(claims.get("nonce").is_none());
    let aud = claims["aud"].as_str().expect("audience").to_string();
    state
        .tokens
        .lock()
        .expect("tokens")
        .push((aud.clone(), token));
    state.entered.notify_one();
    let reply = state
        .replies
        .lock()
        .expect("replies")
        .get_mut(&aud)
        .and_then(VecDeque::pop_front)
        .unwrap_or(Reply::Status(204, vec![]));
    match reply {
        Reply::Hold => std::future::pending().await,
        Reply::BeforeAck(callback) => {
            callback();
            StatusCode::OK.into_response()
        }
        Reply::Status(status, retries) => {
            let mut headers = HeaderMap::new();
            for retry in retries {
                headers.append(
                    "retry-after",
                    HeaderValue::from_str(&retry).expect("fixture header"),
                );
            }
            if status == 302 {
                headers.insert("location", HeaderValue::from_static("/follow"));
            }
            (StatusCode::from_u16(status).expect("status"), headers).into_response()
        }
    }
}

struct HttpFixture {
    cfg: OidcConfig,
    clients: ClientRegistry,
    recipient: Recipient,
    _task: FixtureTask,
}
impl HttpFixture {
    async fn new(replies: &[(&str, Vec<Reply>)]) -> TestResult<Self> {
        let key = local_key()?;
        let recipient = Recipient {
            key: key.clone(),
            tokens: Arc::new(Mutex::new(Vec::new())),
            replies: Arc::new(Mutex::new(
                replies
                    .iter()
                    .map(|(client, list)| (client.to_string(), list.clone().into()))
                    .collect(),
            )),
            entered: Arc::new(Notify::new()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let uri = format!("http://{}/logout", listener.local_addr()?);
        let app = Router::new()
            .route("/logout", post(receive))
            .route("/follow", post(receive))
            .with_state(recipient.clone());
        let task = FixtureTask(tokio::spawn(async move {
            axum::serve(listener, app).await.expect("recipient");
        }));
        let clients = ClientRegistry::new_process_local_for_tests();
        for client in ["a", "b"] {
            clients.register(super::super::delivery::client(client, &uri, false));
        }
        Ok(Self {
            cfg: config(key),
            clients,
            recipient,
            _task: task,
        })
    }
    async fn send(
        &self,
        f: &SessionFixture,
        second: bool,
        now: u64,
    ) -> BackchannelLogoutDispatchReport {
        dispatch_at(
            &self.cfg,
            &self.clients,
            Some(if second { &f.b } else { &f.a }),
            &f.event,
            Clock {
                fixed: Some(UNIX_EPOCH + Duration::from_secs(now)),
            },
        )
        .await
    }
    fn tokens(&self) -> Vec<(String, String)> {
        self.recipient.tokens.lock().expect("tokens").clone()
    }
}

fn runtime_test(work: impl std::future::Future<Output = TestResult>) -> TestResult {
    let _lock = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let _flag = super::super::delivery::LoopbackFlag::enable();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(work)
}

async fn replay_and_retry(mut f: SessionFixture) -> TestResult {
    let http = HttpFixture::new(&[(
        "a",
        vec![Reply::Status(503, vec![]), Reply::Status(204, vec![])],
    )])
    .await?;
    let first = http.send(&f, false, NOW).await;
    assert_eq!((first.sent, first.delivered, first.deferred), (2, 1, 1));
    for seconds in [0, 4] {
        let report = http.send(&f, true, NOW + seconds).await;
        assert_eq!(
            (report.sent, report.already_delivered, report.deferred),
            (0, 1, 1)
        );
    }
    let retry = http.send(&f, true, NOW + 5).await;
    assert_eq!(
        (retry.sent, retry.delivered, retry.already_delivered),
        (1, 1, 1)
    );
    assert_eq!(http.send(&f, false, NOW + 6).await.sent, 0);
    let tokens = http.tokens();
    assert_eq!(tokens.len(), 3);
    assert!(tokens[0].1 == tokens[2].1);
    let a = verify_token(&http.cfg.signing_key, &tokens[0].1, "logout+jwt")?;
    let b = verify_token(&http.cfg.signing_key, &tokens[1].1, "logout+jwt")?;
    assert_ne!(a["jti"], b["jti"]);
    assert_ne!(a["jti"], f.event.jti);
    f.event.client_ids = vec!["unassociated".to_string()];
    assert_eq!(http.send(&f, false, NOW + 7).await.storage_failures, 1);
    assert_eq!(http.tokens().len(), 3);
    Ok(())
}

#[test]
fn logout_delivery_local_http_replay_and_canonical_retry() -> TestResult {
    runtime_test(async { replay_and_retry(SessionFixture::local(600)?).await })
}
#[test]
#[ignore = "requires scoped AEGAEON_TEST_REDIS_URL"]
fn logout_delivery_redis_http_replay_and_canonical_retry() -> TestResult {
    runtime_test(async { replay_and_retry(SessionFixture::redis(600)?).await })
}
