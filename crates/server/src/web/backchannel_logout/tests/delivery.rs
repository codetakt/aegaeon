use super::*;
use axum::{
    extract::{Form, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct Recipient {
    key: OidcSigningKey,
    accepted: Arc<AtomicUsize>,
}

async fn receive_logout(
    State(recipient): State<Recipient>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> StatusCode {
    assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
    assert_eq!(form.len(), 1);
    let token = form.get("logout_token").expect("logout_token form field");
    // Validate signature, audience, type, event and expiry before acknowledging.
    let decoded = verify_token(&recipient.key, token, "logout+jwt").expect("recipient signature");
    let audience = decoded["aud"].as_str().expect("audience");
    let sub = match audience {
        "with-sub" => Some("subject"),
        "sid-only" => None,
        _ => panic!("unexpected audience"),
    };
    let claims = verify_logout(&recipient.key, token, audience, sub).expect("recipient claims");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    assert!(claims["iat"].as_u64().expect("iat") <= now);
    assert!(claims["exp"].as_u64().expect("exp") > now);
    recipient.accepted.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}

struct LoopbackFlag(Option<std::ffi::OsString>);
impl LoopbackFlag {
    fn enable() -> Self {
        let previous = std::env::var_os(BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV);
        std::env::set_var(BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV, "true");
        Self(previous)
    }
}
impl Drop for LoopbackFlag {
    fn drop(&mut self) {
        if let Some(previous) = &self.0 {
            std::env::set_var(
                BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV,
                previous,
            );
        } else {
            std::env::remove_var(BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV);
        }
    }
}

fn client(
    client_id: &str,
    uri: &str,
    require_sid: bool,
) -> crate::client_registry::RegisteredClient {
    crate::client_registry::RegisteredClient {
        client_id: client_id.to_string(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: Some(uri.to_string()),
        backchannel_logout_session_required: require_sid,
        token_endpoint_auth_method: "none".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: vec!["openid".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        registration_access_token: None,
        client_id_issued_at: None,
    }
}

#[test]
fn logout_profile_http_recipient_accepts_sync_and_async_delivery() -> TestResult {
    let _lock = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|err| anyhow::anyhow!("{err}"))?;
    let _flag = LoopbackFlag::enable();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let key = local_key()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/logout", post(receive_logout))
            .with_state(Recipient {
                key: key.clone(),
                accepted: accepted.clone(),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let uri = format!("http://{}/logout", listener.local_addr()?);
        let _fixture = FixtureTask(tokio::spawn(async move {
            axum::serve(listener, app).await.expect("recipient server");
        }));
        let clients = ClientRegistry::new_process_local_for_tests();
        clients.register(client("with-sub", &uri, false));
        clients.register(client("sid-only", &uri, true));
        let event = OidcLogoutEvent {
            sid: "session".to_string(),
            user_id: "subject".to_string(),
            jti: "logout-event".to_string(),
            client_ids: vec!["with-sub".to_string(), "sid-only".to_string()],
        };
        let cfg = config(key);
        let synchronous =
            tokio::task::block_in_place(|| dispatch_backchannel_logout(&cfg, &clients, &event));
        let asynchronous = dispatch_backchannel_logout_async(&cfg, &clients, &event).await;
        for report in [synchronous, asynchronous] {
            assert_eq!(report.targeted_clients, 2);
            assert_eq!(report.delivered, 2);
            assert!(!report.has_failures());
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 4);
        Ok(())
    })
}
