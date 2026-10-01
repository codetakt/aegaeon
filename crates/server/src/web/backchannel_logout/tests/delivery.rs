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
    sid: String,
    event_jti: String,
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
    let claims = decoded;
    assert_eq!(claims["sid"], recipient.sid);
    assert_ne!(claims["jti"], recipient.event_jti);
    assert_eq!(claims["sub"].as_str(), sub);
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(
        claims["exp"].as_u64(),
        claims["iat"].as_u64().and_then(|iat| iat.checked_add(300))
    );
    assert_eq!(claims["events"], json!({BACKCHANNEL_LOGOUT_EVENT_URI:{}}));
    assert!(claims.get("nonce").is_none());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    assert!(claims["iat"].as_u64().expect("iat") <= now);
    assert!(claims["exp"].as_u64().expect("exp") > now);
    recipient.accepted.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}

pub(super) struct LoopbackFlag(Option<std::ffi::OsString>);
impl LoopbackFlag {
    pub(super) fn enable() -> Self {
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

pub(super) fn client(
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
        let sessions = crate::oidc::OidcSessionStore::new_process_local_for_tests();
        let sid = sessions.get_or_create_session("subject", "browser");
        sessions.add_client(&sid, "with-sub");
        sessions.add_client(&sid, "sid-only");
        let event = sessions.logout_by_sid(&sid).expect("logout event");
        let accepted = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/logout", post(receive_logout))
            .with_state(Recipient {
                key: key.clone(),
                accepted: accepted.clone(),
                sid: sid.clone(),
                event_jti: event.jti.clone(),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let uri = format!("http://{}/logout", listener.local_addr()?);
        let _fixture = FixtureTask(tokio::spawn(async move {
            axum::serve(listener, app).await.expect("recipient server");
        }));
        let clients = ClientRegistry::new_process_local_for_tests();
        clients.register(client("with-sub", &uri, false));
        clients.register(client("sid-only", &uri, true));
        let cfg = config(key);
        let synchronous = tokio::task::block_in_place(|| {
            dispatch_backchannel_logout(&cfg, &clients, Some(&sessions), &event)
        });
        let asynchronous =
            dispatch_backchannel_logout_async(&cfg, &clients, Some(&sessions), &event).await;
        assert_eq!(synchronous.targeted_clients, 2);
        assert_eq!(synchronous.delivered, 2);
        assert!(!synchronous.has_failures());
        assert_eq!(asynchronous.delivered, 0);
        assert_eq!(asynchronous.already_delivered, 2);
        assert!(!asynchronous.has_failures());
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        Ok(())
    })
}
