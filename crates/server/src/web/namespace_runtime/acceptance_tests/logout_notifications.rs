//! The existing loopback test flag permits transport observation; this does not test TLS.
use super::{
    authorization_fixture as f,
    browser_consumption::session,
    management_fixture as m,
    support::{remote, unavailable, unavailable_states, TestResult},
};
use crate::{
    oidc::OidcSessionStore,
    web::{self, test_support::TestEnvironment, AppState},
};
use axum::{
    extract::{OriginalUri, State},
    http::StatusCode,
    routing::post,
    Form, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

struct Receiver {
    messages: UnboundedReceiver<String>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Drop for Receiver {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn notifications(state: &mut AppState) -> TestResult<Receiver> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/logout", listener.local_addr()?);
    web::backchannel_logout::validate_backchannel_logout_dispatch_uri(&endpoint).map_err(|_| {
        "set AEGAEON_BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS=true for this test"
    })?;
    let (sender, messages) = unbounded_channel();
    let app = Router::new().route(
        "/logout",
        post(move |Form(params): Form<Vec<(String, String)>>| {
            let sender = sender.clone();
            async move {
                if let Some((_, token)) =
                    params.into_iter().find(|(name, _)| name == "logout_token")
                {
                    let _ = sender.send(token);
                }
                StatusCode::OK
            }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let receiver = Receiver { messages, server };
    let cfg = state
        .oidc
        .config
        .as_mut()
        .ok_or("OIDC configuration missing")?;
    let cfg = Arc::make_mut(cfg);
    cfg.logout_enabled = true;
    cfg.backchannel_logout_enabled = true;
    state.oidc.sessions = Some(OidcSessionStore::new_process_local_for_tests());
    let mut client = state.clients.try_get(f::CLIENT)?.ok_or("client missing")?;
    client.backchannel_logout_uri = Some(endpoint);
    client.backchannel_logout_session_required = true;
    state.clients.register(client);
    state.validate_subject_namespace().await?;
    Ok(receiver)
}

async fn received(receiver: &mut Receiver, state: &AppState, sid: &str) -> TestResult {
    let jwt = tokio::time::timeout(std::time::Duration::from_secs(2), receiver.messages.recv())
        .await?
        .ok_or("notification channel closed")?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.required_spec_claims.remove("exp");
    validation.validate_exp = false;
    validation.set_audience(&[f::CLIENT]);
    validation.set_issuer(&[state.issuer.as_str()]);
    let token = jsonwebtoken::decode::<Value>(
        &jwt,
        &jsonwebtoken::DecodingKey::from_rsa_pem(include_bytes!(
            "../../../../tests/fixtures/rsa2048-public.pem"
        ))?,
        &validation,
    )?;
    assert_eq!(token.claims["sid"], sid);
    assert!(
        token.claims.get("sub").is_none(),
        "session-required client uses sid"
    );
    assert!(token.claims["jti"].as_str().is_some());
    assert!(
        token.claims["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object()
    );
    assert!(token.claims.get("nonce").is_none());
    assert!(
        receiver.messages.try_recv().is_err(),
        "exactly one notification"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and explicit backchannel loopback test flag"]
async fn pg_namespace_oidc_logout_retains_session_and_sends_signed_notification_only_after_match(
) -> TestResult {
    let (mut state, browser) = f::fixture().await?;
    let mut receiver = notifications(&mut state).await?;
    let sessions = state.oidc.sessions.as_ref().ok_or("sessions missing")?;
    let sid = sessions.try_get_or_create_session(crate::oidc::OidcSessionContext {
        user_id: "namespace-user",
        auth_session_id: &browser,
    })?;
    assert!(sessions.try_add_client(&sid, f::CLIENT)?);
    let now = crate::util::now_unix_epoch_secs()?;
    let hint = state
        .oidc
        .config
        .as_ref()
        .ok_or("OIDC missing")?
        .signing_key
        .sign_rs256_jwt(
            &json!({"iss":state.issuer.as_str(),"sub":"namespace-user","aud":f::CLIENT,
            "iat":now,"exp":now+300,"sid":sid}),
        )?;
    let uri = format!(
        "/logout?{}",
        serde_urlencoded::to_string([("id_token_hint", hint.as_str())])?
    );
    let headers = f::headers(&state, &browser)?;
    for denied in unavailable_states(&state) {
        unavailable(
            web::logout_endpoint::logout(
                State(denied),
                remote(),
                OriginalUri(uri.parse()?),
                headers.clone(),
            )
            .await,
        )
        .await?;
        assert!(receiver.messages.try_recv().is_err());
        assert!(state
            .browser_auth
            .auth_sessions
            .try_get(&browser)?
            .is_some());
        assert_eq!(
            sessions.try_get_or_create_session(crate::oidc::OidcSessionContext {
                user_id: "namespace-user",
                auth_session_id: &browser
            })?,
            sid
        );
    }
    let response = web::logout_endpoint::logout(
        State(state.clone()),
        remote(),
        OriginalUri(uri.parse()?),
        headers,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(state
        .browser_auth
        .auth_sessions
        .try_get(&browser)?
        .is_none());
    assert!(sessions.try_logout_by_auth_session_id(&browser)?.is_none());
    received(&mut receiver, &state, &sid).await
}

async fn environment(state: &AppState) -> TestResult<TestEnvironment> {
    let context = crate::local_credentials::load_runtime_environment_context(
        &state.db_pool,
        state.issuer.as_str(),
    )
    .await?
    .ok_or("environment missing")?;
    Ok(TestEnvironment {
        team_id: context.team_id,
        tenant_id: context.tenant_id,
        environment_id: context.environment_id,
        issuer_host: state.runtime_authority.issuer_host().to_owned(),
        issuer_url: state.issuer.as_str().to_owned(),
    })
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and explicit backchannel loopback test flag"]
async fn pg_namespace_management_logout_dispatch_waits_for_matching_permit() -> TestResult {
    for single in [true, false] {
        let (mut state, _) = f::fixture().await?;
        let mut receiver = notifications(&mut state).await?;
        let env = environment(&state).await?;
        let (user, subject) = m::user(&state, &env).await?;
        let key = m::human_session(&state, &env).await?;
        let browser = session(&state, &subject)?;
        let sessions = state.oidc.sessions.as_ref().ok_or("sessions missing")?;
        let sid = sessions.try_get_or_create_session(crate::oidc::OidcSessionContext {
            user_id: &subject,
            auth_session_id: &browser,
        })?;
        assert!(sessions.try_add_client(&sid, f::CLIENT)?);
        let base = m::base_path(&env, user);
        let path = if single {
            format!(
                "{base}/sessions/{}/revoke",
                aegaeon_crypto::hash::sha256_hex(browser.as_bytes())
            )
        } else {
            format!("{base}/invalidateSessions")
        };
        let before = m::effects(&state, &env).await?;
        for denied in unavailable_states(&state) {
            unavailable(m::request(&denied, &key, "POST", &path).await?).await?;
            assert!(receiver.messages.try_recv().is_err());
            assert_eq!(m::effects(&state, &env).await?, before);
            assert!(state
                .browser_auth
                .auth_sessions
                .try_get(&browser)?
                .is_some());
            assert_eq!(
                sessions.try_get_or_create_session(crate::oidc::OidcSessionContext {
                    user_id: &subject,
                    auth_session_id: &browser
                })?,
                sid
            );
        }
        assert_eq!(
            m::request(&state, &key, "POST", &path).await?.status(),
            StatusCode::NO_CONTENT
        );
        assert!(state
            .browser_auth
            .auth_sessions
            .try_get(&browser)?
            .is_none());
        assert_eq!(m::effects(&state, &env).await?.0, before.0 + 1);
        received(&mut receiver, &state, &sid).await?;
    }
    Ok(())
}
