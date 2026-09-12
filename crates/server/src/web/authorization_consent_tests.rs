//! Consent acquisition tests use real `PostgreSQL` and the public HTTP routes.
mod admission;
mod availability;
mod reauthentication;
mod repetition;
mod request_objects;
mod retention;
use super::test_support::{
    cleanup_test_environment, finish_test, sample_registered_client, setup_test_environment,
    test_app_state, test_pg_pool, TestEnvironment, TestResult,
};
use super::{AppState, AuthSessionTimes};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    Extension,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

const CLIENT: &str = "consent-client";
const SCOPE: &str = "openid profile email offline_access";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

async fn fixture(pool: &PgPool, env: &TestEnvironment) -> TestResult<(AppState, String)> {
    let mut client = sample_registered_client(CLIENT);
    client.allowed_scopes = SCOPE.split(' ').map(str::to_string).collect();
    client.allowed_grant_types.push("refresh_token".to_string());
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".to_string()],
        "consent-test-registration",
        "consent-test",
    )
    .await?;
    sqlx::query(
        "UPDATE aegaeon.oauth_profiles SET allowed_grant_types = $1 WHERE environment_id = $2",
    )
    .bind(vec!["authorization_code", "refresh_token"])
    .bind(env.environment_id)
    .execute(pool)
    .await?;
    let mut state = test_app_state(pool.clone(), env).await?;
    Arc::make_mut(&mut state.cfg)
        .security_policy
        .sender_constrained = crate::policy::SenderConstraint::None;
    Arc::make_mut(&mut state.cfg).strict_authorize_redirect = false;
    // This fixture registers a public PKCE client; RFC 9126 permits PAR
    // without client credentials when the registered method is `none`.
    Arc::make_mut(&mut state.cfg).require_client_auth_par = false;
    state
        .protocol
        .par_endpoint
        .register_client(crate::par::Client {
            client_id: CLIENT.to_string(),
            client_secret: None,
            token_endpoint_auth_method: "none".to_string(),
            redirect_uris: client.redirect_uris.clone(),
            allowed_scopes: client.allowed_scopes.clone(),
        });
    let oidc = crate::oidc::OidcConfig {
        issuer: env.issuer_url.clone(),
        id_token_ttl_secs: 300,
        discovery_enabled: true,
        userinfo_enabled: true,
        logout_enabled: false,
        backchannel_logout_enabled: false,
        logout_session_ttl_secs: 600,
        backchannel_logout_timeout_secs: 2,
        require_nonce: true,
        signing_key: crate::oidc::OidcSigningKey::from_rsa_pem(
            "consent-test".to_string(),
            include_str!("../../tests/fixtures/rsa2048-private.pk8.pem"),
        )?,
        request_object_encryption_key: None,
    };
    state.oidc.config = Some(Arc::new(oidc.clone()));
    state.keys.access_token = Arc::new(crate::kms::InMemoryPublicJwtKeyManager::new()?);
    state.tokens.issuer = Arc::new(
        crate::authcode::TokenIssuer::with_stores(
            state.keys.access_token.clone(),
            crate::authcode::AuthCodeStore::new_process_local_for_tests(),
            state.tokens.store.as_ref().clone(),
        )
        .with_issuer(env.issuer_url.clone())
        .with_jwt_access_tokens_enabled(true)
        .with_oidc(Some(oidc)),
    );
    let sid = state
        .browser_auth
        .auth_sessions
        .create(
            "consent-user",
            AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?),
            None,
            None,
            None,
        )
        .ok_or("session creation failed")?;
    Ok((state, sid))
}

async fn send(
    state: &AppState,
    sid: &str,
    uri: &str,
    form: Option<Vec<(&str, &str)>>,
    origin: Option<&str>,
) -> TestResult<(StatusCode, String)> {
    let mut request = if form.is_some() {
        Request::post(uri)
    } else {
        Request::get(uri)
    };
    request = request.header(header::COOKIE, format!("aegaeon_auth_session={sid}"));
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    let body = if let Some(form) = form {
        request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        serde_urlencoded::to_string(form)?
    } else {
        String::new()
    };
    let app = super::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let response = app.oneshot(request.body(Body::from(body))?).await?;
    let status = response.status();
    if status != StatusCode::NOT_FOUND {
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        assert_eq!(response.headers()[header::RETRY_AFTER], "60");
    }
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"text/html"))
    {
        assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert!(response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()?
            .contains("frame-ancestors 'none'"));
    }
    Ok((
        status,
        String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await?.to_vec())?,
    ))
}

fn authorize_uri(state: &AppState, prompt: Option<&str>) -> TestResult<String> {
    let nonce = Uuid::new_v4().to_string();
    let mut pairs = vec![
        ("client_id", CLIENT),
        ("response_type", "code"),
        ("scope", SCOPE),
        ("redirect_uri", "https://client.example.com/callback"),
        ("iss", state.issuer.as_str()),
        ("state", nonce.as_str()),
        ("nonce", nonce.as_str()),
        (
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ),
        ("code_challenge_method", "S256"),
    ];
    if let Some(prompt) = prompt {
        pairs.push(("prompt", prompt));
    }
    Ok(format!(
        "/authorize?{}",
        serde_urlencoded::to_string(pairs)?
    ))
}

fn transaction(html: &str) -> TestResult<&str> {
    html.split("name=\"transaction\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or("expected a consent form, not an issued code".into())
}

async fn redeem(state: &AppState, sid: &str, body: &str) -> TestResult<Value> {
    let value: Value = serde_json::from_str(body)?;
    let code = value["code"].as_str().ok_or("authorization code missing")?;
    let (status, body) = send(
        state,
        sid,
        "/token",
        Some(vec![
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT),
            ("code", code),
            ("redirect_uri", "https://client.example.com/callback"),
            ("code_verifier", VERIFIER),
        ]),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(serde_json::from_str(&body)?)
}

async fn without_prompt(state: &AppState, sid: &str) -> TestResult {
    let (status, body) = send(state, sid, &authorize_uri(state, None)?, None, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = redeem(state, sid, &body).await?;
    assert!(
        token.get("refresh_token").is_none(),
        "scope alone must not authorize offline access"
    );
    assert!(!token["scope"]
        .as_str()
        .ok_or("scope missing")?
        .split(' ')
        .any(|s| s == "offline_access"));
    Ok(())
}

async fn silent_conflict(state: &AppState, sid: &str) -> TestResult {
    let (_, body) = send(
        state,
        sid,
        &authorize_uri(state, Some("none consent"))?,
        None,
        None,
    )
    .await?;
    let value: Value = serde_json::from_str(&body)?;
    assert_eq!(value["error"], "invalid_request");
    Ok(())
}

async fn concurrent_decisions(state: &AppState, sid: &str, token: &str) -> TestResult {
    let fields = || vec![("transaction", token), ("decision", "approve")];
    let (a, b) = tokio::join!(
        send(
            state,
            sid,
            "/auth/consent",
            Some(fields()),
            Some(state.issuer.as_str())
        ),
        send(
            state,
            sid,
            "/auth/consent",
            Some(fields()),
            Some(state.issuer.as_str())
        )
    );
    let results = [a?, b?];
    assert_eq!(
        results.iter().filter(|(s, _)| *s == StatusCode::OK).count(),
        1
    );
    assert_eq!(
        results.iter().filter(|(s, _)| s.is_client_error()).count(),
        1
    );
    let winner = results
        .iter()
        .find(|(s, _)| *s == StatusCode::OK)
        .ok_or("no successful approval")?;
    assert!(redeem(state, sid, &winner.1).await?["refresh_token"].is_string());
    Ok(())
}

async fn changed_request(state: &AppState, sid: &str, token: &str) -> TestResult {
    let fields = || vec![("transaction", token), ("decision", "approve")];
    sqlx::query("UPDATE aegaeon.authorization_consents SET authorize_uri = authorize_uri || '&resource=https%3A%2F%2Fapi.example.com%2Fchanged' WHERE environment_id=$1")
        .bind(state.environment_id).execute(&state.db_pool).await?;
    let (status, _) = send(
        state,
        sid,
        "/auth/consent",
        Some(fields()),
        Some(state.issuer.as_str()),
    )
    .await?;
    assert!(status.is_client_error());
    Ok(())
}

async fn changed_policy(state: &AppState, sid: &str, token: &str) -> TestResult {
    let fields = || vec![("transaction", token), ("decision", "approve")];
    let mut client = sample_registered_client(CLIENT);
    client.allowed_scopes = vec!["openid".to_string()];
    assert!(state.clients.try_update(client)?);
    let (_, body) = send(
        state,
        sid,
        "/auth/consent",
        Some(fields()),
        Some(state.issuer.as_str()),
    )
    .await?;
    assert_eq!(
        serde_json::from_str::<Value>(&body)?["error"],
        "invalid_scope"
    );
    Ok(())
}

async fn storage_failure(state: &AppState, sid: &str, token: &str) -> TestResult {
    let fields = || vec![("transaction", token), ("decision", "approve")];
    let mut unavailable = state.clone();
    unavailable.db_pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy_with(state.db_pool.connect_options().as_ref().clone());
    unavailable.db_pool.close().await;
    // Inject failure at the consent handler: the outer runtime-authority
    // middleware has its own database check and would stop the request first.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("aegaeon_auth_session={sid}").parse()?,
    );
    headers.insert(header::ORIGIN, state.issuer.parse()?);
    let response = super::authorize_endpoint::consent_submit(
        axum::extract::State(unavailable),
        headers,
        Ok(axum::extract::Form(
            fields()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    // The healthy pool still permits the original pending transaction.
    Ok(())
}

async fn invalid_binding(state: &AppState, sid: &str, token: &str) -> TestResult {
    let fields = || vec![("transaction", token), ("decision", "approve")];
    for (cookie, origin) in [
        (sid, Some("https://attacker.invalid")),
        ("wrong-session", Some(state.issuer.as_str())),
        (sid, None),
    ] {
        let (status, body) = send(state, cookie, "/auth/consent", Some(fields()), origin).await?;
        assert!(status.is_client_error());
        let error: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(error["error"], "invalid_request");
        assert_eq!(
            error["error_description"],
            "consent request could not be validated; restart authorization"
        );
    }
    let (status, _) = send(
        state,
        sid,
        "/auth/consent",
        Some(vec![
            ("transaction", token),
            ("transaction", token),
            ("decision", "approve"),
        ]),
        Some(state.issuer.as_str()),
    )
    .await?;
    assert!(status.is_client_error());
    Ok(())
}

async fn expired_transaction(state: &AppState, sid: &str, token: &str) -> TestResult {
    let fields = || vec![("transaction", token), ("decision", "approve")];
    sqlx::query("UPDATE aegaeon.authorization_consents SET expires_at = now() - interval '1 second' WHERE environment_id = $1")
        .bind(state.environment_id).execute(&state.db_pool).await?;
    let (status, _) = send(
        state,
        sid,
        "/auth/consent",
        Some(fields()),
        Some(state.issuer.as_str()),
    )
    .await?;
    assert!(status.is_client_error());
    Ok(())
}

async fn complete_decision(state: &AppState, sid: &str, token: &str, mode: &str) -> TestResult {
    let fields = || vec![("transaction", token), ("decision", "approve")];
    let decision = if mode == "deny" { "deny" } else { "approve" };
    let (_, body) = send(
        state,
        sid,
        "/auth/consent",
        Some(vec![("transaction", token), ("decision", decision)]),
        Some(state.issuer.as_str()),
    )
    .await?;
    if mode == "deny" {
        assert_eq!(
            serde_json::from_str::<Value>(&body)?["error"],
            "access_denied"
        );
    } else {
        let response = redeem(state, sid, &body).await?;
        let refresh = response["refresh_token"]
            .as_str()
            .ok_or("approved offline grant needs refresh token")?;
        let (status, body) = send(
            state,
            sid,
            "/token",
            Some(vec![
                ("grant_type", "refresh_token"),
                ("client_id", CLIENT),
                ("refresh_token", refresh),
            ]),
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: Value = serde_json::from_str(&body)?;
        assert_eq!(value["scope"], SCOPE);
        for token in [&response, &value] {
            let jwt = token["access_token"]
                .as_str()
                .ok_or("access token missing")?;
            let claims: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).ok_or("JWT payload missing")?)?,
            )?;
            let expected = if mode == "resource" {
                "https://api.example.com/orders".to_string()
            } else {
                format!("{}/userinfo", state.issuer)
            };
            assert_eq!(claims["aud"], expected);
        }
    }
    let (status, _) = send(
        state,
        sid,
        "/auth/consent",
        Some(fields()),
        Some(state.issuer.as_str()),
    )
    .await?;
    assert!(
        status.is_client_error(),
        "decision replay must not issue a second code"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.authorization_consents WHERE environment_id = $1 AND decision = $2")
        .bind(state.environment_id).bind(decision).fetch_one(&state.db_pool).await?;
    assert_eq!(count, 1);
    Ok(())
}

async fn scenario(state: &AppState, sid: &str, mode: &str) -> TestResult {
    match mode {
        "no-prompt" => return without_prompt(state, sid).await,
        "silent-conflict" => return silent_conflict(state, sid).await,
        mode if mode.starts_with("par-") => return pushed_request(state, sid, mode).await,
        _ => {}
    }
    let mut uri = authorize_uri(state, Some("consent"))?;
    if mode == "resource" {
        uri.push_str("&resource=https%3A%2F%2Fapi.example.com%2Forders");
    }
    let (status, html) = send(state, sid, &uri, None, None).await?;
    assert_eq!(status, StatusCode::OK, "{html}");
    let token = transaction(&html)?;
    assert!(html.contains("offline_access"));
    match mode {
        "concurrent" => return concurrent_decisions(state, sid, token).await,
        "changed-request" => return changed_request(state, sid, token).await,
        "changed-policy" => return changed_policy(state, sid, token).await,
        "expired" => return expired_transaction(state, sid, token).await,
        "storage-failure" => storage_failure(state, sid, token).await?,
        "binding" => invalid_binding(state, sid, token).await?,
        _ => {}
    }
    complete_decision(state, sid, token, mode).await
}

async fn pushed_request(state: &AppState, sid: &str, mode: &str) -> TestResult {
    let prompt = match mode {
        "par-no-prompt" | "par-outer-prompt" => None,
        "par-silent-conflict" => Some("none consent"),
        _ => Some("consent"),
    };
    let uri = authorize_uri(state, prompt)?;
    let mut fields: Vec<(String, String)> =
        serde_urlencoded::from_str(uri.split_once('?').ok_or("query missing")?.1)?;
    if mode == "par-duplicate-prompt" {
        fields.push(("prompt".to_string(), "none".to_string()));
    }
    let (status, body) = send(
        state,
        sid,
        "/par",
        Some(
            fields
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
        ),
        None,
    )
    .await?;
    if matches!(mode, "par-duplicate-prompt" | "par-silent-conflict") {
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body)?["error"],
            "invalid_request"
        );
        return Ok(());
    }
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let value: Value = serde_json::from_str(&body)?;
    let request_uri = value["request_uri"].as_str().ok_or("request_uri missing")?;
    let mut fields = vec![("client_id", CLIENT), ("request_uri", request_uri)];
    if mode == "par-outer-prompt" {
        fields.push(("prompt", "consent"));
    }
    let uri = format!("/authorize?{}", serde_urlencoded::to_string(fields)?);
    let (status, body) = send(state, sid, &uri, None, None).await?;
    if mode == "par-outer-prompt" {
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body)?["error"],
            "invalid_request"
        );
    } else if mode == "par-no-prompt" {
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = redeem(state, sid, &body).await?;
        assert!(token.get("refresh_token").is_none());
        assert!(!token["scope"]
            .as_str()
            .ok_or("scope missing")?
            .split(' ')
            .any(|s| s == "offline_access"));
    } else {
        assert_eq!(status, StatusCode::OK, "{body}");
        complete_decision(state, sid, transaction(&body)?, "approve").await?;
    }
    Ok(())
}

async fn run(mode: &str) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (state, sid) = fixture(&pool, &env).await?;
        scenario(&state, &sid, mode).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_without_prompt_ignores_offline() -> TestResult {
    run("no-prompt").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_approve_then_refresh() -> TestResult {
    run("approve").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_deny_is_final() -> TestResult {
    run("deny").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_session_origin_and_csrf_binding() -> TestResult {
    run("binding").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_expired_transaction_is_rejected() -> TestResult {
    run("expired").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_silent_prompt_conflict_is_rejected() -> TestResult {
    run("silent-conflict").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_concurrent_decisions_issue_once() -> TestResult {
    run("concurrent").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_explicit_resource_survives_refresh() -> TestResult {
    run("resource").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_changed_request_is_rejected() -> TestResult {
    run("changed-request").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_current_client_scope_is_rechecked() -> TestResult {
    run("changed-policy").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_database_failure_does_not_approve() -> TestResult {
    run("storage-failure").await
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_par_approve_then_refresh() -> TestResult {
    run("par-approve").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_par_without_prompt_ignores_offline() -> TestResult {
    run("par-no-prompt").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_par_outer_prompt_is_rejected() -> TestResult {
    run("par-outer-prompt").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_par_duplicate_prompt_is_rejected() -> TestResult {
    run("par-duplicate-prompt").await
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn offline_consent_http_par_silent_prompt_conflict_is_rejected() -> TestResult {
    run("par-silent-conflict").await
}
