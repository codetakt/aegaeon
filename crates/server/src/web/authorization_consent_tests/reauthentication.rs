//! Exercise the actual login form and credential POST, including wrapped requests.
use super::*;
use std::collections::BTreeMap;
mod negative;

const PASSWORD: &str = "local-reauthentication-test-password";

#[derive(Clone, Default)]
struct Browser {
    cookies: BTreeMap<String, String>,
}

struct Page {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

impl Browser {
    async fn request(
        &mut self,
        state: &AppState,
        uri: &str,
        form: Option<Vec<(&str, &str)>>,
    ) -> TestResult<Page> {
        let mut request = if form.is_some() {
            Request::post(uri)
        } else {
            Request::get(uri)
        };
        request = request.header(
            header::COOKIE,
            self.cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        );
        let body = if let Some(form) = form {
            request = request
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, state.issuer.as_str());
            serde_urlencoded::to_string(form)?
        } else {
            String::new()
        };
        let app = super::super::router::build_router(state.clone()).layer(Extension(ConnectInfo(
            SocketAddr::from(([127, 0, 0, 1], 12345)),
        )));
        let response = app.oneshot(request.body(Body::from(body))?).await?;
        for value in response.headers().get_all(header::SET_COOKIE) {
            let pair = value.to_str()?.split(';').next().ok_or("cookie missing")?;
            let (key, value) = pair.split_once('=').ok_or("cookie malformed")?;
            self.cookies.insert(key.to_string(), value.to_string());
        }
        Ok(Page {
            status: response.status(),
            location: response
                .headers()
                .get(header::LOCATION)
                .map(|v| v.to_str().map(str::to_string))
                .transpose()?,
            body: String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await?.to_vec())?,
        })
    }
}

fn field(html: &str, name: &str) -> TestResult<String> {
    let needle = format!("name=\"{name}\" value=\"");
    let value = html
        .split(&needle)
        .nth(1)
        .and_then(|v| v.split('"').next())
        .ok_or_else(|| format!("missing field {name}"))?;
    Ok(value
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&"))
}

async fn user(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES ($1,$2,'consent-user','ACTIVE')")
        .bind(id).bind(env.environment_id).execute(pool).await?;
    let hash = crate::local_credentials::hash_password(PASSWORD)?;
    sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash) VALUES ($1,$2)")
        .bind(id).bind(hash).execute(pool).await?;
    Ok(())
}

async fn request_uri(state: &AppState, sid: &str, mode: &str) -> TestResult<String> {
    if mode.starts_with("direct-expired-positive") {
        return Ok(format!(
            "{}&max_age=1",
            authorize_uri(state, Some("consent"))?
        ));
    }
    if mode.starts_with("plain-par") {
        let uri = authorize_uri(
            state,
            Some(if mode.contains("consent") {
                "login consent"
            } else {
                "login"
            }),
        )?;
        let pairs: Vec<(String, String)> =
            serde_urlencoded::from_str(uri.split_once('?').ok_or("query missing")?.1)?;
        let form = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let (status, body) = send(state, sid, "/par", Some(form), None).await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let value: Value = serde_json::from_str(&body)?;
        return Ok(format!(
            "/authorize?{}",
            serde_urlencoded::to_string([
                ("client_id", CLIENT),
                (
                    "request_uri",
                    value["request_uri"].as_str().ok_or("PAR URI missing")?
                )
            ])?
        ));
    }
    let jwt = request_objects::signed_request(state, mode)?;
    request_objects::authorization_uri(state, sid, &jwt, mode).await
}

async fn scenario(state: &AppState, sid: &str, mode: &str, existing: bool) -> TestResult {
    let uri = request_uri(state, sid, mode).await?;
    let mut browser = Browser::default();
    if existing {
        browser
            .cookies
            .insert("aegaeon_auth_session".to_string(), sid.to_string());
    }
    let page = browser.request(state, &uri, None).await?;
    assert_eq!(page.status, StatusCode::FOUND, "{}", page.body);
    let login = page.location.ok_or("login redirect missing")?;
    assert!(login.starts_with("/auth/login?"));
    let page = browser.request(state, &login, None).await?;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let mut csrf = field(&page.body, "csrf_token")?;
    let return_to = field(&page.body, "return_to")?;
    if mode.contains("empty-identifier") {
        let error = browser
            .request(
                state,
                "/auth/login",
                Some(vec![
                    ("identifier", ""),
                    ("password", PASSWORD),
                    ("csrf_token", &csrf),
                    ("return_to", &return_to),
                ]),
            )
            .await?;
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        csrf = field(&error.body, "csrf_token")?;
    }

    let page = browser
        .request(
            state,
            "/auth/login",
            Some(vec![
                ("identifier", "consent-user"),
                ("password", PASSWORD),
                ("csrf_token", &csrf),
                ("return_to", &return_to),
            ]),
        )
        .await?;
    assert_eq!(page.status, StatusCode::SEE_OTHER, "{}", page.body);
    let resume = page.location.ok_or("authorize return missing")?;
    if mode.starts_with("direct-expired-positive") {
        let req: crate::authcode::types::AuthorizationRequest =
            serde_urlencoded::from_str(resume.split_once('?').ok_or("query missing")?.1)?;
        let request_id = super::super::authorize_endpoint::stepup_request_id(&req, None, Some(1));
        let now = crate::util::now_unix_epoch_secs()?;
        let sid = browser
            .cookies
            .get("aegaeon_auth_session")
            .ok_or("session missing")?;
        // Simulate an outstanding completed challenge from an older worker.
        let _ = state
            .protocol
            .stepup_store
            .try_issue_challenge(CLIENT, sid, &request_id, now)?;
        assert!(state
            .protocol
            .stepup_store
            .try_complete_for_request(CLIENT, sid, &request_id, now)?
            .is_some());
        tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
        let page = browser.request(state, &resume, None).await?;
        assert!(
            page.status.is_client_error(),
            "a stale completed challenge must not bypass max_age: {}",
            page.body
        );
        return Ok(());
    }

    if mode.contains("zero-age") {
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    }
    let page = browser.request(state, &resume, None).await?;
    assert_eq!(
        page.status,
        StatusCode::OK,
        "must return to authorization after one login: {} {:?}",
        page.body,
        page.location
    );
    if mode.contains("consent") {
        let token = transaction(&page.body)?.to_string();
        let page = browser
            .request(
                state,
                "/auth/consent",
                Some(vec![("transaction", &token), ("decision", "approve")]),
            )
            .await?;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let sid = browser
            .cookies
            .get("aegaeon_auth_session")
            .ok_or("new session missing")?;
        let tokens = redeem(state, sid, &page.body).await?;
        assert!(tokens["refresh_token"].is_string());
    } else {
        let value: Value = serde_json::from_str(&page.body)?;
        assert!(value["code"].is_string(), "{}", page.body);
    }
    let replay = browser.request(state, &resume, None).await?;
    assert!(
        replay.status.is_client_error(),
        "a consumed login continuation must not issue twice: {}",
        replay.body
    );
    Ok(())
}

async fn run(mode: &str) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (state, sid) = fixture(&pool, &env).await?;
        user(&pool, &env).await?;
        let mut client = state.clients.try_get(CLIENT)?.ok_or("client missing")?;
        client.jwks_pem =
            Some(include_str!("../../../tests/fixtures/rsa2048-public.pem").to_string());
        assert!(state.clients.try_update(client)?);
        if mode.ends_with("negative") {
            return negative::scenario(&state, &sid, mode).await;
        }
        for existing in [false, true] {
            scenario(&state, &sid, mode, existing).await?;
        }
        Ok(())
    }
    .await;
    let cleanup = async {
        sqlx::query("DELETE FROM aegaeon.end_user_password_credentials WHERE end_user_id IN (SELECT id FROM aegaeon.end_users WHERE environment_id=$1)")
            .bind(env.environment_id).execute(&pool).await?;
        sqlx::query("DELETE FROM aegaeon.end_users WHERE environment_id=$1")
            .bind(env.environment_id).execute(&pool).await?;
        cleanup_test_environment(&pool,&env).await
    }.await;
    finish_test(result, cleanup)
}

macro_rules! login_test {
    ($name:ident,$mode:literal) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL"]
        async fn $name() -> TestResult {
            run($mode).await
        }
    };
}
login_test!(offline_consent_http_jar_login_returns, "jar-login");
login_test!(
    offline_consent_http_jar_login_consent_returns,
    "jar-login-consent"
);
login_test!(offline_consent_http_par_jar_login_returns, "par-login");
login_test!(
    offline_consent_http_par_jar_login_consent_returns,
    "par-login-consent"
);
login_test!(
    offline_consent_http_plain_par_login_returns,
    "plain-par-login"
);
login_test!(
    offline_consent_http_plain_par_login_consent_returns,
    "plain-par-login-consent"
);
login_test!(
    offline_consent_http_jar_login_zero_age_returns,
    "jar-login-consent-zero-age"
);
login_test!(
    offline_consent_http_par_jar_login_zero_age_returns,
    "par-login-consent-zero-age"
);
login_test!(
    offline_consent_http_jar_login_binding_and_replay,
    "jar-login-consent-negative"
);
login_test!(
    offline_consent_http_par_jar_login_binding_and_replay,
    "par-login-consent-negative"
);

login_test!(
    offline_consent_http_jar_login_admission_retry,
    "jar-login-consent-empty-identifier"
);

login_test!(
    offline_consent_http_old_stepup_cannot_bypass_positive_age,
    "direct-expired-positive"
);
