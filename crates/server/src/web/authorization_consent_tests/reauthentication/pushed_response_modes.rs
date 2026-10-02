use super::*;
use serde_json::json;
mod failures;

const REDIRECT: &str = "https://client.example.com/callback";
fn no_cache(page: &Page) {
    assert_eq!(page.cache_control.as_deref(), Some("no-store"));
    assert_eq!(page.pragma.as_deref(), Some("no-cache"));
}
fn connection() -> TestResult<redis::Connection> {
    Ok(redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?.get_connection()?)
}
fn keys(state: &AppState, version: &str) -> TestResult<Vec<String>> {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let prefix = namespace.redis_atomic_group_prefix(
        crate::config::RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
        "par",
        version,
    );
    Ok(redis::cmd("KEYS")
        .arg(format!("{prefix}:*"))
        .query(&mut connection()?)?)
}
fn request_key(state: &AppState, request_uri: &str, version: &str) -> String {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let prefix = namespace.redis_atomic_group_prefix(
        crate::config::RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
        "par",
        version,
    );
    let mut digest = aegaeon_crypto::hash::Sha256Hasher::new();
    digest.update(format!("aegaeon:par:{version}").as_bytes());
    digest.update(&(request_uri.len() as u64).to_be_bytes());
    digest.update(request_uri.as_bytes());
    format!("{prefix}:req:{}", URL_SAFE_NO_PAD.encode(digest.finalize()))
}
fn stored(state: &AppState, request_uri: &str) -> TestResult<Option<crate::par::ParRequest>> {
    let raw: Option<String> = redis::cmd("GET")
        .arg(request_key(state, request_uri, "v3"))
        .query(&mut connection()?)?;
    raw.map(|raw| {
        let value: Value = serde_json::from_str(&raw)?;
        Ok(serde_json::from_value(value["request"].clone())?)
    })
    .transpose()
}
fn query(uri: &str) -> TestResult<Vec<(String, String)>> {
    Ok(serde_urlencoded::from_str(
        uri.split_once('?').ok_or("query")?.1,
    )?)
}
async fn push(
    state: &AppState,
    sid: &str,
    mode: Option<&str>,
    prompt: Option<&str>,
    signed: bool,
) -> TestResult<String> {
    let pairs;
    let jwt;
    let form = if signed {
        let mode = if mode == Some("form_post") {
            "form-post"
        } else {
            "query-mode"
        };
        let suffix = match prompt {
            Some("login consent") => "login-consent",
            Some("login") => "login",
            Some("consent") => "consent",
            _ => "no-prompt",
        };
        jwt = request_objects::signed_request(state, &format!("par-{mode}-{suffix}"))?;
        vec![("client_id", CLIENT), ("request", jwt.as_str())]
    } else {
        let mut fields = query(&authorize_uri(state, prompt)?)?;
        if let Some(mode) = mode {
            fields.push(("response_mode".into(), mode.into()));
        }
        pairs = fields;
        pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    };
    let (status, body) = send(state, sid, "/par", Some(form), None).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let value: Value = serde_json::from_str(&body)?;
    Ok(format!(
        "/authorize?{}",
        serde_urlencoded::to_string([
            ("client_id", CLIENT),
            (
                "request_uri",
                value["request_uri"].as_str().ok_or("request_uri")?
            )
        ])?
    ))
}
async fn complete_login(state: &AppState, browser: &mut Browser, page: Page) -> TestResult<String> {
    assert_eq!(page.status, StatusCode::FOUND, "{}", page.body);
    let login = page.location.ok_or("login redirect")?;
    assert!(login.starts_with("/auth/login?"));
    let page = browser.request(state, &login, None).await?;
    let csrf = field(&page.body, "csrf_token")?;
    let return_to = field(&page.body, "return_to")?;
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
    page.location.ok_or("resume location".into())
}
async fn redeem_response(
    state: &AppState,
    browser: &Browser,
    page: &Page,
    mode: &str,
    request_uri: &str,
) -> TestResult {
    no_cache(page);
    let code = if mode == "form_post" {
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        assert!(page.location.is_none());
        assert!(page.body.contains(&format!("action=\"{REDIRECT}\"")));
        assert!(page.body.contains("method=\"post\""));
        assert_eq!(field(&page.body, "iss")?, state.issuer.as_str());
        assert!(!field(&page.body, "state")?.is_empty());
        field(&page.body, "code")?
    } else {
        assert!(page.status.is_redirection(), "{}", page.body);
        let url = url::Url::parse(page.location.as_deref().ok_or("query redirect")?)?;
        assert_eq!(url.as_str().split('?').next(), Some(REDIRECT));
        let pairs: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("iss").map(String::as_str),
            Some(state.issuer.as_str())
        );
        assert!(!pairs.get("state").ok_or("state")?.is_empty());
        pairs.get("code").ok_or("code")?.to_string()
    };
    let sid = browser
        .cookies
        .get("aegaeon_auth_session")
        .ok_or("session")?;
    let token = redeem(state, sid, &json!({"code":code}).to_string()).await?;
    assert!(token["access_token"].is_string());
    assert!(stored(state, request_uri)?.is_none());
    Ok(())
}
async fn success(
    state: &AppState,
    sid: &str,
    mode: Option<&str>,
    prompt: Option<&str>,
    signed: bool,
    existing: bool,
) -> TestResult {
    let uri = push(state, sid, mode, prompt, signed).await?;
    let pairs = query(&uri)?;
    let request_uri = &pairs
        .iter()
        .find(|(k, _)| k == "request_uri")
        .ok_or("request URI")?
        .1;
    let stored = stored(state, request_uri)?.ok_or("stored")?;
    assert_eq!(stored.response_mode.as_deref(), mode);
    assert_eq!(stored.request_object_claims.is_some(), signed);
    let mut browser = Browser::default();
    if existing {
        browser
            .cookies
            .insert("aegaeon_auth_session".into(), sid.into());
    }
    let mut resume = uri.clone();
    let mut page = browser.request(state, &uri, None).await?;
    if !existing || prompt.is_some_and(|p| p.contains("login")) {
        resume = complete_login(state, &mut browser, page).await?;
        assert!(resume.starts_with("/authorize?aeg_login_continue="));
        assert_eq!(resume.len(), "/authorize?aeg_login_continue=".len() + 43);
        let before = state.tokens.issuer.code_store.snapshot().codes.len();
        for extra in ["&response_mode=query", "&prompt=none"] {
            let refused = browser
                .request(state, &format!("{resume}{extra}"), None)
                .await?;
            no_cache(&refused);
            assert!(refused.status.is_client_error());
            assert_eq!(
                state.tokens.issuer.code_store.snapshot().codes.len(),
                before
            );
        }
        let mut wrong = query(&resume)?;
        for (k, v) in &mut wrong {
            if k == "aeg_login_continue" {
                *v = "wrong".into();
            }
        }
        let refused = browser
            .request(
                state,
                &format!("/authorize?{}", serde_urlencoded::to_string(wrong)?),
                None,
            )
            .await?;
        assert!(refused.status.is_client_error());
        page = browser.request(state, &resume, None).await?;
    }
    if prompt.is_some_and(|p| p.contains("consent")) {
        let transaction = transaction(&page.body)?.to_string();
        let retained = keys(state, "v3")?;
        assert!(retained.iter().any(|key| key.contains(":reservation:")));
        page = browser
            .request(
                state,
                "/auth/consent",
                Some(vec![("transaction", &transaction), ("decision", "approve")]),
            )
            .await?;
    }
    redeem_response(state, &browser, &page, mode.unwrap_or("query"), request_uri).await?;
    let before = state.tokens.issuer.code_store.snapshot().codes.len();
    let repeated = browser.request(state, &resume, None).await?;
    no_cache(&repeated);
    assert!(repeated.status.is_client_error());
    assert_eq!(
        state.tokens.issuer.code_store.snapshot().codes.len(),
        before
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn pushed_response_modes_survive_real_shared_grant_login_and_consent() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, sid) = fixture(&pool, &env).await?;
        user(&pool, &env).await?;
        update_test_policy(&mut state, |p| p.strict_authorize_redirect = true).await?;
        request_objects::shared_protocol_stores(&mut state)?;
        for mode in [None, Some("query"), Some("form_post")] {
            success(&state, &sid, mode, None, false, true).await?;
        }
        for signed in [false, true] {
            for (prompt, existing) in [
                (None, false),
                (Some("login"), true),
                (Some("consent"), true),
                (Some("login consent"), true),
            ] {
                success(&state, &sid, Some("form_post"), prompt, signed, existing).await?;
            }
        }
        success(&state, &sid, Some("query"), None, true, true).await?;
        assert!(
            keys(&state, "v3")?.is_empty(),
            "grant commits consume both keys"
        );
        Ok(())
    }
    .await;
    let cleanup = if result.is_ok() {
        async {
            sqlx::query("DELETE FROM aegaeon.end_user_password_credentials WHERE end_user_id IN (SELECT id FROM aegaeon.end_users WHERE environment_id=$1)").bind(env.environment_id).execute(&pool).await?;
            cleanup_test_environment(&pool, &env).await
        }.await
    } else {
        Ok(())
    };
    finish_test(result, cleanup)
}
