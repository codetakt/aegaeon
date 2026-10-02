use super::*;

async fn login(state: &AppState, browser: &mut Browser, uri: &str) -> TestResult<(String, Value)> {
    let page = post_input(browser, state, uri).await?;
    assert_eq!(page.status, StatusCode::FOUND, "{}", page.body);
    let page = browser
        .request(state, page.location.as_deref().ok_or("login")?, None)
        .await?;
    let return_to = field(&page.body, "return_to")?;
    let saved = claims::snapshot(state, &return_to).await?;
    let csrf = field(&page.body, "csrf_token")?;
    let page = super::super::negative::login(browser, state, &return_to, &csrf, PASSWORD).await?;
    assert_eq!(page.status, StatusCode::SEE_OTHER, "{}", page.body);
    Ok((return_to, saved))
}

async fn no_session(state: &AppState) -> TestResult {
    let mut browser = Browser::default();
    let uri = format!(
        "{}&resource=https%3A%2F%2Fapi.example.com%2Forders",
        authorize_uri(state, Some("consent"))?
    );
    let (return_to, saved) = login(state, &mut browser, &uri).await?;
    let page = browser.request(state, &return_to, None).await?;
    let transaction = transaction(&page.body)?.to_string();
    claims::consent_snapshot(state, &transaction, &saved).await?;
    let page = browser
        .request(
            state,
            "/auth/consent",
            Some(vec![("transaction", &transaction), ("decision", "approve")]),
        )
        .await?;
    let tokens = check_code(state, &browser, &page, false).await?;
    claims::output(state, &page, &tokens, &saved, false)?;
    Ok(())
}

async fn ordinary_login(state: &AppState) -> TestResult {
    let mut browser = Browser::default();
    let before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.authorization_logins WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_one(&state.db_pool)
    .await?;
    let page = browser.request(state, "/auth/login", None).await?;
    let csrf = field(&page.body, "csrf_token")?;
    let page = browser
        .request(
            state,
            "/auth/login",
            Some(vec![
                ("identifier", "consent-user"),
                ("password", PASSWORD),
                ("csrf_token", &csrf),
            ]),
        )
        .await?;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("Signed in"));
    assert!(browser.cookies.contains_key("aegaeon_auth_session"));
    let after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.authorization_logins WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_one(&state.db_pool)
    .await?;
    assert_eq!(before, after);
    Ok(())
}

async fn invalid_returns(state: &AppState, browser: &mut Browser, return_to: &str) -> TestResult {
    let token = return_to
        .strip_prefix("/authorize?aeg_login_continue=")
        .ok_or("opaque")?;
    for value in [
        "/authorize?aeg_login_continue=".to_string(),
        "/authorize?aeg_login_continue=bad".to_string(),
        format!("/authorize?aeg_login_continue={}", "!".repeat(43)),
        format!("/foreign?aeg_login_continue={token}"),
        format!("https://foreign.example/authorize?aeg_login_continue={token}"),
        format!("/authorize?%61eg_login_continue={token}"),
    ] {
        let uri = format!(
            "/auth/login?{}",
            serde_urlencoded::to_string([("return_to", &value)])?
        );
        let page = browser.request(state, &uri, None).await?;
        assert_eq!(page.status, StatusCode::BAD_REQUEST, "{}", page.body);
        assert!(page.location.is_none());
    }
    Ok(())
}

async fn unavailable(state: &AppState, browser: &Browser, return_to: &str) -> TestResult {
    let mut unavailable = state.clone();
    unavailable.db_pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy_with(state.db_pool.connect_options().as_ref().clone());
    unavailable.db_pool.close().await;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::COOKIE,
        browser
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
            .parse()?,
    );
    // Inject at the bound loader, beyond the router's independent DB admission.
    let response = crate::web::authorize_reauthentication::resume_context(
        &unavailable,
        &headers,
        &return_to.parse()?,
        "storage-control".into(),
    )
    .await
    .err()
    .ok_or("expected failure")?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    Ok(())
}

async fn consumed_par(state: &AppState, sid: &str) -> TestResult {
    for phase in ["login", "consent", "expired-login"] {
        if phase == "expired-login" {
            state.protocol.par_store.set_expires_in(5);
        }
        let uri = request_uri(state, sid, "plain-par-login-consent").await?;
        state.protocol.par_store.set_expires_in(90);
        let pushed = url::form_urlencoded::parse(uri.split_once('?').ok_or("query")?.1.as_bytes())
            .find(|(k, _)| k == "request_uri")
            .ok_or("PAR")?
            .1
            .into_owned();
        let mut browser = Browser::default();
        let (return_to, _) = login(state, &mut browser, &uri).await?;
        invalid_returns(state, &mut browser, &return_to).await?;
        unavailable(state, &browser, &return_to).await?;
        let transaction = if phase == "consent" {
            let page = browser.request(state, &return_to, None).await?;
            Some(transaction(&page.body)?.to_string())
        } else {
            None
        };
        if phase == "expired-login" {
            tokio::time::sleep(std::time::Duration::from_millis(5100)).await;
        } else {
            assert!(state
                .protocol
                .par_store
                .try_consume_request(&pushed)
                .map_err(|error| error.error.to_string())?
                .is_some());
        }
        let page = if let Some(token) = transaction {
            browser
                .request(
                    state,
                    "/auth/consent",
                    Some(vec![("transaction", &token), ("decision", "approve")]),
                )
                .await?
        } else {
            browser.request(state, &return_to, None).await?
        };
        assert!(
            page.status.is_client_error(),
            "{} {}",
            page.status,
            page.body
        );
        assert!(!page.body.contains("access_token"));
        assert!(page.location.is_none());
    }
    Ok(())
}

async fn rejected_redemption(state: &AppState, sid: &str) -> TestResult {
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    for changed in ["client_id", "redirect_uri", "code_verifier"] {
        // Each failure receives its own fresh code; no reusability assumption.
        let page = post_input(&mut browser, state, &authorize_uri(state, None)?).await?;
        let url = url::Url::parse(page.location.as_deref().ok_or("code response")?)?;
        let code = url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .ok_or("code")?
            .1
            .into_owned();
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT),
            ("code", &code),
            ("redirect_uri", "https://client.example.com/callback"),
            ("code_verifier", VERIFIER),
        ];
        for (key, value) in &mut form {
            if *key == changed {
                *value = if changed == "redirect_uri" {
                    "https://client.example.com/wrong"
                } else if changed == "code_verifier" {
                    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                } else {
                    "other-client"
                };
            }
        }
        let page = browser.request(state, "/token", Some(form)).await?;
        assert!(page.status.is_client_error(), "{}", page.body);
        let value: Value = serde_json::from_str(&page.body)?;
        assert!(value["error"].is_string());
        assert!(value.get("access_token").is_none() && value.get("id_token").is_none());
    }
    Ok(())
}

pub(super) async fn run(state: &AppState, sid: &str) -> TestResult {
    no_session(state).await?;
    ordinary_login(state).await?;
    consumed_par(state, sid).await?;
    rejected_redemption(state, sid).await
}
