//! Exact outer selectors at real PG observation and Redis reserve/resume boundaries.
use super::*;
mod controls;

const OTHER_CLIENT: &str = "other-consent-client";

fn par_pair(state: &AppState, request_uri: &str) -> TestResult<Vec<Option<String>>> {
    let request = request_key(state, request_uri, "v2");
    let reservation = request.replace(":req:", ":reservation:");
    Ok(redis::cmd("MGET")
        .arg(request)
        .arg(reservation)
        .query(&mut connection()?)?)
}

fn selector_variants(uri: &str) -> TestResult<Vec<String>> {
    let pairs: Vec<_> = query(uri)?
        .into_iter()
        .filter(|(key, _)| key != "client_id")
        .collect();
    let base = format!("/authorize?{}", serde_urlencoded::to_string(pairs)?);
    let values = [
        format!("client_id=+{CLIENT}"),
        format!("client_id={CLIENT}+"),
        format!("client_id=%20{CLIENT}%20"),
        format!("client_id=%09{CLIENT}%0A"),
        format!("client_id={}", CLIENT.to_uppercase()),
        format!("client_id={OTHER_CLIENT}"),
        "client_id=unknown-client".into(),
        "client_id=".into(),
        format!("client_id={CLIENT}&cli%65nt_id={CLIENT}"),
    ];
    let mut variants = vec![base.clone()];
    variants.extend(values.iter().map(|value| format!("{base}&{value}")));
    Ok(variants)
}

async fn refuse_selectors(
    state: &AppState,
    browser: &mut Browser,
    uri: &str,
    request_uri: &str,
    reserved: bool,
) -> TestResult {
    let retained = par_pair(state, request_uri)?;
    assert!(retained[0].is_some());
    assert_eq!(retained[1].is_some(), reserved);
    let code_count = state.tokens.issuer.code_store.snapshot().codes.len();
    for variant in selector_variants(uri)? {
        let page = browser.request(state, &variant, None).await?;
        no_cache(&page);
        assert_eq!(page.status, StatusCode::BAD_REQUEST, "{}", page.body);
        assert!(
            page.location.is_none(),
            "untrusted selector cannot redirect"
        );
        let body: Value = serde_json::from_str(&page.body)?;
        assert!(body["error"].is_string());
        assert!(!page.body.contains(CLIENT), "do not disclose stored client");
        assert_eq!(par_pair(state, request_uri)?, retained, "{variant}");
        assert_eq!(
            state.tokens.issuer.code_store.snapshot().codes.len(),
            code_count
        );
    }
    Ok(())
}

async fn exact_grant(
    state: &AppState,
    browser: &Browser,
    page: &Page,
    mode: &str,
    expected_state: &str,
) -> TestResult {
    no_cache(page);
    let (code, actual_state) = if mode == "form_post" {
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        assert!(page.location.is_none());
        assert!(page.body.contains(&format!("action=\"{REDIRECT}\"")));
        assert!(page.body.contains("method=\"post\""));
        assert_eq!(field(&page.body, "iss")?, state.issuer.as_str());
        (field(&page.body, "code")?, field(&page.body, "state")?)
    } else {
        assert_eq!(page.status, StatusCode::FOUND, "{}", page.body);
        let url = url::Url::parse(page.location.as_deref().ok_or("redirect")?)?;
        assert_eq!(url.as_str().split('?').next(), Some(REDIRECT));
        let pairs: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("iss").map(String::as_str),
            Some(state.issuer.as_str())
        );
        (
            pairs.get("code").ok_or("code")?.clone(),
            pairs.get("state").ok_or("state")?.clone(),
        )
    };
    assert_eq!(actual_state, expected_state);
    let stored_code = state
        .tokens
        .issuer
        .code_store
        .try_get_code(&code)?
        .ok_or("stored code")?;
    assert_eq!(stored_code.client_id, CLIENT);
    assert_eq!(stored_code.redirect_uri.as_deref(), Some(REDIRECT));
    let sid = browser
        .cookies
        .get("aegaeon_auth_session")
        .ok_or("session")?;
    let token = redeem(state, sid, &json!({"code":code}).to_string()).await?;
    assert!(token["access_token"].is_string());
    Ok(())
}

async fn pushed_case(
    state: &AppState,
    sid: &str,
    signed: bool,
    mode: &str,
    resume: bool,
) -> TestResult {
    let prompt = resume.then_some("login consent");
    let uri = push(state, sid, Some(mode), prompt, signed).await?;
    let request_uri = query(&uri)?
        .into_iter()
        .find(|(k, _)| k == "request_uri")
        .ok_or("request URI")?
        .1;
    let pushed = stored(state, &request_uri)?.ok_or("pushed request")?;
    let expected_state = pushed.state.as_deref().ok_or("pushed state")?;
    assert_eq!(pushed.client_id, CLIENT);
    assert_eq!(pushed.response_mode.as_deref(), Some(mode));
    assert_eq!(pushed.request_object_claims.is_some(), signed);
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    refuse_selectors(state, &mut browser, &uri, &request_uri, false).await?;
    let mut page = browser.request(state, &uri, None).await?;
    if resume {
        let continuation = complete_login(state, &mut browser, page).await?;
        assert!(continuation.contains("aeg_par_continue="));
        refuse_selectors(state, &mut browser, &continuation, &request_uri, true).await?;
        controls::wrong_continuation(state, &mut browser, &continuation, &request_uri).await?;
        page = browser.request(state, &continuation, None).await?;
        let transaction = transaction(&page.body)?.to_string();
        page = browser
            .request(
                state,
                "/auth/consent",
                Some(vec![("transaction", &transaction), ("decision", "approve")]),
            )
            .await?;
    }
    exact_grant(state, &browser, &page, mode, expected_state).await?;
    assert_eq!(par_pair(state, &request_uri)?, vec![None, None]);
    Ok(())
}

async fn run_case(resume: bool, direct: bool, signed: bool, mode: &str) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        controls::register_other(&pool, &env).await?;
        let (mut state, sid) = fixture(&pool, &env).await?;
        user(&pool, &env).await?;
        update_test_policy(&mut state, |p| p.strict_authorize_redirect = true).await?;
        request_objects::shared_protocol_stores(&mut state)?;
        if direct {
            controls::direct_and_empty_controls(&state, &sid).await?;
        } else {
            pushed_case(&state, &sid, signed, mode, resume).await?;
        }
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

async fn run(resume: bool, direct: bool) -> TestResult {
    if direct {
        return run_case(resume, true, false, "query").await;
    }
    // Each scenario has its own environment and normal source-rate budget.
    for signed in [false, true] {
        for mode in ["query", "form_post"] {
            run_case(resume, false, signed, mode).await?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn pushed_client_identifier_refusals_preserve_fresh_requests() -> TestResult {
    run(false, false).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn pushed_client_identifier_refusals_preserve_login_consent_resume() -> TestResult {
    run(true, false).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn pushed_client_identifier_direct_and_empty_controls() -> TestResult {
    run(false, true).await
}
