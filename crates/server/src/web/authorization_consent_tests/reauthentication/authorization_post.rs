//! Actual router, PostgreSQL and Redis controls for authorization form POST.
use super::*;
mod claims;
mod controls;
mod encrypted;
mod lifecycle;
mod logging;
mod snapshots;
mod stepup;

pub(super) async fn post_input(
    browser: &mut Browser,
    state: &AppState,
    uri: &str,
) -> TestResult<Page> {
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(uri.split_once('?').ok_or("query")?.1)?;
    browser
        .request(
            state,
            "/authorize",
            Some(
                pairs
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect(),
            ),
        )
        .await
}

async fn check_code(
    state: &AppState,
    browser: &Browser,
    page: &Page,
    form_post: bool,
) -> TestResult<Value> {
    let code = if form_post {
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        field(&page.body, "code")?
    } else {
        assert_eq!(page.status, StatusCode::FOUND, "{}", page.body);
        let url = url::Url::parse(page.location.as_deref().ok_or("redirect")?)?;
        assert_eq!(
            url.origin().ascii_serialization(),
            "https://client.example.com"
        );
        url.query_pairs()
            .find(|(k, _)| k == "code")
            .ok_or("code")?
            .1
            .into_owned()
    };
    let sid = browser
        .cookies
        .get("aegaeon_auth_session")
        .ok_or("session")?;
    let tokens = redeem(state, sid, &serde_json::json!({"code":code}).to_string()).await?;
    assert!(tokens["access_token"].is_string());
    assert!(tokens["id_token"].is_string());
    Ok(tokens)
}

async fn direct(state: &AppState, sid: &str) -> TestResult {
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    for form_post in [false, true] {
        let uri = format!(
            "{}&response_mode={}",
            authorize_uri(state, None)?,
            if form_post { "form_post" } else { "query" }
        );
        let page = post_input(&mut browser, state, &uri).await?;
        check_code(state, &browser, &page, form_post).await?;
    }
    let page = browser
        .request(state, &authorize_uri(state, None)?, None)
        .await?;
    check_code(state, &browser, &page, false).await?;
    let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let response = app
        .oneshot(
            Request::head(authorize_uri(state, None)?)
                .header(header::COOKIE, format!("aegaeon_auth_session={sid}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(to_bytes(response.into_body(), 1024).await?.is_empty());
    Ok(())
}

async fn login_consent(state: &AppState, sid: &str, encrypted: bool) -> TestResult {
    let modes = if encrypted {
        vec!["jwe-login-consent", "par-jwe-login-consent"]
    } else {
        vec![
            "plain",
            "plain-par-login-consent",
            "jar-login-consent",
            "par-login-consent",
        ]
    };
    for mode in modes {
        let uri = if mode == "plain" {
            format!(
                "{}&max_age=0&response_mode=form_post&resource=https%3A%2F%2Fapi.example.com%2Forders",
                authorize_uri(state, Some("login consent"))?
            )
        } else if mode.contains("jwe") {
            encrypted::request_uri(state, sid, mode).await?
        } else {
            request_uri(state, sid, mode).await?
        };
        let mut browser = Browser::default();
        browser
            .cookies
            .insert("aegaeon_auth_session".into(), sid.into());
        let page = post_input(&mut browser, state, &uri).await?;
        assert_eq!(page.status, StatusCode::FOUND, "{}", page.body);
        let login = page.location.ok_or("login redirect")?;
        let return_to =
            url::form_urlencoded::parse(login.split_once('?').ok_or("query")?.1.as_bytes())
                .find(|(k, _)| k == "return_to")
                .ok_or("return")?
                .1
                .into_owned();
        assert!(return_to.starts_with("/authorize?aeg_login_continue="));
        assert_eq!(return_to.len(), "/authorize?aeg_login_continue=".len() + 43);
        assert!(
            !login.contains("client_id")
                && !login.contains("request_uri")
                && !login.contains("nonce")
        );
        let page = browser.request(state, &login, None).await?;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let saved = claims::snapshot(state, &return_to).await?;
        let csrf = field(&page.body, "csrf_token")?;
        assert_eq!(field(&page.body, "return_to")?, return_to);
        let count_before: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.authorization_logins WHERE environment_id=$1",
        )
        .bind(state.environment_id)
        .fetch_one(&state.db_pool)
        .await?;
        let failed =
            negative::login(&mut browser, state, &return_to, &csrf, "wrong-password").await?;
        assert_eq!(failed.status, StatusCode::UNAUTHORIZED, "{}", failed.body);
        assert_eq!(field(&failed.body, "return_to")?, return_to);
        let count_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.authorization_logins WHERE environment_id=$1",
        )
        .bind(state.environment_id)
        .fetch_one(&state.db_pool)
        .await?;
        assert_eq!(count_before, count_after);
        let csrf = field(&failed.body, "csrf_token")?;
        let logged = negative::login(&mut browser, state, &return_to, &csrf, PASSWORD).await?;
        assert_eq!(logged.status, StatusCode::SEE_OTHER, "{}", logged.body);
        assert_eq!(logged.location.as_deref(), Some(return_to.as_str()));
        let consent = browser.request(state, &return_to, None).await?;
        assert_eq!(consent.status, StatusCode::OK, "{}", consent.body);
        let transaction = transaction(&consent.body)?.to_string();
        claims::consent_snapshot(state, &transaction, &saved).await?;
        let page = browser
            .request(
                state,
                "/auth/consent",
                Some(vec![("transaction", &transaction), ("decision", "approve")]),
            )
            .await?;
        let tokens = check_code(
            state,
            &browser,
            &page,
            mode == "plain" || mode.contains("jwe"),
        )
        .await?;
        claims::output(
            state,
            &page,
            &tokens,
            &saved,
            mode == "plain" || mode.contains("jwe"),
        )?;
        assert_eq!(
            browser.request(state, &return_to, None).await?.status,
            StatusCode::BAD_REQUEST
        );
    }
    Ok(())
}

async fn run(case: &str) -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, _) = fixture(&pool, &env).await?;
        user(&pool, &env).await?;
        update_test_policy(&mut state, |policy| policy.strict_authorize_redirect = true).await?;
        request_objects::shared_protocol_stores(&mut state)?;
        let namespace =
            crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
        state.browser_auth.auth_sessions =
            Arc::new(crate::web::AuthSessionStore::try_from_management_policy(
                &crate::management::types::PolicyDocument::default(),
                &namespace,
            )?);
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
            .ok_or("session")?;
        match case {
            "direct" => direct(&state, &sid).await,
            "login" => login_consent(&state, &sid, false).await,
            "encrypted" => {
                encrypted::install(&mut state).await?;
                login_consent(&state, &sid, true).await
            }
            "admission" => controls::admission(&state, &sid).await,
            "budgets" => controls::budgets(&mut state).await,
            "snapshots" => snapshots::run(&state, &sid).await,
            "logging" => logging::run(&state, &sid).await,
            "stepup" => stepup::run(&mut state, &sid).await,
            "policy" => snapshots::policy(&mut state, &sid).await,
            "lifecycle" => lifecycle::run(&state, &sid).await,
            "concurrency" => {
                update_test_policy(&mut state, |policy| {
                    policy.strict_authorize_redirect = false
                })
                .await?;
                super::negative::scenario(&state, &sid, "par-login-consent-negative-post").await
            }
            _ => Err("unknown fixture case".into()),
        }
    }
    .await;
    let cleanup=async {
        sqlx::query("DELETE FROM aegaeon.end_user_password_credentials WHERE end_user_id IN (SELECT id FROM aegaeon.end_users WHERE environment_id=$1)").bind(env.environment_id).execute(&pool).await?;
        sqlx::query("DELETE FROM aegaeon.end_users WHERE environment_id=$1").bind(env.environment_id).execute(&pool).await?;
        cleanup_test_environment(&pool,&env).await
    }.await;
    finish_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn authorization_post_pg_direct_modes_get_and_head() -> TestResult {
    run("direct").await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn authorization_post_pg_login_failure_consent_and_wrapped_requests() -> TestResult {
    run("login").await
}

macro_rules! post_test {
    ($name:ident, $case:literal) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL and Redis"]
        async fn $name() -> TestResult {
            run($case).await
        }
    };
}
post_test!(
    authorization_post_pg_encrypted_jar_and_par_continuations,
    "encrypted"
);
post_test!(
    authorization_post_pg_router_admission_and_cross_origin,
    "admission"
);
post_test!(
    authorization_post_pg_source_and_insertion_budgets,
    "budgets"
);
post_test!(
    authorization_post_pg_snapshot_binding_and_upgrade,
    "snapshots"
);
post_test!(
    authorization_post_pg_concurrent_receipts_and_consent_denial,
    "concurrency"
);

post_test!(
    authorization_post_pg_sensitive_payload_diagnostics,
    "logging"
);

post_test!(
    authorization_post_pg_stepup_transfer_uses_bound_request,
    "stepup"
);
post_test!(
    authorization_post_pg_changed_client_policy_rejects_resume,
    "policy"
);

post_test!(
    authorization_post_pg_login_lifecycle_and_redemption_bindings,
    "lifecycle"
);
