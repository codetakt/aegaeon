use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn device_confirmation_manual_and_complete_links_render_canonical_code_and_issue_once(
) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = canonical(&pool, &env).await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn canonical(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let state = fixture(pool, env).await?;
    let response = crate::web::router::build_router(state.clone())
        .oneshot(request(
            "/device_authorization",
            form(&[
                ("scope", "openid"),
                ("resource", "https://resource.example/one"),
            ]),
            OWNER,
            SECRET,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let device = body(response).await?;
    let code = device["device_code"].as_str().ok_or("device code")?;
    let user_code = device["user_code"].as_str().ok_or("user code")?;
    assert_eq!(user_code.len(), 9);
    assert_eq!(&user_code[4..5], "-");
    let pending = snapshot(&state, code)?;
    let (_, manual) = entry(&state, "/device").await?;
    assert!(manual.contains("name=\"user_code\" value=\"\""));
    assert_eq!(snapshot(&state, code)?, pending);
    let complete = url::Url::parse(
        device["verification_uri_complete"]
            .as_str()
            .ok_or("complete URI")?,
    )?;
    let path = format!(
        "{}?{}",
        complete.path(),
        complete.query().ok_or("complete query")?
    );
    let (_, prefilled) = entry(&state, &path).await?;
    assert!(prefilled.contains(&format!("name=\"user_code\" value=\"{user_code}\"")));
    assert_eq!(snapshot(&state, code)?, pending);
    let sid = browser_session(&state).await?;
    let normalized = user_code.replace('-', "");
    let variants = [
        normalized.to_ascii_lowercase(),
        user_code.to_string(),
        format!(
            " \t{} \n{}\u{2003}",
            &normalized[..4].to_ascii_lowercase(),
            &normalized[4..].to_ascii_lowercase()
        ),
    ];
    for entered in variants {
        let (cookie, _) = entry(&state, "/device").await?;
        let csrf = cookie.split_once('=').ok_or("CSRF value")?.1;
        let response = browser_post(
            &state,
            "/device",
            &cookie,
            Some(&sid),
            &[("csrf_token", csrf), ("user_code", &entered)],
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        no_cache(&response);
        let confirm_cookie = csrf_cookie(&response)?;
        let html = text(response).await?;
        assert!(html.contains(&format!("<strong>Code:</strong> <code>{user_code}</code>")));
        assert_eq!(
            html.matches(&format!("name=\"user_code\" value=\"{user_code}\""))
                .count(),
            2
        );
        assert!(html.contains(&format!(
            "<strong>Application:</strong> <code>{OWNER}</code>"
        )));
        assert!(html.contains("<strong>Scope:</strong> <code>openid</code>"));
        assert!(
            html.contains("<strong>Resource:</strong> <code>https://resource.example/one</code>")
        );
        let approve = html
            .split_once("action=\"/device/approve\"")
            .ok_or("approve form")?
            .1
            .split_once("</form>")
            .ok_or("approve end")?
            .0;
        assert!(approve.contains("type=\"checkbox\" id=\"confirm_device\" name=\"confirm_device\" value=\"yes\" required"));
        assert!(!approve.contains("checked"));
        assert!(
            approve.contains("I have this device and its displayed code matches the code above.")
        );
        let deny = html
            .split_once("action=\"/device/deny\"")
            .ok_or("deny form")?
            .1
            .split_once("</form>")
            .ok_or("deny end")?
            .0;
        assert!(!deny.contains("confirm_device"));
        assert!(!deny.contains("required"));
        assert!(deny.contains("name=\"csrf_token\""));
        assert_eq!(snapshot(&state, code)?, pending);
        assert!(html.contains(confirm_cookie.split_once('=').ok_or("confirmation CSRF")?.1));
    }
    let response = action(
        &state,
        "/device/approve",
        Some(&sid),
        &normalized.to_ascii_lowercase(),
        &["yes"],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_issued_once(&state, code).await?;
    assert_page_error(
        action(&state, "/device/approve", Some(&sid), user_code, &["yes"]).await?,
        StatusCode::BAD_REQUEST,
    )
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn device_confirmation_confusable_inputs_cannot_select_existing_pending_code() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = confusables(&pool, &env).await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn confusables(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let state = fixture(pool, env).await?;
    let device = create(&state).await?;
    let code = device["device_code"].as_str().ok_or("device code")?;
    let user_code = device["user_code"].as_str().ok_or("user code")?;
    let normalized = user_code.replace('-', "");
    let pending = snapshot(&state, code)?;
    let sid = browser_session(&state).await?;
    for prefix in ["O", "0", "I", "1", "Ａ", "!"] {
        let invalid = format!("{prefix}{}", &normalized[1..]);
        let (cookie, _) = entry(&state, "/device").await?;
        let csrf = cookie.split_once('=').ok_or("CSRF value")?.1;
        assert_page_error(
            browser_post(
                &state,
                "/device",
                &cookie,
                Some(&sid),
                &[("csrf_token", csrf), ("user_code", &invalid)],
            )
            .await?,
            StatusCode::BAD_REQUEST,
        )
        .await?;
        assert_eq!(snapshot(&state, code)?, pending);
    }
    let response = action(&state, "/device/approve", Some(&sid), user_code, &["yes"]).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_issued_once(&state, code).await
}
