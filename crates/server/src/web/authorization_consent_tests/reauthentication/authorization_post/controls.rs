use super::*;

pub(super) async fn raw(
    state: &AppState,
    sid: Option<&str>,
    uri: &str,
    body: String,
    types: &[&str],
    source: u8,
) -> TestResult<Page> {
    let mut request = Request::post(uri).header(header::ORIGIN, "https://rp.example");
    if let Some(sid) = sid {
        request = request.header(header::COOKIE, format!("aegaeon_auth_session={sid}"));
    }
    for content_type in types {
        request = request.header(header::CONTENT_TYPE, *content_type);
    }
    let app = crate::web::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, source], 12345)),
    )));
    let response = app.oneshot(request.body(Body::from(body))?).await?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    Ok(Page {
        cache_control: Some(
            response.headers()[header::CACHE_CONTROL]
                .to_str()?
                .to_owned(),
        ),
        pragma: Some(response.headers()[header::PRAGMA].to_str()?.to_owned()),
        status: response.status(),
        location: response
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().map(str::to_string))
            .transpose()?,
        body: String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await?.to_vec())?,
    })
}

pub(super) async fn admission(state: &AppState, sid: &str) -> TestResult {
    let uri = authorize_uri(state, None)?;
    let form = uri.split_once('?').ok_or("form")?.1;
    let form_type = "application/x-www-form-urlencoded";
    for (path, body, types) in [
        ("/authorize?state=query", form.to_string(), vec![form_type]),
        (
            "/authorize?client_secret=uri-secret",
            form.to_string(),
            vec![form_type],
        ),
        ("/authorize", form.to_string(), vec![]),
        ("/authorize", form.to_string(), vec!["application/json"]),
        ("/authorize", form.to_string(), vec![form_type, form_type]),
        (
            "/authorize",
            format!("{form}&client_id=other"),
            vec![form_type],
        ),
        ("/authorize", format!("{form}&state=%GG"), vec![form_type]),
        ("/authorize", format!("{form}&unknown=%FF"), vec![form_type]),
        (
            "/authorize",
            format!("{form}&{}=x", "k".repeat(65)),
            vec![form_type],
        ),
        (
            "/authorize",
            format!("{form}&unknown={}", "x".repeat(8193)),
            vec![form_type],
        ),
        (
            "/authorize",
            format!("{form}{}", "&unknown=x".repeat(65)),
            vec![form_type],
        ),
        ("/authorize", "x".repeat(16385), vec![form_type]),
        (
            "/authorize",
            format!("{form}&resource=https%3A%2F%2Fa.example&resource=https%3A%2F%2Fb.example"),
            vec![form_type],
        ),
    ] {
        let page = raw(state, Some(sid), path, body, &types, 1).await?;
        assert!(
            page.status.is_client_error(),
            "{} {:?}",
            page.body,
            page.location
        );
        assert!(!page.body.contains("uri-secret"));
    }
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    for suffix in [
        "&client_id=&unknown=a&unknown=b",
        "&response_mode=form_post",
    ] {
        let uri = authorize_uri(state, None)?;
        let page = raw(
            state,
            Some(sid),
            "/authorize",
            format!("{}{suffix}", uri.split_once('?').ok_or("form")?.1),
            &[form_type],
            1,
        )
        .await?;
        check_code(state, &browser, &page, suffix.contains("form_post")).await?;
    }
    Ok(())
}

pub(super) async fn budgets(state: &mut AppState) -> TestResult {
    Arc::make_mut(&mut state.cfg)
        .database
        .authorization_admission = crate::config::AuthorizationAdmissionLimits::new(64, 12, 3)?;
    reload_authorization_runtime(state).await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    state.device.local_login_rate_limiter = Arc::new(
        crate::device_authz::VerificationRateLimiter::try_from_shared_store_env(
            "AEGAEON_TEST_REDIS_URL",
            "authorization-post",
            &namespace,
        )?,
    );
    let mut other = state.clone();
    other.device.local_login_rate_limiter = Arc::new(
        crate::device_authz::VerificationRateLimiter::try_from_shared_store_env(
            "AEGAEON_TEST_REDIS_URL",
            "authorization-post",
            &namespace,
        )?,
    );
    for n in 0..4 {
        let uri = authorize_uri(state, None)?;
        let selected = if n % 2 == 0 { &*state } else { &other };
        let page = raw(
            selected,
            None,
            "/authorize",
            uri.split_once('?').ok_or("form")?.1.into(),
            &["application/x-www-form-urlencoded"],
            1,
        )
        .await?;
        assert_eq!(
            page.status,
            if n < 3 {
                StatusCode::FOUND
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    Arc::make_mut(&mut state.cfg)
        .database
        .authorization_admission = crate::config::AuthorizationAdmissionLimits::new(64, 5, 1)?;
    reload_authorization_runtime(state).await?;
    for source in [2, 3] {
        let uri = authorize_uri(state, None)?;
        assert_eq!(
            raw(
                state,
                None,
                "/authorize",
                uri.split_once('?').ok_or("form")?.1.into(),
                &["application/x-www-form-urlencoded"],
                source
            )
            .await?
            .status,
            StatusCode::FOUND
        );
    }
    // Terminal records remain in the window: cancellation/consumption cannot
    // refund the insertion budget. No row is deleted by this fixture.
    sqlx::query("UPDATE aegaeon.authorization_logins SET completed_at=now(), consumed_at=now(), session_snapshot='{}' WHERE environment_id=$1")
        .bind(state.environment_id).execute(&state.db_pool).await?;
    let uri = authorize_uri(state, None)?;
    assert_eq!(
        raw(
            state,
            None,
            "/authorize",
            uri.split_once('?').ok_or("form")?.1.into(),
            &["application/x-www-form-urlencoded"],
            4
        )
        .await?
        .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.authorization_logins WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_one(&state.db_pool)
    .await?;
    assert_eq!(count, 5);
    Ok(())
}
