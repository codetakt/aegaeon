use super::fixture::*;
use crate::web::{
    test_support::{update_test_policy, TestResult},
    AUTH_SESSION_COOKIE_NAME,
};
use axum::http::{header, Method, StatusCode};

pub(super) async fn bindings(f: &Fixture) -> TestResult {
    let a = f.session("user", None).await?;
    let b = f.session("user", None).await?;
    let tx = f.start(Method::GET, &[], None).await?;
    for cookie in [None, Some("__Host-aegaeon-logout-invalid=copy")] {
        assert_eq!(
            send(&f.state, Method::GET, &tx.location, cookie, None, "")
                .await?
                .status,
            StatusCode::BAD_REQUEST
        );
    }
    let request = axum::http::Request::get(&tx.location)
        .header(header::COOKIE, &tx.cookie)
        .header(header::COOKIE, &tx.cookie)
        .body(axum::body::Body::empty())?;
    assert_eq!(
        send_request(&f.state, request).await?.status,
        StatusCode::BAD_REQUEST
    );
    let other = f.start(Method::GET, &[], None).await?;
    assert_eq!(
        send(
            &f.state,
            Method::GET,
            &tx.location,
            Some(&other.cookie),
            None,
            ""
        )
        .await?
        .status,
        StatusCode::BAD_REQUEST
    );
    let duplicated = format!("{}; {}", tx.cookie, tx.cookie);
    assert_eq!(
        send(
            &f.state,
            Method::GET,
            &tx.location,
            Some(&duplicated),
            None,
            ""
        )
        .await?
        .status,
        StatusCode::BAD_REQUEST
    );
    let duplicate_session = format!(
        "{}; {AUTH_SESSION_COOKIE_NAME}={}; {AUTH_SESSION_COOKIE_NAME}={}",
        tx.cookie, a.id, b.id
    );
    assert_eq!(
        send(
            &f.state,
            Method::GET,
            &tx.location,
            Some(&duplicate_session),
            None,
            ""
        )
        .await?
        .status,
        StatusCode::BAD_REQUEST
    );
    let head = send(
        &f.state,
        Method::HEAD,
        &tx.location,
        Some(&tx.cookies(Some(&a.id))),
        None,
        "",
    )
    .await?;
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.body.is_empty());
    // A decision without a presentation cannot win.
    assert_eq!(
        tx.choose(&f.state, Some(&a.id), "confirm").await?.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(tx.show(&f.state, Some(&a.id)).await?.status, StatusCode::OK);
    assert_eq!(
        tx.show(&f.state, Some(&b.id)).await?.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        tx.choose(&f.state, Some(&b.id), "confirm").await?.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        tx.choose(&f.state, None, "confirm").await?.status,
        StatusCode::BAD_REQUEST
    );
    let body = format!("transaction={}&decision=confirm", tx.token);
    for origin in [None, Some("https://foreign.example"), Some("null")] {
        assert_eq!(
            send(
                &f.state,
                Method::POST,
                "/logout/confirm",
                Some(&tx.cookies(Some(&a.id))),
                origin,
                &body
            )
            .await?
            .status,
            StatusCode::BAD_REQUEST
        );
    }
    f.intact(&a).await?;
    f.intact(&b).await?;
    let (first, second) = tokio::join!(
        tx.choose(&f.state, Some(&a.id), "confirm"),
        tx.choose(&f.state, Some(&a.id), "confirm")
    );
    let statuses = [first?.status, second?.status];
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
    f.ended(&a).await?;
    f.intact(&b).await?;
    let expired = f.start(Method::GET, &[], None).await?;
    expired.show(&f.state, Some(&b.id)).await?;
    sqlx::query("UPDATE aegaeon.logout_confirmations SET expires_at=now()-interval '1 second' WHERE token_sha256=$1")
        .bind(crate::web::logout_confirmation::storage::digest(&expired.token)).execute(&f.state.db_pool).await?;
    assert_eq!(
        expired
            .choose(&f.state, Some(&b.id), "confirm")
            .await?
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        expired.show(&f.state, Some(&b.id)).await?.status,
        StatusCode::BAD_REQUEST
    );
    f.intact(&b).await
}

pub(super) async fn admission(f: &Fixture) -> TestResult {
    let session = f.session("user", None).await?;
    let hint = f.hint("user", Some(&session.oidc))?;
    let cookie = format!("{AUTH_SESSION_COOKIE_NAME}={}", session.id);
    for fields in [
        vec![("client_id", "unknown")],
        vec![("post_logout_redirect_uri", REDIRECT)],
        vec![
            ("client_id", CLIENT),
            ("post_logout_redirect_uri", "https://evil.example"),
        ],
        vec![
            ("client_id", "other-client"),
            ("id_token_hint", hint.as_str()),
        ],
        vec![("id_token_hint", "invalid")],
    ] {
        let encoded = serde_urlencoded::to_string(&fields)?;
        for method in [Method::GET, Method::POST] {
            let (uri, body) = if method == Method::POST {
                ("/logout".into(), encoded.clone())
            } else {
                (format!("/logout?{encoded}"), String::new())
            };
            assert_eq!(
                send(&f.state, method, &uri, Some(&cookie), None, &body)
                    .await?
                    .status,
                StatusCode::BAD_REQUEST
            );
        }
    }
    for (uri, body) in [
        ("/logout?client_id=other-client", "client_id=logout-client"),
        ("/logout", "client_id=a&client_id=b"),
        ("/logout", "state=%GG"),
        ("/logout?client_secret=private", ""),
        ("/logout", "state=%FF"),
    ] {
        assert_eq!(
            send(&f.state, Method::POST, uri, Some(&cookie), None, body)
                .await?
                .status,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        send(
            &f.state,
            Method::POST,
            "/logout",
            Some(&cookie),
            None,
            &"x".repeat(40_000)
        )
        .await?
        .status,
        StatusCode::BAD_REQUEST
    );
    let wrong_type = axum::http::Request::post("/logout")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from("{}"))?;
    assert_eq!(
        send_request(&f.state, wrong_type).await?.status,
        StatusCode::BAD_REQUEST
    );
    let head = send(&f.state, Method::HEAD, "/logout", Some(&cookie), None, "").await?;
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.body.is_empty());
    assert!(!head.headers.contains_key(header::SET_COOKIE));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.logout_confirmations WHERE environment_id=$1",
    )
    .bind(f.state.environment_id)
    .fetch_one(&f.state.db_pool)
    .await?;
    assert_eq!(count, 0);
    f.intact(&session).await?;
    let tx = f.start(Method::GET, &[], None).await?;
    tx.show(&f.state, Some(&session.id)).await?;
    for body in [
        format!("transaction={}&decision=confirm&decision=cancel", tx.token),
        format!("transaction={}&decision=confirm&unknown=1", tx.token),
        format!("transaction=&transaction={}&decision=confirm", tx.token),
        format!("transaction={}&decision=other", tx.token),
    ] {
        assert_eq!(
            send(
                &f.state,
                Method::POST,
                "/logout/confirm",
                Some(&tx.cookies(Some(&session.id))),
                Some(&f.state.issuer),
                &body
            )
            .await?
            .status,
            StatusCode::BAD_REQUEST
        );
    }
    f.intact(&session).await
}

pub(super) async fn failures(f: &Fixture) -> TestResult {
    let session = f.session("user", None).await?;
    let tx = f
        .start(
            Method::GET,
            &[
                ("client_id", CLIENT),
                ("post_logout_redirect_uri", REDIRECT),
            ],
            None,
        )
        .await?;
    tx.show(&f.state, Some(&session.id)).await?;
    let mut unavailable = f.state.clone();
    unavailable.runtime_restart = crate::runtime_restart::RuntimeRestartState::new();
    unavailable.readiness = crate::web::ReadinessState::new();
    unavailable.db_pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(50))
        .connect_lazy("postgres://claude@127.0.0.1:1/unavailable")?;
    assert_eq!(
        tx.choose(&unavailable, Some(&session.id), "confirm")
            .await?
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    f.intact(&session).await?;
    // A failure after one-use approval cannot claim success or broaden logout.
    let failed = f.start(Method::GET, &[], None).await?;
    failed.show(&f.state, Some(&session.id)).await?;
    let mut broken = f.state.clone();
    broken.oidc.sessions = Some(crate::oidc::OidcSessionStore::new_redis_for_test(
        "redis://127.0.0.1:1/",
        "logout-unavailable",
        600,
    )?);
    let response = failed.choose(&broken, Some(&session.id), "confirm").await?;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers.contains_key(header::LOCATION));
    assert_eq!(
        failed
            .choose(&f.state, Some(&session.id), "confirm")
            .await?
            .status,
        StatusCode::BAD_REQUEST
    );
    f.intact(&session).await?;
    let mut changed = f.state.clone();
    changed.runtime_restart = crate::runtime_restart::RuntimeRestartState::new();
    changed.readiness = crate::web::ReadinessState::new();
    update_test_policy(&mut changed, |p| p.oidc_enable_logout = false).await?;
    assert_eq!(
        tx.choose(&changed, Some(&session.id), "confirm")
            .await?
            .status,
        StatusCode::NOT_FOUND
    );
    f.intact(&session).await?;
    changed.readiness = crate::web::ReadinessState::new();
    update_test_policy(&mut changed, |p| p.oidc_enable_logout = true).await?;
    // Revoking the registered target between display and submission rejects
    // before consuming or ending either store's session.
    sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET post_logout_redirect_uris=ARRAY[]::text[] WHERE environment_id=$1 AND client_identifier=$2")
        .bind(changed.environment_id).bind(CLIENT).execute(&changed.db_pool).await?;
    changed.readiness = crate::web::ReadinessState::new();
    crate::web::test_support::reload_authorization_runtime(&mut changed).await?;
    changed
        .runtime_authority
        .try_synchronize_client_projection_from_database(&changed.db_pool, &changed.clients)
        .await?;
    assert_eq!(
        tx.choose(&changed, Some(&session.id), "confirm")
            .await?
            .status,
        StatusCode::BAD_REQUEST
    );
    f.intact(&session).await
}
