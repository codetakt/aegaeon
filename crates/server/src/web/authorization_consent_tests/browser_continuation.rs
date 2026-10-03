//! The real consent route preserves query/form_post approve and deny results.
use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn consent_form_referrer_policy_preserves_strict_origin_validation() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL required; no silent skip")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, sid) = fixture(&pool, &env).await?;
        update_test_policy(&mut state, |policy| policy.strict_authorize_redirect = true).await?;
        let app = super::super::router::build_router(state.clone()).layer(Extension(ConnectInfo(
            SocketAddr::from(([127, 0, 0, 1], 12345)),
        )));
        let response = app
            .clone()
            .oneshot(
                Request::get(authorize_uri(&state, Some("consent"))?)
                    .header(header::COOKIE, format!("aegaeon_auth_session={sid}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::REFERRER_POLICY], "same-origin");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(response.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY],
            "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'none'; script-src 'none'; style-src 'unsafe-inline'");
        let html = String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await?.to_vec())?;
        let token = transaction(&html)?.to_owned();
        let valid = header::HeaderValue::from_str(&state.issuer)?;
        let foreign = header::HeaderValue::from_static("https://foreign.example.test");
        let controls = [
            ("missing", vec![]),
            ("null", vec![header::HeaderValue::from_static("null")]),
            ("foreign", vec![foreign.clone()]),
            ("non_ascii", vec![header::HeaderValue::from_bytes(b"https://issuer.example.test\x80")?]),
            ("combined", vec![header::HeaderValue::from_str(&format!("{} https://foreign.example.test", state.issuer))?]),
            ("duplicate_exact", vec![valid.clone(), valid.clone()]),
            ("duplicate_foreign", vec![valid.clone(), foreign]),
        ];
        let body = serde_urlencoded::to_string([("transaction", token.as_str()), ("decision", "approve")])?;
        for (label, origins) in controls {
            let mut request = Request::post("/auth/consent")
                .header(header::COOKIE, format!("aegaeon_auth_session={sid}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.clone()))?;
            for origin in origins {
                request.headers_mut().append(header::ORIGIN, origin);
            }
            let response = app.clone().oneshot(request).await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{label}");
            assert!(response.headers().get(header::LOCATION).is_none(), "{label}");
            let rejected = String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await?.to_vec())?;
            assert!(!rejected.contains("aegaeon-continuation"), "{label}");
        }
        // Origin failures must not decide or consume the valid transaction.
        let response = app
            .oneshot(
                Request::post("/auth/consent")
                    .header(header::COOKIE, format!("aegaeon_auth_session={sid}"))
                    .header(header::ORIGIN, valid)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert!(response.headers().get(header::LOCATION).is_none());
        let html = String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await?.to_vec())?;
        assert!(continuation_destination(&html)?.contains("code="));
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn scenario(state: &mut AppState, sid: &str, choice: &str, mode: &str) -> TestResult {
    update_test_policy(state, |policy| policy.strict_authorize_redirect = true).await?;
    let uri = format!(
        "{}&response_mode={mode}",
        authorize_uri(state, Some("consent"))?
    );
    let request: Vec<(String, String)> =
        serde_urlencoded::from_str(uri.split_once('?').ok_or("query missing")?.1)?;
    let expected_state = request
        .iter()
        .find(|(key, _)| key == "state")
        .ok_or("state missing")?
        .1
        .clone();
    let (status, page) = send(state, sid, &uri, None, None).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let transaction = transaction(&page)?.to_string();
    let (status, page) = send(
        state,
        sid,
        "/auth/consent",
        Some(vec![("transaction", &transaction), ("decision", choice)]),
        Some(&state.issuer),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let fields: Vec<(String, String)> = if mode == "query" {
        let destination = continuation_destination(&page)?;
        let url = url::Url::parse(&destination)?;
        assert_eq!(
            url.origin().ascii_serialization(),
            "https://client.example.com"
        );
        assert_eq!(url.path(), "/callback");
        assert!(!page.contains("<form"));
        url.query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    } else {
        assert!(page.contains("id=\"aegaeon-form-post\""));
        assert!(!page.contains("aegaeon-continuation"));
        let mut fields = Vec::new();
        for name in ["code", "error", "state", "iss"] {
            let needle = format!("name=\"{name}\" value=\"");
            if let Some(value) = page
                .split(&needle)
                .nth(1)
                .and_then(|value| value.split('"').next())
            {
                fields.push((
                    name.to_string(),
                    value
                        .replace("&quot;", "\"")
                        .replace("&#x27;", "'")
                        .replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("&amp;", "&"),
                ));
            }
        }
        fields
    };
    assert_eq!(
        fields
            .iter()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.as_str()),
        Some(expected_state.as_str())
    );
    assert_eq!(
        fields
            .iter()
            .find(|(key, _)| key == "iss")
            .map(|(_, value)| value.as_str()),
        Some(state.issuer.as_str())
    );
    if choice == "approve" {
        assert!(fields
            .iter()
            .any(|(key, value)| key == "code" && !value.is_empty()));
        assert!(!fields.iter().any(|(key, _)| key == "error"));
    } else {
        assert!(fields
            .iter()
            .any(|(key, value)| key == "error" && value == "access_denied"));
        assert!(!fields.iter().any(|(key, _)| key == "code"));
    }
    let (status, _) = send(
        state,
        sid,
        "/auth/consent",
        Some(vec![("transaction", &transaction), ("decision", "approve")]),
        Some(&state.issuer),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "decisions remain one-time");
    Ok(())
}

async fn run(choice: &str, mode: &str) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL required; no silent skip")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, sid) = fixture(&pool, &env).await?;
        scenario(&mut state, &sid, choice, mode).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

macro_rules! continuation_test {
    ($name:ident, $choice:literal, $mode:literal) => {
        #[tokio::test]
        #[ignore = "requires PostgreSQL"]
        async fn $name() -> TestResult {
            run($choice, $mode).await
        }
    };
}
continuation_test!(
    consent_approve_query_uses_html_continuation,
    "approve",
    "query"
);
continuation_test!(consent_deny_query_uses_html_continuation, "deny", "query");
continuation_test!(
    consent_approve_form_post_is_preserved,
    "approve",
    "form_post"
);
continuation_test!(consent_deny_form_post_is_preserved, "deny", "form_post");
