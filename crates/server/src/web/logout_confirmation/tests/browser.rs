use super::fixture::*;
use crate::web::test_support::TestResult;
use axum::http::{header, Method, StatusCode};

pub(super) async fn sessions(f: &Fixture) -> TestResult {
    let a = f.session("current<user>", None).await?;
    let b = f.session("current<user>", None).await?;
    let foreign = f.session("foreign-secret-subject", None).await?;
    let hint = f.hint("foreign-secret-subject", Some(&foreign.oidc))?;
    // Cross-site POST has no normal auth cookie; the returning top-level GET does.
    let tx = f
        .start(
            Method::POST,
            &[
                ("id_token_hint", &hint),
                ("client_id", CLIENT),
                ("post_logout_redirect_uri", REDIRECT),
                ("state", "round trip +&"),
            ],
            None,
        )
        .await?;
    for s in [&a, &b, &foreign] {
        f.intact(s).await?;
    }
    let page = tx.show(&f.state, Some(&a.id)).await?;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("current&lt;user&gt;"));
    assert!(!page.body.contains("foreign-secret-subject"));
    assert!(!page.body.contains(&hint));
    assert_eq!(page.headers[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(page.headers[header::X_FRAME_OPTIONS], "DENY");
    assert!(page.headers[header::CONTENT_SECURITY_POLICY]
        .to_str()?
        .contains("frame-ancestors 'none'"));
    assert_eq!(tx.show(&f.state, Some(&a.id)).await?.status, StatusCode::OK);
    for s in [&a, &b, &foreign] {
        f.intact(s).await?;
    }
    let done = tx.choose(&f.state, Some(&a.id), "confirm").await?;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    let redirect = url::Url::parse(done.headers[header::LOCATION].to_str()?)?;
    assert_eq!(
        redirect.origin().ascii_serialization(),
        "https://rp.example"
    );
    assert!(redirect
        .query_pairs()
        .any(|(k, v)| k == "state" && v == "round trip +&"));
    assert_eq!(done.headers.get_all(header::SET_COOKIE).iter().count(), 2);
    f.ended(&a).await?;
    f.intact(&b).await?;
    f.intact(&foreign).await?;
    assert_eq!(
        tx.choose(&f.state, Some(&a.id), "confirm").await?.status,
        StatusCode::BAD_REQUEST
    );

    // GET and client_id-only requests use the same confirmation path.
    let tx = f
        .start(
            Method::GET,
            &[
                ("client_id", CLIENT),
                ("post_logout_redirect_uri", REDIRECT),
            ],
            Some(&b.id),
        )
        .await?;
    f.intact(&b).await?;
    assert_eq!(tx.show(&f.state, Some(&b.id)).await?.status, StatusCode::OK);
    let cancelled = tx.choose(&f.state, Some(&b.id), "cancel").await?;
    assert_eq!(cancelled.status, StatusCode::OK);
    assert!(cancelled.body.contains("cancelled"));
    assert!(!cancelled.headers.contains_key(header::LOCATION));
    f.intact(&b).await?;
    let matching = f.hint("current<user>", Some(&b.oidc))?;
    let tx = f
        .start(
            Method::GET,
            &[("client_id", CLIENT), ("id_token_hint", &matching)],
            Some(&b.id),
        )
        .await?;
    tx.show(&f.state, Some(&b.id)).await?;
    assert_eq!(
        tx.choose(&f.state, Some(&b.id), "confirm").await?.status,
        StatusCode::OK
    );
    f.ended(&b).await?;

    // No current browser session is explicitly bound to no session. A hint
    // without sid cannot revive the old user-wide logout fallback.
    let no_sid_hint = f.hint("foreign-secret-subject", None)?;
    let tx = f
        .start(Method::GET, &[("id_token_hint", &no_sid_hint)], None)
        .await?;
    assert_eq!(tx.show(&f.state, None).await?.status, StatusCode::OK);
    assert_eq!(
        tx.choose(&f.state, None, "confirm").await?.status,
        StatusCode::OK
    );
    f.intact(&foreign).await?;
    let tx = f.start(Method::GET, &[], Some(&foreign.id)).await?;
    tx.show(&f.state, Some(&foreign.id)).await?;
    assert_eq!(
        tx.choose(&f.state, Some(&foreign.id), "confirm")
            .await?
            .status,
        StatusCode::OK
    );
    f.ended(&foreign).await
}

pub(super) async fn upstream(f: &Fixture) -> TestResult {
    let upstream = crate::web::auth_session::UpstreamLogoutSession {
        issuer: "https://upstream.example".into(),
        end_session_endpoint: Some("https://upstream.example/logout".into()),
        back_channel: false,
        session_hint_claim: Some("sid".into()),
        session_hint_value: Some("current-upstream-session".into()),
        recovery_policy: crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
        team_id: None,
        tenant_id: None,
        environment_id: None,
        connection_id: None,
    };
    let session = f.session("upstream-user", Some(upstream)).await?;
    let tx = f
        .start(
            Method::GET,
            &[
                ("client_id", CLIENT),
                ("post_logout_redirect_uri", REDIRECT),
                ("state", "downstream-state"),
            ],
            Some(&session.id),
        )
        .await?;
    let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    let mut conn = client.get_connection()?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{}*", f.relay_prefix))
        .query(&mut conn)?;
    assert!(keys.is_empty(), "no relay before confirmation");
    tx.show(&f.state, Some(&session.id)).await?;
    let done = tx.choose(&f.state, Some(&session.id), "confirm").await?;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    let target = url::Url::parse(done.headers[header::LOCATION].to_str()?)?;
    assert_eq!(
        target.origin().ascii_serialization(),
        "https://upstream.example"
    );
    assert!(target
        .query_pairs()
        .any(|(k, v)| k == "logout_hint" && v == "current-upstream-session"));
    let token = target
        .query_pairs()
        .find(|(k, _)| k == "state")
        .ok_or("relay state")?
        .1
        .into_owned();
    let relay = f
        .state
        .upstream
        .logout_relay_store
        .try_take_async(token)
        .await?
        .ok_or("relay persisted")?;
    assert_eq!(relay.downstream_redirect_uri, REDIRECT);
    assert_eq!(relay.downstream_state.as_deref(), Some("downstream-state"));
    assert_eq!(done.headers.get_all(header::SET_COOKIE).iter().count(), 2);
    f.ended(&session).await
}
