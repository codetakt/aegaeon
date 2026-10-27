use super::fixture::*;
use crate::web::{test_support::TestResult, AUTH_SESSION_COOKIE_NAME};
use axum::http::{header, Method, StatusCode};
use std::collections::BTreeMap;

pub(super) async fn replacement(f: &Fixture) -> TestResult {
    let session = f.session("cookie-slot-user", None).await?;
    let first = f.start(Method::GET, &[], Some(&session.id)).await?;
    assert_eq!(
        first.show(&f.state, Some(&session.id)).await?.status,
        StatusCode::OK
    );
    let mut jar = BTreeMap::from([(AUTH_SESSION_COOKIE_NAME.to_string(), session.id.clone())]);
    let mut latest = first.cookie.clone();
    for method in [Method::GET, Method::POST].into_iter().cycle().take(16) {
        let tx = f
            .start(method, &[("client_id", CLIENT)], Some(&session.id))
            .await?;
        let (name, secret) = tx.cookie.split_once('=').ok_or("cookie")?;
        assert_eq!(name, "__Host-aegaeon-logout");
        assert_ne!(tx.cookie, latest, "every start rotates the secret");
        jar.insert(name.to_string(), secret.to_string());
        assert_eq!(
            jar.len(),
            2,
            "confirmation starts cannot grow the cookie jar"
        );
        assert_eq!(jar.get(AUTH_SESSION_COOKIE_NAME), Some(&session.id));
        let page = tx.show(&f.state, Some(&session.id)).await?;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page
            .body
            .contains("Sign-out was requested for this browser."));
        assert!(
            !page.body.contains(CLIENT),
            "public client_id is not requester provenance"
        );
        latest = tx.cookie;
    }
    let current = jar
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    assert_eq!(
        send(
            &f.state,
            Method::GET,
            &first.location,
            Some(&current),
            None,
            ""
        )
        .await?
        .status,
        StatusCode::BAD_REQUEST
    );
    let body = format!("transaction={}&decision=confirm", first.token);
    assert_eq!(
        send(
            &f.state,
            Method::POST,
            "/logout/confirm",
            Some(&current),
            Some(&f.state.issuer),
            &body
        )
        .await?
        .status,
        StatusCode::BAD_REQUEST
    );
    f.intact(&session).await?;
    let hint = f.hint("cookie-slot-user", Some(&session.oidc))?;
    let tx = f
        .start(
            Method::GET,
            &[("client_id", CLIENT), ("id_token_hint", &hint)],
            Some(&session.id),
        )
        .await?;
    let page = tx.show(&f.state, Some(&session.id)).await?;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        !page.body.contains(CLIENT),
        "a replayable hint does not authenticate the requester"
    );
    let cancelled = tx.choose(&f.state, Some(&session.id), "cancel").await?;
    assert_eq!(cancelled.status, StatusCode::OK);
    let clear = cancelled.headers[header::SET_COOKIE].to_str()?;
    assert!(clear.starts_with("__Host-aegaeon-logout=;"));
    assert!(clear.contains("Max-Age=0"));
    assert_eq!(
        cancelled.headers.get_all(header::SET_COOKIE).iter().count(),
        1
    );
    assert_eq!(
        tx.choose(&f.state, Some(&session.id), "confirm")
            .await?
            .status,
        StatusCode::BAD_REQUEST
    );
    f.intact(&session).await
}
