use super::support::{fixture, remote, unavailable, unavailable_states, TestResult};
use crate::web::{self, auth_session::AuthSessionTimes};
use axum::{
    extract::{OriginalUri, Query, State},
    http::{header, HeaderMap, StatusCode},
};
use serde_json::json;

pub(super) fn session(state: &web::AppState, subject: &str) -> TestResult<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(state
        .browser_auth
        .auth_sessions
        .try_create(
            subject,
            AuthSessionTimes {
                created_at_epoch_secs: now,
                auth_time_epoch_secs: now,
            },
            None,
            None,
            None,
        )?
        .ok_or("session missing")?)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_local_logout_preserves_session_until_matching_permit() -> TestResult {
    let (state, _) = fixture().await?;
    let sid = session(&state, "namespace-user")?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{}={sid}", web::AUTH_SESSION_COOKIE_NAME).parse()?,
    );
    for denied in unavailable_states(&state) {
        unavailable(web::local_auth::local_logout_post(State(denied), headers.clone()).await)
            .await?;
        assert!(state.browser_auth.auth_sessions.try_get(&sid)?.is_some());
    }
    let response = web::local_auth::local_logout_post(State(state.clone()), headers).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/auth/login");
    assert!(response.headers().contains_key(header::SET_COOKIE));
    assert!(state.browser_auth.auth_sessions.try_get(&sid)?.is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_upstream_logout_callback_retains_relay_until_matching_permit() -> TestResult {
    let (state, _) = fixture().await?;
    let relay = uuid::Uuid::new_v4().to_string();
    state.upstream.logout_relay_store.try_insert(
        &relay,
        web::UpstreamLogoutRelayState {
            incident_id: None,
            downstream_redirect_uri: "https://client.example/signed-out".into(),
            downstream_state: Some("retained-state".into()),
        },
    )?;
    for denied in unavailable_states(&state) {
        unavailable(
            web::logout_endpoint::upstream_logout_callback(
                State(denied),
                remote(),
                HeaderMap::new(),
                Query(serde_json::from_value(json!({"state":relay}))?),
            )
            .await,
        )
        .await?;
    }
    let response = web::logout_endpoint::upstream_logout_callback(
        State(state.clone()),
        remote(),
        HeaderMap::new(),
        Query(serde_json::from_value(json!({"state":relay}))?),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()[header::LOCATION],
        "https://client.example/signed-out?state=retained-state"
    );
    assert!(state
        .upstream
        .logout_relay_store
        .try_take(&relay)?
        .is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_login_positive_issues_form_and_csrf_cookie() -> TestResult {
    let (state, _) = fixture().await?;
    let response = web::local_auth::local_login_get(
        State(state),
        OriginalUri("/auth/login".parse()?),
        HeaderMap::new(),
        Query(serde_json::from_value(json!({}))?),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()[header::SET_COOKIE]
        .to_str()?
        .contains(web::LOCAL_AUTH_CSRF_COOKIE_NAME));
    let body = axum::body::to_bytes(response.into_body(), 65536).await?;
    assert!(std::str::from_utf8(&body)?.contains("<form"));
    Ok(())
}
