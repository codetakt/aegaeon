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
    let (mut state, _) = fixture().await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    state.browser_auth.auth_sessions = std::sync::Arc::new(web::AuthSessionStore::from_postgres(
        &crate::management::types::PolicyDocument::default(),
        state.db_pool.clone(),
        &namespace,
    )?);

    let now = crate::util::now_unix_epoch_secs()?;
    let sid = state
        .browser_auth
        .auth_sessions
        .try_create_async(
            "namespace-user".into(),
            AuthSessionTimes::local(now),
            None,
            None,
            None,
        )
        .await?
        .ok_or("session missing")?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{}={sid}", web::AUTH_SESSION_COOKIE_NAME).parse()?,
    );
    for denied in unavailable_states(&state) {
        unavailable(web::local_auth::local_logout_post(State(denied), headers.clone()).await)
            .await?;
        assert!(state
            .browser_auth
            .auth_sessions
            .try_get_async(sid.clone())
            .await?
            .is_some());
    }
    let response = web::local_auth::local_logout_post(State(state.clone()), headers).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/auth/login");
    assert!(response.headers().contains_key(header::SET_COOKIE));
    assert!(state
        .browser_auth
        .auth_sessions
        .try_get_async(sid.clone())
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_upstream_logout_callback_retains_relay_until_matching_permit() -> TestResult {
    let (mut state, _) = fixture().await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    state.upstream.logout_relay_store = std::sync::Arc::new(
        web::UpstreamLogoutRelayStore::from_postgres(state.db_pool.clone(), &namespace, 60)?,
    );
    let relay = uuid::Uuid::new_v4().to_string();
    state
        .upstream
        .logout_relay_store
        .try_insert_async(
            relay.clone(),
            web::UpstreamLogoutRelayState {
                incident_id: None,
                downstream_redirect_uri: "https://client.example/signed-out".into(),
                downstream_state: Some("retained-state".into()),
            },
        )
        .await
        .map_err(anyhow::Error::msg)?;
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
        .try_take_async(relay.clone())
        .await
        .map_err(anyhow::Error::msg)?
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

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_browser_inventory_pages_and_direct_revocation() -> TestResult {
    use super::management_fixture as m;
    let (mut state, env) = fixture().await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    state.browser_auth.auth_sessions = std::sync::Arc::new(web::AuthSessionStore::from_postgres(
        &crate::management::types::PolicyDocument::default(),
        state.db_pool.clone(),
        &namespace,
    )?);
    let (user, subject) = m::user(&state, &env).await?;
    let key = m::human_session(&state, &env).await?;
    let now = crate::util::now_unix_epoch_secs()?;
    let mut expected = std::collections::BTreeSet::new();
    let mut ids = Vec::new();
    for _ in 0..5 {
        let sid = state
            .browser_auth
            .auth_sessions
            .try_create_async(
                subject.clone(),
                AuthSessionTimes::local(now),
                None,
                None,
                None,
            )
            .await?
            .ok_or("session missing")?;
        expected.insert(aegaeon_crypto::hash::sha256_hex(sid.as_bytes()));
        ids.push(sid);
    }
    let base = m::base_path(&env, user);
    let mut token = None;
    let mut seen = std::collections::BTreeSet::new();
    for page in 0..3 {
        let path = match token {
            Some(ref token) => format!("{base}/sessions?pageSize=2&pageToken={token}"),
            None => format!("{base}/sessions?pageSize=2"),
        };
        let response = m::request(&state, &key, "GET", &path).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await?)?;
        let rows = body["sessions"].as_array().ok_or("sessions missing")?;
        assert_eq!(rows.len(), if page == 2 { 1 } else { 2 });
        for row in rows {
            assert!(seen.insert(row["id"].as_str().ok_or("id missing")?.to_owned()));
        }
        token = body["pageInfo"]["nextPageToken"]
            .as_str()
            .map(str::to_owned);
    }
    assert!(token.is_none());
    assert_eq!(seen, expected);
    let id = aegaeon_crypto::hash::sha256_hex(ids[0].as_bytes());
    assert_eq!(
        m::request(
            &state,
            &key,
            "POST",
            &format!("{base}/sessions/{id}/revoke")
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    assert!(state
        .browser_auth
        .auth_sessions
        .try_get_async(ids[0].clone())
        .await?
        .is_none());
    assert_eq!(
        m::request(
            &state,
            &key,
            "GET",
            &format!("{base}/sessions?pageToken=bad")
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}
