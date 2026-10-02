use super::{
    browser_consumption::session,
    management_fixture as m,
    support::{fixture, unavailable, unavailable_states, TestResult},
};
use crate::{oidc::OidcSessionStore, web::test_support};
use axum::{body::to_bytes, http::StatusCode};
use serde_json::Value;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_management_session_actions_preserve_commands_audit_and_sessions() -> TestResult
{
    for single in [true, false] {
        let (mut state, env) = fixture().await?;
        state.oidc.sessions = Some(OidcSessionStore::new_process_local_for_tests());
        state.validate_subject_namespace().await?;
        let (user, subject) = m::user(&state, &env).await?;
        let key = m::human_session(&state, &env).await?;
        let sid = session(&state, &subject)?;
        let sessions = state
            .oidc
            .sessions
            .as_ref()
            .ok_or("OIDC sessions missing")?;
        let oidc_sid = sessions.try_get_or_create_session(crate::oidc::OidcSessionContext {
            user_id: &subject,
            auth_session_id: &sid,
        })?;
        assert!(sessions.try_add_client(&oidc_sid, "namespace-client")?);
        let base = m::base_path(&env, user);
        let inventory = m::request(&state, &key, "GET", &format!("{base}/sessions")).await?;
        assert_eq!(inventory.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(&to_bytes(inventory.into_body(), 65536).await?)?;
        let inventory_id = body["sessions"][0]["id"]
            .as_str()
            .ok_or("session inventory missing")?;
        let path = if single {
            format!("{base}/sessions/{inventory_id}/revoke")
        } else {
            format!("{base}/invalidateSessions")
        };
        let before = m::effects(&state, &env).await?;
        for denied in unavailable_states(&state) {
            unavailable(m::request(&denied, &key, "POST", &path).await?).await?;
            assert_eq!(m::effects(&state, &env).await?, before);
            assert!(state.browser_auth.auth_sessions.try_get(&sid)?.is_some());
            assert_eq!(
                sessions.try_get_or_create_session(crate::oidc::OidcSessionContext {
                    user_id: &subject,
                    auth_session_id: &sid
                })?,
                oidc_sid
            );
        }
        let response = m::request(&state, &key, "POST", &path).await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(state.browser_auth.auth_sessions.try_get(&sid)?.is_none());
        assert!(
            sessions.try_logout_by_auth_session_id(&sid)?.is_none(),
            "matching request already logged out OIDC session"
        );
        let after = m::effects(&state, &env).await?;
        assert_eq!(after.0, before.0 + 1);
        assert!(after.1 > before.1);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_management_cannot_borrow_another_environments_valid_permit() -> TestResult {
    let (state, _) = fixture().await?;
    let target = test_support::setup_test_environment(&state.db_pool).await?;
    let (user, subject) = m::user(&state, &target).await?;
    let key = m::human_session(&state, &target).await?;
    let sid = session(&state, &subject)?;
    let base = m::base_path(&target, user);
    let inventory = m::request(&state, &key, "GET", &format!("{base}/sessions")).await?;
    assert_eq!(
        inventory.status(),
        StatusCode::OK,
        "authenticated management read remains available"
    );
    let body: Value = serde_json::from_slice(&to_bytes(inventory.into_body(), 65536).await?)?;
    let id = body["sessions"][0]["id"]
        .as_str()
        .ok_or("inventory missing")?;
    let before = m::effects(&state, &target).await?;
    for path in [
        format!("{base}/sessions/{id}/revoke"),
        format!("{base}/invalidateSessions"),
    ] {
        assert!(state.require_subject_namespace().is_ok());
        unavailable(m::request(&state, &key, "POST", &path).await?).await?;
        assert_eq!(m::effects(&state, &target).await?, before);
        assert!(state.browser_auth.auth_sessions.try_get(&sid)?.is_some());
    }
    Ok(())
}
