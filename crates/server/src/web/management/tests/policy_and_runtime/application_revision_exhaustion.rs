#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_application_counter_exhaustion_rejects_terminal_inputs() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        let mgmt = test_management_state();
        let sid = mgmt.sessions.create(env.administrator_id, crate::util::now_unix_epoch_secs()?).ok_or("session")?;
        let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
        let payload = serde_json::json!({"clientId":"default","subject":"default",
            "baseRevision":0,"authority":"operator","sourceRevision":1,"audiences":["resource"],
            "claims":{"roles":[],"organization_roles":[]},"enabled":true,"reason":"counter boundary regression"});
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
            "application-authorizations", &sid, payload.clone())?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await?["revision"], 1);
        let stored: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(a) FROM aegaeon.application_authorizations a WHERE environment_id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        for (base, source, enabled) in [
            (1, i64::MAX, true), (1, i64::MAX - 1, true),
            (1, i64::MAX, false), (i64::MAX - 1, 2, true),
            (i64::MAX - 1, 2, false), (i64::MAX, 2, false),
            (-1, 2, true), (1, 0, true),
        ] {
            let mut bad = payload.clone();
            bad["baseRevision"] = base.into(); bad["sourceRevision"] = source.into();
            bad["enabled"] = enabled.into();
            let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
                "application-authorizations", &sid, bad)?).await?;
            let status = response.status();
            let body = response_json(response).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "base={base} source={source} enabled={enabled}: {body}");
            assert_eq!(body["errorCode"], "invalid_request");
            let after: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(a) FROM aegaeon.application_authorizations a WHERE environment_id=$1")
                .bind(env.environment_id).fetch_one(&pool).await?;
            assert_eq!(after, stored);
            let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.application_authorization.updated.v1'")
                .bind(env.environment_id).fetch_one(&pool).await?;
            assert_eq!(audits, 1);
        }
        Ok(())
    }.await;
    sqlx::query("DELETE FROM aegaeon.application_authorizations WHERE environment_id=$1")
        .bind(env.environment_id).execute(&pool).await?;
    finish_runtime_key_pg_test(result, cleanup_configuration_members(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_application_counter_exhaustion_reserves_audited_revocation() -> TestResult {
    use crate::application_authorization::store::{capture, is_current, lock_current};
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        let mgmt = test_management_state();
        let sid = mgmt.sessions.create(env.administrator_id, crate::util::now_unix_epoch_secs()?).ok_or("session")?;
        let state = test_app_state(pool.clone(), mgmt)?;
        let issuer = state.issuer.to_string();
        let app = super::super::build_router(state);
        let mut payload = serde_json::json!({"clientId":"default","subject":"default",
            "baseRevision":0,"authority":"operator","sourceRevision":1,"audiences":["resource"],
            "claims":{"roles":[],"organization_roles":[]},"enabled":true,"reason":"last active revision"});
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
            "application-authorizations", &sid, payload.clone())?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        // Place only the counters near exhaustion; identity binding and all subsequent
        // authority changes still use the real management and online validation paths.
        sqlx::query("UPDATE aegaeon.application_authorizations SET revision=$2,source_revision=$2 WHERE environment_id=$1")
            .bind(env.environment_id).bind(i64::MAX - 3).execute(&pool).await?;
        payload["baseRevision"] = (i64::MAX - 3).into();
        payload["sourceRevision"] = (i64::MAX - 2).into();
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
            "application-authorizations", &sid, payload.clone())?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await?["revision"], i64::MAX - 2);
        let old = capture(&pool, env.environment_id, &issuer, "default", "default").await?.ok_or("active projection")?;
        assert!(is_current(&pool, env.environment_id, &issuer, &old).await?);
        assert!(lock_current(&pool, env.environment_id, &issuer, &old).await?.is_some());
        payload["baseRevision"] = (i64::MAX - 2).into();
        payload["sourceRevision"] = (i64::MAX - 1).into();
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
            "application-authorizations", &sid, payload.clone())?).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(response).await?["errorCode"], "invalid_request");
        assert!(is_current(&pool, env.environment_id, &issuer, &old).await?);
        payload["enabled"] = false.into(); payload["reason"] = "revoke at counter boundary".into();
        // Exhaustion does not relax the authority, source freshness or CAS checks.
        for (key, value) in [
            ("authority", serde_json::json!("different-authority")),
            ("baseRevision", serde_json::json!(i64::MAX - 3)),
            ("sourceRevision", serde_json::json!(i64::MAX - 2)),
        ] {
            let mut bad = payload.clone(); bad[key] = value;
            let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
                "application-authorizations", &sid, bad)?).await?;
            assert_eq!(response.status(), StatusCode::CONFLICT);
            assert_eq!(response_json(response).await?["errorCode"], "base_revision_mismatch");
        }
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
            "application-authorizations", &sid, payload.clone())?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await?["revision"], i64::MAX - 1);
        assert!(capture(&pool, env.environment_id, &issuer, "default", "default").await?.is_none());
        assert!(!is_current(&pool, env.environment_id, &issuer, &old).await?);
        assert!(lock_current(&pool, env.environment_id, &issuer, &old).await?.is_none());
        let stored: (i64, i64, bool) = sqlx::query_as("SELECT revision,source_revision,enabled FROM aegaeon.application_authorizations WHERE environment_id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(stored, (i64::MAX - 1, i64::MAX - 1, false));
        let audit: serde_json::Value = sqlx::query_scalar("SELECT data FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.application_authorization.updated.v1' AND data->>'reason'='revoke at counter boundary'")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(audit["fromRevision"], i64::MAX - 2);
        assert_eq!(audit["toRevision"], i64::MAX - 1);
        assert_eq!(audit["sourceRevision"], i64::MAX - 1);
        assert_eq!(audit["enabled"], false);
        payload["baseRevision"] = (i64::MAX - 1).into();
        payload["sourceRevision"] = i64::MAX.into(); payload["enabled"] = true.into();
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
            "application-authorizations", &sid, payload)?).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(response).await?["errorCode"], "invalid_request");
        assert!(capture(&pool, env.environment_id, &issuer, "default", "default").await?.is_none());
        assert!(!is_current(&pool, env.environment_id, &issuer, &old).await?);
        Ok(())
    }.await;
    sqlx::query("DELETE FROM aegaeon.application_authorizations WHERE environment_id=$1")
        .bind(env.environment_id).execute(&pool).await?;
    finish_runtime_key_pg_test(result, cleanup_configuration_members(&pool, &env).await)
}
