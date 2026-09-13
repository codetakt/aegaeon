#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_application_subject_reassignment_requires_audited_reauthorization() -> TestResult {
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
        // Existing ACTIVE identities are fixture input. Subject reassignment and
        // every authorization change below use the real management HTTP handlers.
        let mut ids = Vec::new();
        for subject in ["subject-a", "subject-b"] {
            let id: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES ($1,$2,'ACTIVE') RETURNING id")
                .bind(env.environment_id).bind(subject).fetch_one(&pool).await?;
            ids.push(id.to_string());
        }
        assert_ne!(ids[0], ids[1]);
        let mut projection = serde_json::json!({"clientId":"bound","subject":"subject-a",
            "baseRevision":0,"authority":"operator","sourceRevision":1,"audiences":["resource"],
            "claims":{"roles":["USER"],"organization_roles":[]},"enabled":true,
            "reason":"explicit identity authorization"});
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
            "application-authorizations", &sid, projection.clone())?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let old = capture(&pool,env.environment_id,&issuer,"bound","subject-a").await?.ok_or("initial grant")?;
        assert!(lock_current(&pool,env.environment_id,&issuer,&old).await?.is_some());
        for (id, subject) in [(&ids[0], "subject-c"), (&ids[1], "subject-a")] {
            let response = app.clone().oneshot(membership_http_request(Method::PATCH, &env,
                &format!("users/{id}"), &sid, serde_json::json!({"subject":subject}))?).await?;
            let status = response.status();
            let body = response_json(response).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["subject"], subject);
        }
        assert!(capture(&pool,env.environment_id,&issuer,"bound","subject-a").await?.is_none());
        assert!(!is_current(&pool,env.environment_id,&issuer,&old).await?);
        assert!(lock_current(&pool,env.environment_id,&issuer,&old).await?.is_none());
        let bound: Uuid = sqlx::query_scalar("SELECT end_user_record_id FROM aegaeon.application_authorizations WHERE environment_id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(bound.to_string(), ids[0]);
        // Disabling after reassignment audits the previously bound user.
        projection["enabled"] = false.into();
        projection["baseRevision"] = 1.into(); projection["sourceRevision"] = 2.into();
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
            "application-authorizations", &sid, projection.clone())?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let target: String = sqlx::query_scalar("SELECT target_id FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.application_authorization.updated.v1' AND data->>'toRevision'='2'")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(target, ids[0]);
        projection["enabled"] = true.into();
        projection["baseRevision"] = 2.into(); projection["sourceRevision"] = 3.into();
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
            "application-authorizations", &sid, projection.clone())?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await?["revision"], 3);
        let new = capture(&pool,env.environment_id,&issuer,"bound","subject-a").await?.ok_or("regrant")?;
        assert_eq!(new.revision, 3);
        assert!(is_current(&pool,env.environment_id,&issuer,&new).await?);
        assert!(!is_current(&pool,env.environment_id,&issuer,&old).await?);
        assert!(lock_current(&pool,env.environment_id,&issuer,&old).await?.is_none());
        let audit: serde_json::Value = sqlx::query_scalar("SELECT data FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.application_authorization.updated.v1' AND data->>'toRevision'='3'")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(audit["endUserRecordId"], ids[1]);
        assert!(audit["clientRecordId"].as_str().is_some());
        // A retained pre-migration projection has no provable identity owner.
        sqlx::query("UPDATE aegaeon.application_authorizations SET client_record_id=NULL,end_user_record_id=NULL WHERE environment_id=$1")
            .bind(env.environment_id).execute(&pool).await?;
        assert!(capture(&pool,env.environment_id,&issuer,"bound","subject-a").await?.is_none());
        assert!(lock_current(&pool,env.environment_id,&issuer,&new).await?.is_none());
        projection["baseRevision"] = 3.into(); projection["sourceRevision"] = 4.into();
        let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
            "application-authorizations", &sid, projection)?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(capture(&pool,env.environment_id,&issuer,"bound","subject-a").await?.ok_or("legacy reauthorization")?.revision, 4);
        assert!(!is_current(&pool,env.environment_id,&issuer,&new).await?);
        Ok(())
    }.await;
    for table in ["application_authorizations", "end_users"] {
        sqlx::query(&format!("DELETE FROM aegaeon.{table} WHERE environment_id=$1"))
            .bind(env.environment_id).execute(&pool).await?;
    }
    finish_runtime_key_pg_test(result, cleanup_configuration_members(&pool, &env).await)
}
