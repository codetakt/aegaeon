#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_application_projection_revocation_survives_identity_deactivation() -> TestResult {
    use crate::application_authorization::store::{capture, is_current};

    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        sqlx::query("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES ($1,'projection-user','ACTIVE')")
            .bind(env.environment_id).execute(&pool).await?;
        let mgmt = test_management_state();
        let now = crate::util::now_unix_epoch_secs()?;
        let sid = mgmt.sessions.create(env.administrator_id, now)
            .ok_or_else(|| io::Error::other("session creation failed"))?;
        let outsider = mgmt.sessions.create(env.non_member_administrator_id, now)
            .ok_or_else(|| io::Error::other("session creation failed"))?;
        let state = test_app_state(pool.clone(), mgmt)?;
        let issuer = state.issuer.to_string();
        let app = super::super::build_router(state);
        let mut payload = serde_json::json!({
            "clientId":"bound", "subject":"projection-user", "baseRevision":0,
            "authority":"operator", "sourceRevision":1, "audiences":["resource"],
            "claims":{"roles":["USER"],"organization_roles":[]},
            "enabled":true, "reason":"projection lifecycle regression"
        });
        let request = |value, session: &str| membership_http_request(
            Method::POST, &env, "application-authorizations", session, value);
        let response = app.clone().oneshot(request(payload.clone(), &sid)?).await?;
        let status = response.status();
        let value = response_json(response).await?;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(value["revision"], 1);
        let user_id: Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.end_users WHERE environment_id=$1 AND subject='projection-user'")
            .bind(env.environment_id).fetch_one(&pool).await?;
        let audit: (String, String, String, String) = sqlx::query_as("SELECT actor_type,actor_id,target_type,target_id FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.application_authorization.updated.v1'")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(audit, ("ADMINISTRATOR".into(), env.administrator_id.to_string(), "END_USER".into(), user_id.to_string()));

        let mut revision = 1_i64;
        for (deleted_client, user_status) in [
            (true, "ACTIVE"), (false, "SUSPENDED"), (true, "DELETED"),
        ] {
            let original = capture(&pool, env.environment_id, &issuer, "bound", "projection-user")
                .await?.ok_or_else(|| io::Error::other("active projection"))?;
            assert!(is_current(&pool, env.environment_id, &issuer, &original).await?);
            sqlx::query("UPDATE aegaeon.clients SET status=$2::aegaeon.client_status, deleted_at=CASE WHEN $3 THEN now() ELSE NULL END WHERE environment_id=$1 AND client_identifier='bound'")
                .bind(env.environment_id).bind(if deleted_client { "DELETED" } else { "ACTIVE" })
                .bind(deleted_client).execute(&pool).await?;
            sqlx::query("UPDATE aegaeon.end_users SET status=$2::aegaeon.end_user_status WHERE environment_id=$1 AND subject='projection-user'")
                .bind(env.environment_id).bind(user_status).execute(&pool).await?;
            payload["baseRevision"] = revision.into();
            payload["sourceRevision"] = (revision + 1).into();
            payload["enabled"] = true.into();
            let response = app.clone().oneshot(request(payload.clone(), &sid)?).await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response_json(response).await?["errorCode"], "invalid_request");
            payload["enabled"] = false.into();

            let mut no_reason = payload.clone();
            no_reason["reason"] = "  ".into();
            let response = app.clone().oneshot(request(no_reason, &sid)?).await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response_json(response).await?["errorCode"], "invalid_request");

            // A revocation still requires the owning authority and fresh revisions.
            for (key, value) in [
                ("baseRevision", serde_json::json!(revision - 1)),
                ("authority", serde_json::json!("other-authority")),
                ("sourceRevision", serde_json::json!(revision)),
            ] {
                let mut bad = payload.clone();
                bad[key] = value;
                let response = app.clone().oneshot(request(bad, &sid)?).await?;
                assert_eq!(response.status(), StatusCode::CONFLICT);
                assert_eq!(response_json(response).await?["errorCode"], "base_revision_mismatch");
            }
            let response = app.clone().oneshot(request(payload.clone(), &outsider)?).await?;
            // The management API conceals teams from non-members.
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(response_json(response).await?["errorCode"], "not_found");
            let mut no_csrf = request(payload.clone(), &sid)?;
            no_csrf.headers_mut().remove("x-csrf-token");
            assert_eq!(app.clone().oneshot(no_csrf).await?.status(), StatusCode::FORBIDDEN);
            assert!(!is_current(&pool, env.environment_id, &issuer, &original).await?);
            let response = app.clone().oneshot(request(payload.clone(), &sid)?).await?;
            let status = response.status();
            let value = response_json(response).await?;
            assert_eq!(status, StatusCode::OK, "{value}");
            revision += 1;
            assert_eq!(value["revision"], revision);
            assert!(!is_current(&pool, env.environment_id, &issuer, &original).await?);
            assert!(capture(&pool, env.environment_id, &issuer, "bound", "projection-user").await?.is_none());
            let audit: serde_json::Value = sqlx::query_scalar("SELECT data FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.application_authorization.updated.v1' AND data->>'toRevision'=$2")
                .bind(env.environment_id).bind(revision.to_string()).fetch_one(&pool).await?;
            assert_eq!(audit["enabled"], false);
            assert_eq!(audit["fromRevision"], revision - 1);
            assert_eq!(audit["reason"], payload["reason"]);

            // Reactivation needs both identities active and creates a new revision.
            sqlx::query("UPDATE aegaeon.clients SET status='ACTIVE',deleted_at=NULL WHERE environment_id=$1 AND client_identifier='bound'")
                .bind(env.environment_id).execute(&pool).await?;
            sqlx::query("UPDATE aegaeon.end_users SET status='ACTIVE' WHERE environment_id=$1 AND subject='projection-user'")
                .bind(env.environment_id).execute(&pool).await?;
            payload["baseRevision"] = revision.into();
            payload["sourceRevision"] = (revision + 1).into();
            payload["enabled"] = true.into();
            let response = app.clone().oneshot(request(payload.clone(), &sid)?).await?;
            assert_eq!(response.status(), StatusCode::OK);
            revision += 1;
            assert_eq!(response_json(response).await?["revision"], revision);
            assert!(!is_current(&pool, env.environment_id, &issuer, &original).await?);
        }
        // A duplicate soft-deleted subject does not replace the bound audit UUID.
        sqlx::query("INSERT INTO aegaeon.end_users(environment_id,subject,status) VALUES ($1,'projection-user','DELETED')")
            .bind(env.environment_id).execute(&pool).await?;
        payload["baseRevision"] = revision.into();
        payload["sourceRevision"] = (revision + 1).into();
        payload["enabled"] = false.into();
        let response = app.clone().oneshot(request(payload.clone(), &sid)?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let audit: (String, String) = sqlx::query_as("SELECT target_type,target_id FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.application_authorization.updated.v1' AND data->>'subject'='projection-user' AND data->>'toRevision'=$2")
            .bind(env.environment_id).bind((revision + 1).to_string()).fetch_one(&pool).await?;
        assert_eq!(audit, ("END_USER".into(), user_id.to_string()));
        // A disable request never creates a new row, even for active identities.
        for client in ["default", "unknown"] {
            let mut unknown = payload.clone();
            unknown["clientId"] = client.into();
            unknown["baseRevision"] = 0.into();
            unknown["sourceRevision"] = 1.into();
            unknown["enabled"] = false.into();
            let response = app.clone().oneshot(request(unknown, &sid)?).await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response_json(response).await?["errorCode"], "invalid_request");
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.application_authorizations WHERE environment_id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(count, 1);
        // Service principals have no end-user row or roles, but retain the same
        // revocation contract when their registered client is deleted.
        let mut service = payload.clone();
        service["clientId"] = "default".into();
        service["subject"] = "default".into();
        service["baseRevision"] = 0.into();
        service["sourceRevision"] = 1.into();
        service["enabled"] = true.into();
        service["claims"] = serde_json::json!({"roles":[],"organization_roles":[]});
        let response = app.clone().oneshot(request(service.clone(), &sid)?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let original = capture(&pool, env.environment_id, &issuer, "default", "default")
            .await?.ok_or_else(|| io::Error::other("service projection"))?;
        assert!(is_current(&pool, env.environment_id, &issuer, &original).await?);
        sqlx::query("UPDATE aegaeon.clients SET status='DELETED',deleted_at=now() WHERE environment_id=$1 AND client_identifier='default'")
            .bind(env.environment_id).execute(&pool).await?;
        // Deleted client identifiers are not unique. Audit targets must not select
        // an arbitrary historical client UUID, even when revoking a projection.
        sqlx::query("INSERT INTO aegaeon.clients (environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,status,deleted_at) VALUES ($1,$2,'default','historical service','PUBLIC',ARRAY['https://client.example/callback'],ARRAY['authorization_code'],ARRAY['openid'],'none','DELETED',now())")
            .bind(env.environment_id).bind(env.configuration_version_id).execute(&pool).await?;
        service["baseRevision"] = 1.into();
        service["sourceRevision"] = 2.into();
        service["enabled"] = false.into();
        let response = app.clone().oneshot(request(service, &sid)?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await?["revision"], 2);
        let audits: Vec<(String, String, String, String, serde_json::Value)> = sqlx::query_as("SELECT actor_type,actor_id,target_type,target_id,data FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.application_authorization.updated.v1' AND data->>'subject'='default' ORDER BY (data->>'toRevision')::bigint")
            .bind(env.environment_id).fetch_all(&pool).await?;
        assert_eq!(audits.len(), 2);
        for (i, (actor_type, actor_id, target_type, target_id, data)) in audits.iter().enumerate() {
            assert_eq!(actor_type, "ADMINISTRATOR");
            assert_eq!(actor_id, &env.administrator_id.to_string());
            assert_eq!(target_type, "APPLICATION_AUTHORIZATION");
            assert_eq!(serde_json::from_str::<serde_json::Value>(target_id)?, serde_json::json!([env.environment_id,"default","default"]));
            assert_eq!(data["enabled"], i == 0);
            assert_eq!(data["toRevision"], i + 1);
        }
        assert!(!is_current(&pool, env.environment_id, &issuer, &original).await?);
        Ok(())
    }.await;
    for table in ["application_authorizations", "end_users"] {
        sqlx::query(&format!("DELETE FROM aegaeon.{table} WHERE environment_id=$1"))
            .bind(env.environment_id).execute(&pool).await?;
    }
    finish_runtime_key_pg_test(result, cleanup_configuration_members(&pool, &env).await)
}
