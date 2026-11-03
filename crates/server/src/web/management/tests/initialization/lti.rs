use super::database_with_management as database;
use super::*;
use serde_json::{json, Value};

mod read_locks;
mod revision_repair;

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_lti_management_authority_staging_and_export_are_environment_bound(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let initialized=initialize_management(&pool,&input()).await?;
        let mut management=test_management_state();
        management.cfg=std::sync::Arc::new(super::super::super::ManagementConfig::try_from_env_with_database(&pool).await?);
        let state=test_app_state(pool.clone(),management)?;
        let app=crate::web::build_router(state.clone());
        let login=app.clone().oneshot(request("/api/v1/authentication/sessions",json!({"email":input().owner_email,"password":input().owner_password}),"","https://admin.aegaeon.test",true)).await?;
        assert_eq!(login.status(),StatusCode::NO_CONTENT);
        let session=login.headers().get_all("set-cookie").iter().filter_map(|h|h.to_str().ok()).find(|h|h.starts_with("aegaeon_admin_session=")).and_then(|h|h.split(';').next()).ok_or("admin session")?.to_string();
        sqlx::query("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,status) SELECT id,active_configuration_version_id,'tool','Example Tool','PUBLIC',ARRAY['https://tool.example/launch'],ARRAY['authorization_code'],ARRAY['openid'],'none','ACTIVE' FROM aegaeon.environments WHERE id=$1")
            .bind(initialized.environment_id).execute(&pool).await?;
        let client:String=sqlx::query_scalar("SELECT client_identifier FROM aegaeon.clients WHERE environment_id=$1 AND status='ACTIVE' LIMIT 1").bind(initialized.environment_id).fetch_one(&pool).await?;
        let uri=format!("/api/v1/teams/{}/environments/{}/lti/registrations",initialized.team_id,initialized.environment_id);
        let config=json!({"schemaVersion":1,"name":"Example Tool","status":"active","initiateLoginUri":"https://tool.example/login","redirectUris":["https://tool.example/launch"],"deployments":[]});
        let payload=json!({"clientId":client,"baseRevision":0,"configuration":config});
        for (cookie,origin,csrf,expected) in [("","https://admin.aegaeon.test",true,StatusCode::UNAUTHORIZED),(session.as_str(),"https://untrusted.example",true,StatusCode::FORBIDDEN),(session.as_str(),"https://admin.aegaeon.test",false,StatusCode::FORBIDDEN)] {
            let mut req=request(&uri,payload.clone(),cookie,origin,csrf);*req.method_mut()=Method::PUT;
            assert_eq!(app.clone().oneshot(req).await?.status(),expected);
        }
        let mut req=request(&uri,payload.clone(),&session,"https://admin.aegaeon.test",true);*req.method_mut()=Method::PUT;
        let response=app.clone().oneshot(req).await?;let status=response.status();let bytes=body::to_bytes(response.into_body(),262144).await?;
        assert_eq!(status,StatusCode::OK,"{}",String::from_utf8_lossy(&bytes));
        let saved:Value=serde_json::from_slice(&bytes)?;assert_eq!(saved["revision"],1);assert_eq!(saved["activeRevision"],Value::Null);
        let mut req=request(&uri,payload,&session,"https://admin.aegaeon.test",true);*req.method_mut()=Method::PUT;
        assert_eq!(app.clone().oneshot(req).await?.status(),StatusCode::CONFLICT);
        let mut missing = state.clone();
        missing.management.database = None;
        let denied = crate::web::build_router(missing).oneshot(request(&format!("{uri}/activate"),json!({"clientId":client,"revision":1}),&session,"https://admin.aegaeon.test",true)).await?;
        assert_eq!(denied.status(),StatusCode::SERVICE_UNAVAILABLE);
        let mut closed = state.clone();
        let closed_pool = sqlx::postgres::PgPoolOptions::new().connect_lazy_with(pool.connect_options().as_ref().clone());
        closed_pool.close().await;
        closed.management.database = Some(closed_pool);
        let denied = crate::web::build_router(closed).oneshot(request(&format!("{uri}/activate"),json!({"clientId":client,"revision":1}),&session,"https://admin.aegaeon.test",true)).await?;
        assert_eq!(denied.status(),StatusCode::SERVICE_UNAVAILABLE, "closed explicit management pool cannot fall back to runtime");
        let writer_name:String=sqlx::query_scalar("SELECT current_user::text").fetch_one(&pool).await?;
        let writer_id=format!("\"{}\"",writer_name.replace('"',"\"\""));
        let admin=crate::web::test_support::test_admin_pool(&pool).await?;
        sqlx::raw_sql(&format!("GRANT SET ON PARAMETER session_replication_role TO {writer_id}")).execute(&admin).await?;
        let denied=app.clone().oneshot(request(&format!("{uri}/activate"),json!({"clientId":client,"revision":1}),&session,"https://admin.aegaeon.test",true)).await;
        sqlx::raw_sql(&format!("REVOKE SET ON PARAMETER session_replication_role FROM {writer_id}")).execute(&admin).await?;
        let administrative_role=format!("lti_admin_activation_{}",uuid::Uuid::new_v4().simple());
        sqlx::raw_sql(&format!("CREATE ROLE {administrative_role} NOLOGIN; GRANT {administrative_role} TO {writer_id} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")).execute(&admin).await?;
        let administrative_denial=app.clone().oneshot(request(&format!("{uri}/activate"),json!({"clientId":client,"revision":1}),&session,"https://admin.aegaeon.test",true)).await;
        sqlx::raw_sql(&format!("REVOKE {administrative_role} FROM {writer_id}; DROP ROLE {administrative_role}")).execute(&admin).await?;
        let original_owner:String=sqlx::query_scalar("SELECT quote_ident(pg_get_userbyid(proowner)) FROM pg_proc WHERE oid='aegaeon.lti_immutable_record()'::regprocedure").fetch_one(&admin).await?;
        sqlx::raw_sql(&format!("ALTER FUNCTION aegaeon.lti_immutable_record() OWNER TO {writer_id}")).execute(&admin).await?;
        let owner_denial=app.clone().oneshot(request(&format!("{uri}/activate"),json!({"clientId":client,"revision":1}),&session,"https://admin.aegaeon.test",true)).await;
        sqlx::raw_sql(&format!("ALTER FUNCTION aegaeon.lti_immutable_record() OWNER TO {original_owner}")).execute(&admin).await?;
        sqlx::raw_sql(&format!("GRANT pg_execute_server_program TO {writer_id} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE")).execute(&admin).await?;
        let host_denial=app.clone().oneshot(request(&format!("{uri}/activate"),json!({"clientId":client,"revision":1}),&session,"https://admin.aegaeon.test",true)).await;
        sqlx::raw_sql(&format!("REVOKE pg_execute_server_program FROM {writer_id}")).execute(&admin).await?;
        admin.close().await;
        assert_eq!(denied?.status(),StatusCode::SERVICE_UNAVAILABLE,"activation must reject a writer that can disable identity guards");
        assert_eq!(administrative_denial?.status(),StatusCode::SERVICE_UNAVAILABLE,"activation must reject ADMIN-only role membership");
        assert_eq!(owner_denial?.status(),StatusCode::SERVICE_UNAVAILABLE,"activation must reject protected trigger ownership");
        assert_eq!(host_denial?.status(),StatusCode::SERVICE_UNAVAILABLE,"activation must reject host program authority");
        let response=app.clone().oneshot(request(&format!("{uri}/activate"),json!({"clientId":client,"revision":1}),&session,"https://admin.aegaeon.test",true)).await?;
        assert_eq!(response.status(),StatusCode::OK);
        let mut req=request(&format!("{uri}?clientId={client}"),Value::Null,&session,"https://admin.aegaeon.test",true);*req.method_mut()=Method::GET;
        let response=app.clone().oneshot(req).await?;assert_eq!(response.status(),StatusCode::OK);
        let exported:Value=serde_json::from_slice(&body::to_bytes(response.into_body(),262144).await?)?;
        let issuer:String=sqlx::query_scalar("SELECT issuer_url FROM aegaeon.environments WHERE id=$1").bind(initialized.environment_id).fetch_one(&pool).await?;
        assert_eq!(exported["platform"]["issuer"],issuer);
        assert_eq!(exported["platform"]["authorizationEndpoint"],format!("{issuer}/lti/authorize"));
        assert_eq!(exported["registration"]["activeRevision"],1);
        let events:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type LIKE 'management.lti.%'").bind(initialized.environment_id).fetch_one(&pool).await?;assert_eq!(events,2);
        read_locks::Probe { app, pool:pool.clone(), path:format!("{uri}?clientId={client}"), session, team:initialized.team_id, environment:initialized.environment_id }.verify().await?;
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
