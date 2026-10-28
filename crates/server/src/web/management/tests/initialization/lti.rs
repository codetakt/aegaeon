use super::*;
use serde_json::{json, Value};

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_lti_management_authority_staging_and_export_are_environment_bound(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let initialized=initialize_management(&pool,&input()).await?;
        let mut management=test_management_state();
        management.cfg=std::sync::Arc::new(super::super::super::ManagementConfig::try_from_env_with_database(&pool).await?);
        let app=crate::web::build_router(test_app_state(pool.clone(),management)?);
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
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
