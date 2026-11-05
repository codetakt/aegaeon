use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_clients_enforce_registration_authority_and_byte_bounded_pages(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let initialized=initialize_management(&pool,&input()).await?;
        let mut mgmt=test_management_state();
        mgmt.cfg=Arc::new(crate::web::management::ManagementConfig::try_from_env_with_database(&pool).await?);
        let app=crate::web::build_router(test_app_state(pool.clone(),mgmt)?);
        let login=app.clone().oneshot(request("/api/v1/authentication/sessions",json!({"email":input().owner_email,"password":input().owner_password}),"","https://admin.aegaeon.test",true)).await?;
        assert_eq!(login.status(),StatusCode::NO_CONTENT);
        let cookie=login.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()).find(|v| v.starts_with("aegaeon_admin_session=")).ok_or("session")?.split(';').next().ok_or("cookie")?.to_owned();
        let base=format!("/api/v1/teams/{}/environments/{}/organization-domains",initialized.team_id,initialized.environment_id);
        let (domain,tag)=representation(app.clone().oneshot(mutation(&format!("{base}/default"),Method::POST,json!({"reason":"initialize"}),&cookie,"bootstrap",None)).await?,StatusCode::OK).await?;
        let domain_id=domain["id"].as_str().ok_or("domain")?;
        let path=format!("{base}/{domain_id}");
        let (_,mut tag)=representation(app.clone().oneshot(mutation(&format!("{path}/targets"),Method::POST,json!({"audience":"urn:example:学校/É","management":false,"reason":"register target"}),&cookie,"target",Some(&tag))).await?,StatusCode::OK).await?;
        let clients=format!("{path}/clients");
        assert_eq!(app.clone().oneshot(mutation(&format!("{path}/enable"),Method::POST,json!({"reason":"premature"}),&cookie,"premature",Some(&tag))).await?.status(),StatusCode::FORBIDDEN);

        let mut retained=Vec::new();
        for i in 0..2 {
            let registration=Uuid::new_v4();
            sqlx::query("INSERT INTO aegaeon.clients(id,environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,dpop_bound_access_tokens) SELECT $1,id,active_configuration_version_id,$2,'org test','CONFIDENTIAL',ARRAY['https://example.test/cb'],ARRAY['authorization_code','urn:ietf:params:oauth:grant-type:token-exchange'],ARRAY['openid'],'client_secret_basic',true FROM aegaeon.environments WHERE id=$3")
                .bind(registration).bind(format!("client-{i}")).bind(initialized.environment_id).execute(&pool).await?;
            let privileges:Vec<_>=(0..256).map(|p|format!("p{}{:03}","x".repeat(124),p)).collect();
            let body=json!({"clientRegistrationId":registration,"active":true,"targets":[{"audience":"urn:example:学校/É","privileges":privileges}],"reason":"explicit client"});
            assert_eq!(app.clone().oneshot(mutation(&clients,Method::POST,body.clone(),&cookie,"missing-etag",None)).await?.status(),StatusCode::PRECONDITION_REQUIRED);
            assert_eq!(app.clone().oneshot(mutation(&clients,Method::POST,body.clone(),"","missing-session",Some(&tag))).await?.status(),StatusCode::UNAUTHORIZED);
            let key=format!("create-{i}");
            let (binding,binding_tag)=representation(app.clone().oneshot(mutation(&clients,Method::POST,body.clone(),&cookie,&key,Some(&tag))).await?,StatusCode::OK).await?;
            assert_eq!(binding["clientRegistrationId"],registration.to_string());
            assert_eq!(binding["active"],true);
            assert_eq!(representation(app.clone().oneshot(mutation(&clients,Method::POST,body.clone(),&cookie,&key,Some(&tag))).await?,StatusCode::OK).await?,(binding.clone(),binding_tag.clone()));
            retained.push((binding,binding_tag,body,key,tag));
            let read=Request::builder().uri(&path).header("cookie",&cookie).body(Body::empty())?;
            let (configuration,next)=representation(app.clone().oneshot(read).await?,StatusCode::OK).await?;
            assert_eq!(configuration["enabled"],false);
            tag=next;
        }
        let read=|uri:&str|Request::builder().uri(uri).header("cookie",&cookie).body(Body::empty()).unwrap();
        let response=app.clone().oneshot(read(&format!("{clients}?pageSize=50"))).await?;
        assert_eq!(response.status(),StatusCode::OK);
        assert_eq!(response.headers()["cache-control"],"no-store");
        let bytes=axum::body::to_bytes(response.into_body(),65536).await?;
        let page:Value=serde_json::from_slice(&bytes)?;
        assert_eq!(page["clients"].as_array().ok_or("clients")?.len(),1);
        let cursor=page["pageInfo"]["nextPageToken"].as_str().ok_or("cursor")?;
        let uri=format!("{clients}?pageToken={cursor}");
        let second=app.clone().oneshot(read(&uri)).await?;
        assert_eq!(second.status(),StatusCode::OK);
        let second:Value=serde_json::from_slice(&axum::body::to_bytes(second.into_body(),65536).await?)?;
        assert_eq!(second["clients"].as_array().ok_or("clients")?.len(),1);
        assert_ne!(page["clients"][0]["id"],second["clients"][0]["id"]);
        assert!(second["pageInfo"]["nextPageToken"].is_null());
        assert_eq!(app.clone().oneshot(read(&format!("{path}/operators?pageToken={cursor}"))).await?.status(),StatusCode::BAD_REQUEST);

        let (enabled,enabled_tag)=representation(app.clone().oneshot(mutation(&format!("{path}/enable"),Method::POST,json!({"reason":"activate configured domain"}),&cookie,"enable",Some(&tag))).await?,StatusCode::OK).await?;
        assert_eq!(enabled["enabled"],true);
        assert_ne!(enabled_tag,tag);
        let (binding,binding_tag,_,_,_)=&retained[0];
        let revoke_path=format!("{clients}/{}/revoke",binding["id"].as_str().ok_or("id")?);
        sqlx::query("DELETE FROM aegaeon.clients WHERE id=$1").bind(Uuid::parse_str(binding["clientRegistrationId"].as_str().ok_or("registration")?)?).execute(&pool).await?;

        let (disabled,disabled_tag)=representation(app.clone().oneshot(mutation(&format!("{path}/disable"),Method::POST,json!({"reason":"stop domain"}),&cookie,"disable",Some(&enabled_tag))).await?,StatusCode::OK).await?;
        assert_eq!(disabled["enabled"],false);
        assert_ne!(disabled_tag,enabled_tag);
        let (revoked,_)=representation(app.clone().oneshot(mutation(&revoke_path,Method::POST,json!({"reason":"withdraw"}),&cookie,"revoke",Some(binding_tag))).await?,StatusCode::OK).await?;
        assert_eq!(revoked["active"],false);
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE domain_id=$1").bind(Uuid::parse_str(domain_id)?).execute(&pool).await?;
        let (_,_,body,key,original_tag)=&retained[1];
        assert_eq!(app.clone().oneshot(mutation(&clients,Method::POST,body.clone(),&cookie,key,Some(original_tag))).await?.status(),StatusCode::FORBIDDEN);
        assert_eq!(app.oneshot(read(&uri)).await?.status(),StatusCode::FORBIDDEN);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
