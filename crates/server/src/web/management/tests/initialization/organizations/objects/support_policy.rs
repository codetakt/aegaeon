use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_support_policy_requires_explicit_owner_csrf_and_current_provider(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let h=Harness::new(&pool).await?;
        let base=h.collection.strip_suffix("/organizations").ok_or("path")?;
        let path=format!("{base}/support-policy");
        let (disabled,tag)=representation(h.app.clone().oneshot(h.read(&path)).await?,StatusCode::OK).await?;
        assert_eq!(disabled["id"],h.domain.to_string());assert!(disabled["policy"].is_null());
        let organization=Uuid::new_v4();let user=Uuid::new_v4();let connection=Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state) VALUES($1,$2,$3,'support/API/学校','active')").bind(organization).bind(h.environment).bind(h.domain).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')").bind(user).bind(h.environment).bind(format!("support-{user}")).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.organization_role_definitions(environment_id,domain_id,role_key,privileges) VALUES($1,$2,'reader','[\"read\"]')").bind(h.environment).bind(h.domain).execute(&pool).await?;
        let configuration:Uuid=sqlx::query_scalar("SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1").bind(h.environment).fetch_one(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.connections(id,environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_auth_method) VALUES($1,$2,$3,'support','support','https://provider.example','client','none')").bind(connection).bind(h.environment).bind(configuration).execute(&pool).await?;
        let payload=json!({"reason":"Reviewed provider assurance and operator correspondence","policy":{"providers":[{"connectionId":connection,"configurationVersionId":configuration,"issuer":"https://provider.example","upstreamClientId":"client","acr":"urn:example:two-factors","factors":[{"method":"pwd","class":"knowledge"},{"method":"otp","class":"possession"}]}],"entitlements":[{"administratorId":h.administrator,"userId":user,"organizationId":organization,"audience":"urn:example:provisioning","roles":["reader"]}]}});
        let mut no_csrf=mutation(&path,Method::PUT,payload.clone(),&h.cookie,"no-csrf",Some(&tag));no_csrf.headers_mut().remove("x-csrf-token");
        assert_eq!(h.app.clone().oneshot(no_csrf).await?.status(),StatusCode::FORBIDDEN);
        assert_eq!(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"no-version",None)).await?.status(),StatusCode::PRECONDITION_REQUIRED);
        assert_eq!(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"no-support",Some(&tag))).await?.status(),StatusCode::FORBIDDEN);
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"configure\",\"provision\",\"support\"]',revision=revision+1 WHERE domain_id=$1 AND administrator_id=$2").bind(h.domain).bind(h.administrator).execute(&pool).await?;
        let untyped_tag=format!("\"{}.1\"",h.domain);
        assert_eq!(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"wrong-representation",Some(&untyped_tag))).await?.status(),StatusCode::BAD_REQUEST,"a domain-shaped ETag is not a support-policy version");
        let enabled=representation(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"enable",Some(&tag))).await?,StatusCode::OK).await?;
        assert_eq!(enabled.0["revision"],2);
        assert_eq!(representation(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"enable",Some(&tag))).await?,StatusCode::OK).await?,enabled);
        let mut changed=payload.clone();changed["reason"]=json!("different");
        assert_eq!(h.app.clone().oneshot(mutation(&path,Method::PUT,changed,&h.cookie,"enable",Some(&tag))).await?.status(),StatusCode::CONFLICT);
        sqlx::query("UPDATE aegaeon.team_memberships SET role='ADMINISTRATOR' WHERE administrator_id=$1").bind(h.administrator).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(h.read(&path)).await?.status(),StatusCode::FORBIDDEN);
        sqlx::query("UPDATE aegaeon.team_memberships SET role='OWNER' WHERE administrator_id=$1").bind(h.administrator).execute(&pool).await?;
        sqlx::query("UPDATE aegaeon.connections SET status='DISABLED' WHERE id=$1").bind(connection).execute(&pool).await?;
        let disabled=representation(h.app.clone().oneshot(mutation(&format!("{path}/disable"),Method::POST,json!({"reason":"Revoke support immediately"}),&h.cookie,"disable",Some(&enabled.1))).await?,StatusCode::OK).await?;
        assert_eq!(disabled.0["revision"],3);assert!(disabled.0["policy"].is_null());
        assert_ne!(h.app.clone().oneshot(mutation(&path,Method::PUT,payload,&h.cookie,"bad-provider",Some(&disabled.1))).await?.status(),StatusCode::OK);
        let foreign=path.replace(&h.domain.to_string(),&Uuid::new_v4().to_string());
        assert_eq!(h.app.clone().oneshot(h.read(&foreign)).await?.status(),StatusCode::FORBIDDEN);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
