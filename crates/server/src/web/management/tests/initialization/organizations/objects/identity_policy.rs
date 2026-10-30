use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_identity_policy_requires_owner_explicit_grant_and_environment_version(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult = async {
        let h=Harness::new(&pool).await?;
        let base=h.collection.strip_suffix("/organizations").ok_or("path")?;
        let path=format!("{base}/identity-policy");
        let (disabled,tag)=representation(h.app.clone().oneshot(h.read(&path)).await?,StatusCode::OK).await?;
        assert_eq!(disabled["id"],h.environment.to_string());assert!(disabled["policy"].is_null());
        let payload=json!({"policy":{"registration":true,"passwordRecovery":false,"subjectFormat":"uuid"},"reason":"Enable invited signup"});
        let mut no_csrf=mutation(&path,Method::PUT,payload.clone(),&h.cookie,"no-csrf",Some(&tag));
        no_csrf.headers_mut().remove("x-csrf-token");
        assert_eq!(h.app.clone().oneshot(no_csrf).await?.status(),StatusCode::FORBIDDEN);
        assert_eq!(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"no-version",None)).await?.status(),StatusCode::PRECONDITION_REQUIRED);
        let (_,domain_tag)=representation(h.app.clone().oneshot(h.read(base)).await?,StatusCode::OK).await?;
        assert_eq!(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"domain-tag",Some(&domain_tag))).await?.status(),StatusCode::PRECONDITION_FAILED);
        let enabled=representation(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"enable",Some(&tag))).await?,StatusCode::OK).await?;
        assert_eq!(enabled.0["revision"],2);
        assert_eq!(representation(h.app.clone().oneshot(mutation(&path,Method::PUT,payload,&h.cookie,"enable",Some(&tag))).await?,StatusCode::OK).await?,enabled);
        sqlx::query("UPDATE aegaeon.team_memberships SET role='ADMINISTRATOR' WHERE administrator_id=$1").bind(h.administrator).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(h.read(&path)).await?.status(),StatusCode::FORBIDDEN);
        sqlx::query("UPDATE aegaeon.team_memberships SET role='OWNER' WHERE administrator_id=$1").bind(h.administrator).execute(&pool).await?;
        let disabled=representation(h.app.clone().oneshot(mutation(&format!("{path}/disable"),Method::POST,json!({"reason":"Revoke enrollment"}),&h.cookie,"disable",Some(&enabled.1))).await?,StatusCode::OK).await?;
        assert_eq!(disabled.0["revision"],3);assert!(disabled.0["policy"].is_null());
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE domain_id=$1").bind(h.domain).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(h.read(&path)).await?.status(),StatusCode::FORBIDDEN);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
