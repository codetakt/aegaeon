use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_delivery_configuration_defaults_and_current_replay(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let h=Harness::new(&pool).await?;
        let base=h.collection.strip_suffix("/organizations").ok_or("base")?;
        let path=format!("{base}/invitation-delivery");
        let (initial,tag)=representation(h.app.clone().oneshot(h.read(&path)).await?,StatusCode::OK).await?;
        assert!(initial["channel"].is_null());
        let payload=json!({"channel":{"endpoint":"https://delivery.example.test/envelopes","credentialSha256":"a".repeat(64)},"reason":"Configure delivery"});
        assert_eq!(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"mail",None)).await?.status(),StatusCode::PRECONDITION_REQUIRED);
        let mut request=mutation(&path,Method::PUT,payload.clone(),&h.cookie,"mail",Some(&tag));request.headers_mut().remove("x-csrf-token");
        assert_eq!(h.app.clone().oneshot(request).await?.status(),StatusCode::FORBIDDEN);
        let (configured,new_tag)=representation(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"mail",Some(&tag))).await?,StatusCode::OK).await?;
        assert_eq!(configured["channel"],payload["channel"]);
        assert_eq!(representation(h.app.clone().oneshot(mutation(&path,Method::PUT,payload.clone(),&h.cookie,"mail",Some(&tag))).await?,StatusCode::OK).await?.0,configured);
        assert_eq!(h.app.clone().oneshot(mutation(&path,Method::PUT,payload,&h.cookie,"stale",Some(&tag))).await?.status(),StatusCode::PRECONDITION_FAILED);
        let invalid=json!({"channel":{"endpoint":"http://127.0.0.1/secret","credentialSha256":"a".repeat(64)},"reason":"Invalid"});
        assert_eq!(h.app.clone().oneshot(mutation(&path,Method::PUT,invalid,&h.cookie,"invalid",Some(&new_tag))).await?.status(),StatusCode::BAD_REQUEST);
        let disable=format!("{path}/disable");
        let (disabled,_)=representation(h.app.clone().oneshot(mutation(&disable,Method::POST,json!({"reason":"Stop delivery"}),&h.cookie,"stop",Some(&new_tag))).await?,StatusCode::OK).await?;
        assert!(disabled["channel"].is_null());
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE domain_id=$1").bind(h.domain).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(h.read(&path)).await?.status(),StatusCode::FORBIDDEN);
        assert_eq!(h.app.clone().oneshot(mutation(&disable,Method::POST,json!({"reason":"Stop delivery"}),&h.cookie,"stop",Some(&new_tag))).await?.status(),StatusCode::FORBIDDEN);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
