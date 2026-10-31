use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_administrator_recovery_requires_owner_and_current_scope(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let mut witness = None;
    let result:ManagementTestResult=async {
        let mut h=Harness::new(&pool).await?;
        let supplier = Arc::new(crate::organizations::witness::tests::caller_fixture::CallerFixture::new(h.environment).await?);
        h.app = supplier.router(h.app, |_| crate::organizations::request_work::CapacityClass::Ordinary);
        witness = Some(supplier);
        invitations::role(&pool,&h).await?;
        let (created,_)=representation(h.app.clone().oneshot(h.create("recovery/学校","org")).await?,StatusCode::OK).await?;
        let id=Uuid::parse_str(created["id"].as_str().ok_or("id")?)?;
        let user=Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')").bind(user).bind(h.environment).bind(user.to_string()).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,roles) VALUES($1,$2,$3,$4,$5,'active','[\"first-admin\"]')")
            .bind(h.environment).bind(h.domain).bind(id).bind(user).bind(Uuid::new_v4()).execute(&pool).await?;
        sqlx::query("UPDATE aegaeon.application_organizations SET state='active',revision=2,grant_generation=2 WHERE id=$1").bind(id).execute(&pool).await?;
        let path=format!("{}/{id}/administrator-recovery",h.collection);
        let tag=format!("\"{id}.2\"");let payload=json!({"reason":"Recover missing administrator"});
        let request=|key:&str|mutation(&path,Method::POST,payload.clone(),&h.cookie,key,Some(&tag));
        assert_eq!(h.app.clone().oneshot(request("active-admin")).await?.status(),StatusCode::FORBIDDEN);
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE id=$1").bind(user).execute(&pool).await?;
        let mut no_csrf=request("no-csrf");no_csrf.headers_mut().remove("x-csrf-token");
        assert_eq!(h.app.clone().oneshot(no_csrf).await?.status(),StatusCode::FORBIDDEN);
        assert_eq!(h.app.clone().oneshot(mutation(&path,Method::POST,payload.clone(),&h.cookie,"no-version",None)).await?.status(),StatusCode::PRECONDITION_REQUIRED);
        let foreign=path.replace(&h.domain.to_string(),&Uuid::new_v4().to_string());
        assert_eq!(h.app.clone().oneshot(mutation(&foreign,Method::POST,payload.clone(),&h.cookie,"foreign",Some(&tag))).await?.status(),StatusCode::FORBIDDEN);
        sqlx::query("UPDATE aegaeon.team_memberships SET role='ADMINISTRATOR' WHERE administrator_id=$1").bind(h.administrator).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(request("not-owner")).await?.status(),StatusCode::FORBIDDEN);
        sqlx::query("UPDATE aegaeon.team_memberships SET role='OWNER' WHERE administrator_id=$1").bind(h.administrator).execute(&pool).await?;
        let revocation_reserve=crate::organizations::request_work::Admission::try_acquire_revocation()?;
        let (one,two)=tokio::join!(h.app.clone().oneshot(request("recover")),h.app.clone().oneshot(request("recover")));
        drop(revocation_reserve);
        let recovered=representation(one?,StatusCode::OK).await?;assert_eq!(representation(two?,StatusCode::OK).await?,recovered);
        assert_eq!(recovered.0["state"],"provisioning");assert_eq!(recovered.0["revision"],3);assert_eq!(recovered.0["externalId"],"recovery/学校");
        let invite=format!("{}/{id}/invitations",h.collection);
        assert_eq!(h.app.clone().oneshot(mutation(&invite,Method::POST,json!({"recipient":"Replacement@example.test","roles":["first-admin"],"reason":"Replacement administrator"}),&h.cookie,"replacement",Some(&recovered.1))).await?.status(),StatusCode::OK);
        let events:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.administrator_recovery_prepared'").bind(id).fetch_one(&pool).await?;assert_eq!(events,1);
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE domain_id=$1").bind(h.domain).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(request("recover")).await?.status(),StatusCode::FORBIDDEN,"replay rechecks current grant");
        Ok(())
    }.await;
    let witness_cleanup = match witness {
        Some(witness) => Arc::try_unwrap(witness)
            .map_err(|_| "retained witness")?
            .finish()
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() }),
        None => Ok(()),
    };
    finish(
        result.and(witness_cleanup),
        cleanup(control, pool, &name).await,
    )
}
