use super::*;

pub(super) async fn role(pool: &sqlx::PgPool, h: &Harness) -> ManagementTestResult {
    sqlx::query("INSERT INTO aegaeon.organization_role_definitions(environment_id,domain_id,role_key,privileges,manages_members,assignable_roles) VALUES($1,$2,'first-admin','[\"organization.members.manage\"]',true,'[\"first-admin\"]')")
        .bind(h.environment).bind(h.domain).execute(pool).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_invitation_issue_read_and_cancel_recheck_current_authority(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let h=Harness::new(&pool).await?;
        role(&pool,&h).await?;
        let (org,tag)=representation(h.app.clone().oneshot(h.create("Invitation/学校","org")).await?,StatusCode::OK).await?;
        let id=org["id"].as_str().ok_or("id")?;
        let collection=format!("{}/{id}/invitations",h.collection);
        let payload=json!({"recipient":"First.Admin@EXAMPLE.test","roles":["first-admin"],"reason":"Initial administrator"});
        assert_eq!(h.app.clone().oneshot(mutation(&collection,Method::POST,payload.clone(),&h.cookie,"invite",None)).await?.status(),StatusCode::PRECONDITION_REQUIRED);
        let (invite,invite_tag)=representation(h.app.clone().oneshot(mutation(&collection,Method::POST,payload.clone(),&h.cookie,"invite",Some(&tag))).await?,StatusCode::OK).await?;
        assert_eq!(invite["state"],"pending");
        assert_eq!(invite["organizationId"],id);
        assert_eq!(invite.as_object().ok_or("object")?.len(),6);
        let invitation=invite["id"].as_str().ok_or("invite id")?;
        Uuid::parse_str(invitation)?;
        let base=h.collection.strip_suffix("/organizations").ok_or("path")?;
        let item=format!("{base}/invitations/{invitation}");
        assert_eq!(representation(h.app.clone().oneshot(h.read(&item)).await?,StatusCode::OK).await?,(invite.clone(),invite_tag.clone()));
        let mut head=h.read(&item);*head.method_mut()=Method::HEAD;
        let response=h.app.clone().oneshot(head).await?;
        assert_eq!(response.status(),StatusCode::OK);
        assert!(body::to_bytes(response.into_body(),1).await?.is_empty());
        // A scanner GET does not create membership or consume the invitation.
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_memberships WHERE organization_id=$1")
            .bind(Uuid::parse_str(id)?).fetch_one(&pool).await?;
        assert_eq!(count,0);
        assert_eq!(representation(h.app.clone().oneshot(mutation(&collection,Method::POST,payload,&h.cookie,"invite",Some(&tag))).await?,StatusCode::OK).await?,(invite,invite_tag.clone()));
        let cancel=format!("{item}/revoke");
        let cancellation=json!({"reason":"Withdraw invitation"});
        let (revoked,_)=representation(h.app.clone().oneshot(mutation(&cancel,Method::POST,cancellation.clone(),&h.cookie,"cancel",Some(&invite_tag))).await?,StatusCode::OK).await?;
        assert_eq!(revoked["state"],"revoked");
        assert_eq!(representation(h.app.clone().oneshot(mutation(&cancel,Method::POST,cancellation,&h.cookie,"cancel",Some(&invite_tag))).await?,StatusCode::OK).await?.0,revoked);
        assert_eq!(h.app.clone().oneshot(mutation(&cancel,Method::POST,json!({"reason":"Changed reason"}),&h.cookie,"cancel",Some(&invite_tag))).await?.status(),StatusCode::CONFLICT);
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false WHERE domain_id=$1").bind(h.domain).execute(&pool).await?;
        assert_eq!(h.app.clone().oneshot(h.read(&item)).await?.status(),StatusCode::FORBIDDEN);
        assert_eq!(h.app.clone().oneshot(mutation(&cancel,Method::POST,json!({"reason":"Withdraw invitation"}),&h.cookie,"cancel",Some(&invite_tag))).await?.status(),StatusCode::FORBIDDEN);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and CREATEDB fixture"]
async fn pg_organizations_http_invitation_refuses_ambiguous_input_and_foreign_scope(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result:ManagementTestResult=async {
        let h=Harness::new(&pool).await?;
        role(&pool,&h).await?;
        let (org,tag)=representation(h.app.clone().oneshot(h.create("invite-boundary","org")).await?,StatusCode::OK).await?;
        let collection=format!("{}/{}/invitations",h.collection,org["id"].as_str().ok_or("id")?);
        let valid=json!({"recipient":"User@example.test","roles":["first-admin"],"reason":"Create"});
        for payload in [json!({"recipient":"User@example.test","roles":["first-admin","first-admin"],"reason":"Create"}),
            json!({"recipient":"User@example.test","roles":["first-admin"],"lifetimeSeconds":86401,"reason":"Create"}),
            json!({"recipient":"User@example.test","roles":["first-admin"],"reason":"Create","accepted":true})] {
            assert_eq!(h.app.clone().oneshot(mutation(&collection,Method::POST,payload,&h.cookie,"invalid",Some(&tag))).await?.status(),StatusCode::BAD_REQUEST);
        }
        let mut request=mutation(&collection,Method::POST,valid.clone(),&h.cookie,"no-csrf",Some(&tag));
        request.headers_mut().remove("x-csrf-token");
        assert_eq!(h.app.clone().oneshot(request).await?.status(),StatusCode::FORBIDDEN);
        let (invite,_)=representation(h.app.clone().oneshot(mutation(&collection,Method::POST,valid,&h.cookie,"valid",Some(&tag))).await?,StatusCode::OK).await?;
        let foreign=format!("{}/invitations/{}",h.collection.strip_suffix("/organizations").ok_or("base")?,invite["id"].as_str().ok_or("invitation")?).replace(&h.domain.to_string(),&Uuid::new_v4().to_string());
        assert_eq!(h.app.clone().oneshot(h.read(&foreign)).await?.status(),StatusCode::FORBIDDEN);
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_invitations WHERE domain_id=$1").bind(h.domain).fetch_one(&pool).await?;
        assert_eq!(count,1);
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
