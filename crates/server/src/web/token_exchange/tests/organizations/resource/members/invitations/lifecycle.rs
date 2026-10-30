use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_delegated_invitation_refuses_existing_memberships() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured(&f).await?;
    let result=async {
        let key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let (_,token)=issue(&f,&state,&key,MANAGE).await?;
        let client=MemberClient {state:&state,key:&key,read:token.clone(),write:token.clone(),list:String::new()};
        let path=format!("/organizations/{}/invitations",f.organization.id);
        let tag=VersionTag::new(f.organization.id,f.organization.revision).map_err(|_|"version")?.header_value();
        let mail=Mail::new(204,vec![],Duration::ZERO,false)?;
        for (index,status) in ["active","suspended","removed"].into_iter().enumerate() {
            let user=Uuid::new_v4();let incarnation=Uuid::new_v4();
            sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,status) VALUES($1,$2,$3,'ACTIVE')").bind(user).bind(state.environment_id).bind(user.to_string()).execute(&f.pool).await?;
            sqlx::query("INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,roles) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(state.environment_id).bind(f.organization.scope.domain_id).bind(f.organization.id).bind(user).bind(incarnation).bind(status).bind(if status=="removed" {json!([])} else {json!(["reader"])}).execute(&f.pool).await?;
            let created=client.request(Method::POST,&path,&token,Some(&tag),Some(status),r#"{"recipient":"Member@example.test","roles":["reader"],"reason":"check existing membership"}"#).await?;
            assert_eq!(created.0,StatusCode::OK,"{}",created.1);
            let id=Uuid::parse_str(created.1["id"].as_str().ok_or("id")?)?;
            let send=crate::web::OrganizationDeliveryRequest { identity_request_id: None,domain_id:f.organization.scope.domain_id,invitation_id:id,challenge_id:None,credential:credential()};
            assert_eq!(state.deliver_organization_invitation(send).await?.outcome,"acknowledged");
            let capability=mail.received.lock().unwrap()[index]["capability"].clone();
            let recipient_key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
            let recipient=recipient_token(&state,user,&recipient_key).await?;
            let consumer=MemberClient {state:&state,key:&recipient_key,read:recipient.clone(),write:recipient.clone(),list:String::new()};
            let challenge_path=format!("/organization-invitations/{}/{id}/challenges",f.organization.scope.domain_id);
            let response=consumer.request(Method::POST,&challenge_path,&recipient,None,Some(status),&json!({"invitationCapability":capability}).to_string()).await?;
            assert_eq!(response.0,StatusCode::FORBIDDEN,"{status}: {}",response.1);
            let retained:(String,Uuid,i64)=sqlx::query_as("SELECT state,incarnation,revision FROM aegaeon.organization_memberships WHERE organization_id=$1 AND end_user_id=$2").bind(f.organization.id).bind(user).fetch_one(&f.pool).await?;
            assert_eq!(retained,(status.into(),incarnation,1));
            let challenges:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_invitation_challenges WHERE invitation_id=$1").bind(id).fetch_one(&f.pool).await?;assert_eq!(challenges,0);
        }
        crate::organizations::repository_tests::import::validate_fixture_source(&f).await?;
        drop(mail);Ok(())
    }.await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
