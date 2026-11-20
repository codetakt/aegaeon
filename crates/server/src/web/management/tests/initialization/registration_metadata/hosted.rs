use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB and a current human management session"]
async fn pg_management_hosted_client_creation_requires_domain_configure_and_exact_profile(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result = async {
        let init = initialize_management(&pool, &input()).await?;
        let env = TestEnvironment { team_id:init.team_id, tenant_id:init.tenant_id, environment_id:init.environment_id,
            issuer_url:format!("https://{}",init.issuer_host), issuer_host:init.issuer_host };
        let domain=Uuid::new_v4();
        let grants=vec!["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:token-exchange"];
        let scopes=vec!["openid","read","offline_access","organization.invitation.accept"];
        sqlx::query("INSERT INTO aegaeon.authorization_domains(id,environment_id,name,is_default,enabled) VALUES($1,$2,'hosted',true,true)")
            .bind(domain).bind(env.environment_id).execute(&pool).await?;
        sqlx::query("UPDATE aegaeon.environment_policies SET allowed_grant_types=$2 WHERE environment_id=$1")
            .bind(env.environment_id).bind(&grants).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.environment_scope_allowlist(environment_id,configuration_version_id,scope) SELECT $1,$2,unnest($3::text[]) ON CONFLICT DO NOTHING")
            .bind(env.environment_id).bind(init.configuration_version_id).bind(&scopes).execute(&pool).await?;
        sqlx::query("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,allowed_grant_types,token_endpoint_auth_methods_allowed,sender_constrained) VALUES($1,$2,'hosted','DOWNSTREAM',true,$3,ARRAY['client_secret_basic'],'NONE')")
            .bind(env.environment_id).bind(init.configuration_version_id).bind(&grants).execute(&pool).await?;
        let (app,cookie)=login(&pool,&env).await?;
        let url=format!("/api/v1/teams/{}/environments/{}/clients",env.team_id,env.environment_id);
        let request_body=json!({"baseConfigurationVersionId":init.configuration_version_id,"name":"Invitation acceptance",
            "hostedInvitationDomainId":domain,"clientType":"CONFIDENTIAL","dpopBoundAccessTokens":true,
            "redirectUris":[format!("{}/organization-invitations/hosted/callback",env.issuer_url)],
            "allowedGrantTypes":grants,"allowedScopes":scopes,"tokenEndpointAuthenticationMethod":"client_secret_basic"});
        let submit=|value| app.clone().oneshot(request(&url,value,&cookie,"https://admin.aegaeon.test",true));
        assert_eq!(submit(request_body.clone()).await?.status(),StatusCode::FORBIDDEN);
        sqlx::query("INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,active,capabilities) SELECT gen_random_uuid(),$1,$2,administrator_id,true,'[\"configure\"]'::jsonb FROM aegaeon.team_memberships WHERE team_id=$3 AND role='OWNER'")
            .bind(env.environment_id).bind(domain).bind(env.team_id).execute(&pool).await?;
        let mut foreign=request_body.clone();
        foreign["redirectUris"]=json!(["https://client.example.test/callback"]);
        assert_eq!(submit(foreign).await?.status(),StatusCode::BAD_REQUEST);
        let response=submit(request_body).await?;
        let status=response.status();
        let body:Value=serde_json::from_slice(&body::to_bytes(response.into_body(),65536).await?)?;
        assert_eq!(status,StatusCode::CREATED,"{body}");
        assert_eq!(body["client"]["clientIdentifier"],format!("aegaeon-hosted-invitation-{domain}"));
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
