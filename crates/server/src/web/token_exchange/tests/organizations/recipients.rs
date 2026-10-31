use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_recipient_reregistration_cannot_inherit_old_visibility(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = fixture::state(&f).await?;
    let result = f.in_epoch(Box::pin(async {
        let key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let parent=fixture::parent(&f,&state,&key).await?;
        let source=parent["access_token"].as_str().ok_or("source")?;
        let (status,body)=select(&state,source,&key,IDENTIFIER).await?;
        assert_eq!(status,StatusCode::OK,"{body}");
        let token=body["access_token"].as_str().ok_or("selected")?;
        inspect(&state,token,RS,true).await?;
        let old:uuid::Uuid=sqlx::query_scalar("SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2").bind(state.environment_id).bind(RS).fetch_one(&f.pool).await?;
        sqlx::query("UPDATE aegaeon.clients SET status='DELETED',deleted_at=statement_timestamp() WHERE id=$1").bind(old).execute(&f.pool).await?;
        let new=uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.clients(id,environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method) SELECT $1,id,active_configuration_version_id,$2,'replacement resource server','CONFIDENTIAL',ARRAY['https://example.test/cb'],ARRAY['authorization_code'],ARRAY['openid'],'client_secret_basic' FROM aegaeon.environments WHERE id=$3")
            .bind(new).bind(RS).bind(state.environment_id).execute(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.client_secrets(environment_id,client_id,configuration_version_id,secret_hash,active_slot,expires_at) SELECT environment_id,id,configuration_version_id,$1,1,statement_timestamp()+interval '1 hour' FROM aegaeon.clients WHERE id=$2")
            .bind(crate::local_credentials::hash_password(SECRET)?).bind(new).execute(&f.pool).await?;
        state.runtime_authority.try_synchronize_client_projection_from_database(&state.db_pool,state.clients.as_ref()).await?;
        inspect(&state,token,RS,false).await?;
        // Explicit reconfiguration is a new domain revision. It does not revive
        // tokens or original approvals captured before the recipient change.
        let mut tx=f.pool.begin().await?;
        crate::organizations::repository::lock_domain(&mut tx,f.organization.scope).await?;
        sqlx::query("UPDATE aegaeon.authorization_domain_targets SET introspection_clients=$1 WHERE environment_id=$2")
            .bind(json!([{"clientRegistrationId":new,"clientIdentifier":RS}])).bind(state.environment_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE aegaeon.authorization_domains SET revision=revision+1 WHERE id=$1").bind(f.organization.scope.domain_id).execute(&mut *tx).await?;
        tx.commit().await?;
        inspect(&state,token,RS,false).await?;
        assert_eq!(select(&state,source,&key,IDENTIFIER).await?.0,StatusCode::BAD_REQUEST);
        let new_parent=fixture::parent(&f,&state,&key).await?;
        let (status,new_token)=select(&state,new_parent["access_token"].as_str().ok_or("new parent")?,&key,IDENTIFIER).await?;
        assert_eq!(status,StatusCode::OK,"fresh approval: {new_token}");
        inspect(&state,new_token["access_token"].as_str().ok_or("new token")?,RS,true).await?;
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
