use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; management DPoP field CRUD, authority and audit"]
async fn pg_management_client_dpop_minimum_preserves_and_audits_explicit_boolean(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result=async {
        let init=initialize_management(&pool,&input()).await?;
        let env=TestEnvironment { team_id:init.team_id,tenant_id:init.tenant_id,environment_id:init.environment_id,issuer_url:format!("https://{}",init.issuer_host),issuer_host:init.issuer_host };
        sqlx::query("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,allowed_grant_types,token_endpoint_auth_methods_allowed,sender_constrained) VALUES($1,$2,'minimum-test','DOWNSTREAM',true,ARRAY['authorization_code'],ARRAY['none'],'NONE')").bind(env.environment_id).bind(init.configuration_version_id).execute(&pool).await?;
        let (app,cookie)=login(&pool,&env).await?;
        let collection=format!("/api/v1/teams/{}/environments/{}/clients",env.team_id,env.environment_id);
        for choice in [None,Some(false),Some(true)] {
            let mut payload=json!({"baseConfigurationVersionId":init.configuration_version_id,"name":"minimum","clientType":"PUBLIC","redirectUris":["https://client.example/callback"],"allowedGrantTypes":["authorization_code"],"allowedScopes":[],"tokenEndpointAuthenticationMethod":"none"});
            if let Some(value)=choice { payload["dpopBoundAccessTokens"]=value.into(); }
            let mut invalid_create=payload.clone();invalid_create["dpopBoundAccessTokens"]=Value::Null;
            let before=saved(&pool,env.environment_id).await?;
            assert!(app.clone().oneshot(request(&collection,invalid_create,&cookie,"https://admin.aegaeon.test",true)).await?.status().is_client_error());
            assert_eq!(saved(&pool,env.environment_id).await?,before);
            let response=app.clone().oneshot(request(&collection,payload,&cookie,"https://admin.aegaeon.test",true)).await?;
            let status=response.status();let value:Value=serde_json::from_slice(&body::to_bytes(response.into_body(),65536).await?)?;
            assert_eq!(status,StatusCode::CREATED,"{value}");
            assert_eq!(value["client"]["dpopBoundAccessTokens"],choice.unwrap_or(false));
            let uri=format!("{collection}/{}",value["client"]["id"].as_str().ok_or("client id")?);
            let before=saved(&pool,env.environment_id).await?;
            let stale=json!({"baseConfigurationVersionId":Uuid::new_v4(),"dpopBoundAccessTokens":true});
            assert_eq!(patch(&app,&cookie,&uri,stale).await?.0,StatusCode::CONFLICT);
            sqlx::query("UPDATE aegaeon.team_memberships SET role='READONLY' WHERE team_id=$1").bind(env.team_id).execute(&pool).await?;
            assert_eq!(patch(&app,&cookie,&uri,json!({"baseConfigurationVersionId":init.configuration_version_id,"dpopBoundAccessTokens":true})).await?.0,StatusCode::FORBIDDEN);
            assert_eq!(saved(&pool,env.environment_id).await?,before);
            sqlx::query("UPDATE aegaeon.team_memberships SET role='OWNER' WHERE team_id=$1").bind(env.team_id).execute(&pool).await?;
            for selected in [true,false,true] {
                let before=saved(&pool,env.environment_id).await?;
                let patch_value=json!({"baseConfigurationVersionId":init.configuration_version_id,"dpopBoundAccessTokens":selected});
                let (status,value)=patch(&app,&cookie,&uri,patch_value.clone()).await?;
                assert_eq!(status,StatusCode::OK,"{value}");assert_eq!(value["client"]["dpopBoundAccessTokens"],selected);
                for path in [&uri,&collection] {
                    let mut req=request(path,json!({}),&cookie,"https://admin.aegaeon.test",true);*req.method_mut()=Method::GET;
                    let response=app.clone().oneshot(req).await?;assert_eq!(response.status(),StatusCode::OK);
                    let read:Value=serde_json::from_slice(&body::to_bytes(response.into_body(),65536).await?)?;
                    if path==&uri { assert_eq!(read["dpopBoundAccessTokens"],selected); }
                    else { assert_eq!(read["clients"].as_array().ok_or("client list")?.iter().find(|c|c["id"]==value["client"]["id"]).ok_or("listed client")?["dpopBoundAccessTokens"],selected); }
                }

                let after=saved(&pool,env.environment_id).await?;
                assert_ne!(before[3],after[3]);
                let audit:Value=sqlx::query_scalar("SELECT data FROM aegaeon.audit_events WHERE event_type='management.client.updated.v1' AND target_id=$1 ORDER BY occurred_at DESC LIMIT 1").bind(value["client"]["id"].as_str().ok_or("id")?).fetch_one(&pool).await?;
                assert_eq!(audit["current"]["dpopBoundAccessTokens"],selected);
                let prior=before[0].as_array().ok_or("prior clients")?.iter().find(|c|c["id"]==value["client"]["id"]).ok_or("prior client")?;
                assert_eq!(audit["previous"]["dpopBoundAccessTokens"],prior["dpop_bound_access_tokens"]);
                let omitted=json!({"baseConfigurationVersionId":init.configuration_version_id,"name":"renamed"});
                assert_eq!(patch(&app,&cookie,&uri,omitted).await?.1["client"]["dpopBoundAccessTokens"],selected);
                for invalid in [Value::Null,json!("true"),json!(1)] {
                    let before=saved(&pool,env.environment_id).await?;
                    let mut payload=patch_value.clone();payload["dpopBoundAccessTokens"]=invalid;
                    let mut req=request(&uri,payload,&cookie,"https://admin.aegaeon.test",true);
                    *req.method_mut()=Method::PATCH;
                    assert!(app.clone().oneshot(req).await?.status().is_client_error());
                    assert_eq!(saved(&pool,env.environment_id).await?,before);
                }
            }
            sqlx::query("UPDATE aegaeon.oauth_profiles SET sender_constrained='MTLS' WHERE environment_id=$1 AND is_default").bind(env.environment_id).execute(&pool).await?;
            let before=saved(&pool,env.environment_id).await?;
            assert_eq!(patch(&app,&cookie,&uri,json!({"baseConfigurationVersionId":init.configuration_version_id,"dpopBoundAccessTokens":true})).await?.0,StatusCode::BAD_REQUEST);
            assert_eq!(saved(&pool,env.environment_id).await?,before);
            sqlx::query("UPDATE aegaeon.oauth_profiles SET sender_constrained='NONE' WHERE environment_id=$1 AND is_default").bind(env.environment_id).execute(&pool).await?;
        }
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; actual configuration HTTP refuses retained NULL before commit"]
async fn pg_client_dpop_minimum_configuration_switch_refuses_deleted_legacy_authority(
) -> ManagementTestResult {
    let database =
        crate::dcr_persistence::test_database::Database::client_dpop_predecessor().await?;
    let pool = &database.pool;
    let result=async {
        let init=initialize_management(pool,&input()).await?;
        let env=TestEnvironment {team_id:init.team_id,tenant_id:init.tenant_id,environment_id:init.environment_id,issuer_url:format!("https://{}",init.issuer_host),issuer_host:init.issuer_host};
        sqlx::query("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,allowed_grant_types,token_endpoint_auth_methods_allowed) VALUES($1,$2,'legacy-barrier','DOWNSTREAM',true,ARRAY['authorization_code'],ARRAY['none'])").bind(env.environment_id).bind(init.configuration_version_id).execute(pool).await?;
        sqlx::query("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method,status) VALUES($1,$2,'retained-legacy','legacy','PUBLIC',ARRAY['https://client.example/callback'],ARRAY['authorization_code'],ARRAY['openid'],'none','DELETED')").bind(env.environment_id).bind(init.configuration_version_id).execute(pool).await?;
        sqlx::raw_sql(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../db/migrations/20261002120000_client_dpop_minimum.sql"))).execute(pool).await?;
        let draft:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.configuration_versions(environment_id,version_number,configuration_hash,status,configuration_document,created_by_administrator_id) SELECT environment_id,2,'null-barrier','DRAFT',configuration_document,created_by_administrator_id FROM aegaeon.configuration_versions WHERE id=$1 RETURNING id").bind(init.configuration_version_id).fetch_one(pool).await?;
        let (app,cookie)=login(pool,&env).await?;
        let root=format!("/api/v1/teams/{}/environments/{}",env.team_id,env.environment_id);
        let before=configuration_snapshot(pool,env.environment_id).await?;
        let (status,body)=patch(&app,&cookie,&format!("{root}/policies"),json!({"baseConfigurationVersionId":init.configuration_version_id,"accessTokenTimeToLiveSeconds":301})).await?;
        assert_eq!(status,StatusCode::INTERNAL_SERVER_ERROR,"{body}");
        assert!(body.to_string().contains("Client DPoP requirements are unresolved"));
        assert_eq!(configuration_snapshot(pool,env.environment_id).await?,before);
        let response=app.oneshot(request(&format!("{root}/configurationVersions/{draft}/activate"),json!({}),&cookie,"https://admin.aegaeon.test",true)).await?;
        let status=response.status();let body:Value=serde_json::from_slice(&body::to_bytes(response.into_body(),65536).await?)?;
        assert_eq!(status,StatusCode::INTERNAL_SERVER_ERROR,"{body}");
        assert!(body.to_string().contains("Client DPoP requirements are unresolved"));
        assert_eq!(configuration_snapshot(pool,env.environment_id).await?,before);
        Ok(())
    }.await;
    database.cleanup().await?;
    result
}

async fn configuration_snapshot(
    pool: &PgPool,
    environment: Uuid,
) -> crate::web::test_support::TestResult<Value> {
    let mut values = Vec::new();
    for table in [
        "clients",
        "configuration_versions",
        "oauth_profiles",
        "audit_events",
    ] {
        values.push(sqlx::query_scalar::<_,Value>(&format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM aegaeon.{table} t WHERE environment_id=$1")).bind(environment).fetch_one(pool).await?);
    }
    values.push(
        sqlx::query_scalar::<_, Value>(
            "SELECT to_jsonb(e) FROM aegaeon.environments e WHERE id=$1",
        )
        .bind(environment)
        .fetch_one(pool)
        .await?,
    );
    Ok(json!(values))
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; production management/DCR/runtime NULL refusal and repair readback"]
async fn pg_client_dpop_minimum_null_decoders_refuse_then_read_repaired_authority(
) -> ManagementTestResult {
    let database =
        crate::dcr_persistence::test_database::Database::client_dpop_predecessor().await?;
    let pool = &database.pool;
    let result=async {
        let env=crate::web::test_support::setup_test_environment(pool).await?;
        let id:Uuid=sqlx::query_scalar("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method) SELECT id,active_configuration_version_id,'legacy-null','legacy','PUBLIC',ARRAY['https://client.example/callback'],ARRAY['authorization_code'],ARRAY['openid'],'none' FROM aegaeon.environments WHERE id=$1 RETURNING id").bind(env.environment_id).fetch_one(pool).await?;
        sqlx::query("INSERT INTO aegaeon.dynamic_client_registrations(environment_id,client_id,client_identifier,registration_access_token_hash,registration_access_token_hash_algorithm,client_id_issued_at,response_types) VALUES($1,$2,'legacy-null',$3,'sha256',now(),ARRAY['code'])").bind(env.environment_id).bind(id).bind(crate::dcr_persistence::registration_access_token_hash("legacy-rat")).execute(pool).await?;
        sqlx::raw_sql(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../db/migrations/20261002120000_client_dpop_minimum.sql"))).execute(pool).await?;
        let response=crate::web::management::client_store::load_visible_client(pool,env.team_id,env.environment_id,id,"null-control").await.expect_err("management refuses null");
        assert_eq!(response.status(),StatusCode::INTERNAL_SERVER_ERROR);
        let body:Value=serde_json::from_slice(&body::to_bytes(response.into_body(),65536).await?)?;assert_eq!(body["message"],"Failed to load client");
        assert!(crate::dcr_persistence::load_dynamic_registration_by_token(pool,&env.issuer_host,"legacy-null","legacy-rat").await.is_err());
        assert!(crate::web::test_support::test_app_state(pool.clone(),&env).await.is_err());
        let mut conn=pool.acquire().await?;
        sqlx::query("SET TIME ZONE 'UTC'").execute(&mut *conn).await?;
        let digest:String=sqlx::query_scalar("SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.to_jsonb(c)::text,'UTF8')),'hex') FROM aegaeon.clients c WHERE id=$1").bind(id).fetch_one(&mut *conn).await?;
        sqlx::query("CREATE TEMP TABLE client_dpop_minimum_repair_input(schema_version integer,environment_id uuid,client_id uuid,expected_row_sha256 text,dpop_bound_access_tokens text,operator_reference text)").execute(&mut *conn).await?;
        sqlx::query("INSERT INTO client_dpop_minimum_repair_input VALUES(1,$1,$2,$3,'true','decoder-test')").bind(env.environment_id).bind(id).bind(digest).execute(&mut *conn).await?;
        let repair=include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../scripts/operations/client-dpop-minimum-repair.sql"));
        let commit=repair.strip_suffix("ROLLBACK;\n").ok_or("final rollback")?.to_owned()+"COMMIT;\n";
        sqlx::raw_sql(&commit).execute(&mut *conn).await?;drop(conn);
        let client=crate::web::management::client_store::load_visible_client(pool,env.team_id,env.environment_id,id,"repaired-control").await.map_err(|r|format!("management response {}",r.status()))?.ok_or("visible client")?;
        assert!(client.dpop_bound_access_tokens);
        assert!(crate::dcr_persistence::load_dynamic_registration_by_token(pool,&env.issuer_host,"legacy-null","legacy-rat").await?.ok_or("owner")?.client.dpop_bound_access_tokens);
        let state=crate::web::test_support::test_app_state(pool.clone(),&env).await?;
        assert!(state.clients.try_get("legacy-null")?.ok_or("runtime")?.dpop_bound_access_tokens);
        Ok(())
    }.await;
    database.cleanup().await?;
    result
}
