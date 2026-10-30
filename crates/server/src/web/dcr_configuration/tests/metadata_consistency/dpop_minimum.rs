//! Durable minimum through mounted registration endpoints and actual runtime projection.
use super::*;

async fn assert_stored(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    value: &Value,
    expected: bool,
) -> TestResult {
    assert_eq!(value["dpop_bound_access_tokens"], expected);
    assert!(value.get("require_dpop").is_none());
    assert!(value.get("dpop_required").is_none());
    let client = crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        field(value, "client_id")?,
        field(value, "registration_access_token")?,
    )
    .await?
    .ok_or("stored registration")?;
    assert_eq!(client.client.dpop_bound_access_tokens, expected);
    let state = test_app_state(pool.clone(), env).await?;
    assert_eq!(
        state
            .clients
            .try_get(field(value, "client_id")?)?
            .ok_or("runtime client")?
            .dpop_bound_access_tokens,
        expected
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL database; real registration CRUD and runtime projection"]
async fn pg_dcr_client_dpop_minimum_roundtrips_aliases_and_retains_omitted_null() -> TestResult {
    let database = Database::create(false).await?;
    let env = setup_test_dcr_environment(&database.pool).await?;
    let result = async {
        let app = router(&database.pool, &env).await?;
        for key in ["require_dpop", "dpop_required", "dpop_bound_access_tokens"] {
            let metadata = json!({"redirect_uris":["https://client.example/callback"],"token_endpoint_auth_method":"none",key:true});
            let mut client = post(&app, &metadata).await?;
            assert_stored(&database.pool, &env, &client, true).await?;
            assert_eq!(read(&app, &client).await?["dpop_bound_access_tokens"], true);
            for choice in [None, Some(Value::Null), Some(json!(false)), Some(json!(true))] {
                let mut body = json!({"client_id":field(&client,"client_id")?});
                if let Some(value) = &choice { body[key] = value.clone(); }
                let expected = choice.as_ref().and_then(Value::as_bool).unwrap_or(client["dpop_bound_access_tokens"].as_bool().unwrap());
                let response = app.clone().oneshot(request(Method::PUT, &format!("/register/{}",field(&client,"client_id")?), Some(field(&client,"registration_access_token")?), &body)?).await?;
                let status=response.status();client=response_json(response).await?;
                assert_eq!(status,StatusCode::OK,"{client}");
                assert_stored(&database.pool,&env,&client,expected).await?;
            }
        }
        for choice in [None, Some(Value::Null)] {
            let mut metadata=json!({"redirect_uris":["https://client.example/default"],"token_endpoint_auth_method":"none"});
            if let Some(value)=choice { metadata["dpop_bound_access_tokens"]=value; }
            let client=post(&app,&metadata).await?;
            assert_stored(&database.pool,&env,&client,false).await?;
        }
        Ok(())
    }.await;
    database.cleanup().await?;
    result
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL database; raw collision and capability refusal"]
async fn pg_dcr_client_dpop_minimum_refusals_are_write_free() -> TestResult {
    let database = Database::create(false).await?;
    let env = setup_test_dcr_environment(&database.pool).await?;
    let result=async {
        let app=router(&database.pool,&env).await?;
        for raw in [
            r#""require_dpop":true,"dpop_required":true"#,
            r#""require_dpop":true,"dpop_bound_access_tokens":true"#,
            r#""dpop_required":true,"dpop_bound_access_tokens":true"#,
            r#""dpop_bound_access_tokens":true,"dpop_bound_access_tokens":true"#,
            r#""dpop_bound_access_tokens":"true""#,
            r#""dpop_bound_access_tokens":1"#,
            r#""dpop_bound_access_tokens":[]"#,
        ] {
            let before=digest(&database.pool,&env).await?;
            let body=format!(r#"{{"redirect_uris":["https://client.example/callback"],"token_endpoint_auth_method":"none",{raw}}}"#);
            let response=app.clone().oneshot(Request::post("/register").header(header::CONTENT_TYPE,"application/json").body(Body::from(body))?).await?;
            assert_eq!(response.status(),StatusCode::BAD_REQUEST,"{raw}");
            assert_eq!(before,digest(&database.pool,&env).await?);
        }
        Ok(())
    }.await;
    database.cleanup().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; actual owner profile, global capability and generic declaration boundaries"]
async fn pg_dcr_client_dpop_minimum_keeps_global_policy_and_checks_assigned_profile() -> TestResult
{
    let database = Database::create(false).await?;
    let env = setup_test_dcr_environment(&database.pool).await?;
    let result=async {
        let app=router(&database.pool,&env).await?;
        let client=post(&app,&json!({"redirect_uris":["https://client.example/callback"],"token_endpoint_auth_method":"none"})).await?;
        let assigned:uuid::Uuid=sqlx::query_scalar("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,sender_constrained,allowed_grant_types,token_endpoint_auth_methods_allowed) SELECT environment_id,configuration_version_id,'assigned-minimum','DOWNSTREAM',false,'MTLS',allowed_grant_types,token_endpoint_auth_methods_allowed FROM aegaeon.oauth_profiles WHERE environment_id=$1 AND is_default AND profile_type='DOWNSTREAM' RETURNING id").bind(env.environment_id).fetch_one(&database.pool).await?;
        sqlx::query("UPDATE aegaeon.clients SET oauth_profile_id=$1 WHERE environment_id=$2 AND client_identifier=$3").bind(assigned).bind(env.environment_id).bind(field(&client,"client_id")?).execute(&database.pool).await?;
        let payload=json!({"client_id":field(&client,"client_id")?,"dpop_bound_access_tokens":true});
        let path=format!("/register/{}",field(&client,"client_id")?);
        let before=digest(&database.pool,&env).await?;
        let response=app.clone().oneshot(request(Method::PUT,&path,Some(field(&client,"registration_access_token")?),&payload)?).await?;
        assert_eq!(response.status(),StatusCode::BAD_REQUEST);
        assert_eq!(response_json(response).await?["error"],"invalid_client_metadata");
        assert_eq!(digest(&database.pool,&env).await?,before);
        sqlx::query("UPDATE aegaeon.oauth_profiles SET sender_constrained='DPOP' WHERE id=$1").bind(assigned).execute(&database.pool).await?;
        let response=app.oneshot(request(Method::PUT,&path,Some(field(&client,"registration_access_token")?),&payload)?).await?;
        let status=response.status();let value=response_json(response).await?;assert_eq!(status,StatusCode::OK,"{value}");
        assert_stored(&database.pool,&env,&value,true).await?;
        let invalid_policy=crate::management::types::PolicyDocument {dcr_allowed_sender_methods:vec![],..Default::default()};
        assert!(crate::dcr::DcrValidationConfig::try_from_policy(&invalid_policy,false,false,true,true,8192).is_err(), "empty capability lists must fail configuration validation without changing stored policy");
        {
            let app=router_with_sender_policy(&database.pool,&env,true,vec!["dpop".into()]).await?;
            let before=digest(&database.pool,&env).await?;
            let response=app.oneshot(request(Method::POST,"/register",None,&json!({"redirect_uris":["https://client.example/callback"],"token_endpoint_auth_method":"none","dpop_bound_access_tokens":true}))?).await?;
            assert_eq!(response.status(),StatusCode::BAD_REQUEST);
            assert_eq!(response_json(response).await?["error"],"invalid_client_metadata");
            assert_eq!(digest(&database.pool,&env).await?,before);
        }
        Ok(())
    }.await;
    database.cleanup().await?;
    result
}
