use super::*;

fn sign_raw_header(header: &str, payload: &[u8]) -> TestResult<String> {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let key = EncodingKey::from_rsa_pem(include_bytes!(
        "../../../../tests/fixtures/rsa2048-private.pk8.pem"
    ))?;
    let signature = jsonwebtoken::crypto::sign(input.as_bytes(), &key, Algorithm::RS256)?;
    Ok(format!("{input}.{signature}"))
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
async fn protected_header_pg_par_request_object_admission() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result=async {
        let (state,sid)=fixture(&pool,&env).await?;
        for (extra,accepted,error) in [
            (r#""extension":{"nested":[null,true]},"\u2603":"ignored","jku":"https://keys.example/jwks""#,true,""),
            (r#""extension":[1,]"#,false,"invalid_request_object"),
            (r#""crit":null"#,false,"invalid_request_object"),
            (r#""b64":true"#,false,"invalid_request_object"),
            (r#""kid":null"#,false,"invalid_request_object"),
            (r#""extension":0,"\u0065xtension":1"#,false,"invalid_request"),
        ] {
            let original=signed_request(&state,"header-admission")?;
            let payload=URL_SAFE_NO_PAD.decode(original.split('.').nth(1).ok_or("payload")?)?;
            let header=format!("{{\"alg\":\"RS256\",\"typ\":\"oauth-authz-req+jwt\",{extra}}}");
            let token=sign_raw_header(&header,&payload)?;
            let (status,body)=send(&state,&sid,"/par",Some(vec![("client_id",CLIENT),("request",&token)]),None).await?;
            assert_eq!(status,if accepted {StatusCode::CREATED} else {StatusCode::BAD_REQUEST},"{header}: {body}");
            let response:Value=serde_json::from_str(&body)?;
            if accepted {assert!(response["request_uri"].is_string());}
            else {assert_eq!(response["error"],error,"{header}: {body}");}
        }
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
async fn protected_header_pg_token_client_assertion_admission() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result=async {
        let (state,sid)=fixture_with_auth_method(&pool,&env,"private_key_jwt").await?;
        for (extra,accepted) in [
            (r#""extension":{"nested":[null,true]},"\u2603":"ignored","jku":"https://keys.example/jwks""#,true),
            (r#""extension":[1,]"#,false),
            (r#""crit":null"#,false),
            (r#""b64":true"#,false),
            (r#""cty":null"#,false),
            (r#""extension":0,"\u0065xtension":1"#,false),
        ] {
            let now=crate::util::now_unix_epoch_secs()?;
            let claims=json!({"iss":CLIENT,"sub":CLIENT,"aud":format!("{}/token",state.issuer),"iat":now,"exp":now+30,"jti":Uuid::new_v4().to_string()});
            let header=format!("{{\"alg\":\"RS256\",\"typ\":\"JWT\",{extra}}}");
            let token=sign_raw_header(&header,&serde_json::to_vec(&claims)?)?;
            let (status,body)=send(&state,&sid,"/token",Some(vec![
                ("client_id",CLIENT),("client_assertion_type","urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                ("client_assertion",&token),("grant_type","authorization_code"),("code","absent-code"),
                ("redirect_uri","https://client.example.com/callback"),("code_verifier",VERIFIER),
            ]),None).await?;
            assert!(status.is_client_error(),"{body}");
            // A successful authentication reaches the absent-code grant check;
            // this control does not claim successful token issuance.
            assert_eq!(serde_json::from_str::<Value>(&body)?["error"],if accepted {"invalid_grant"} else {"invalid_client"},"{header}: {body}");
        }
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
