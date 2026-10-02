#[test]
fn protected_header_stored_jwt_access_token_validation() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let store = TokenStore::new_process_local_for_tests();
    let validator = TokenValidator::new(store.clone(), key_manager.clone())
        .with_jwt_access_tokens_enabled(true)
        .with_issuer(Some("https://issuer.example".into()));
    let payload = json!({"iss":"https://issuer.example","sub":"client","aud":"client",
        "client_id":"client","iat":unix_epoch_now_secs(),
        "exp":unix_epoch_now_secs()+300,"jti":"header-admission"}).to_string();
    for (extra, accepted) in [
        (r#""extension":{"nested":[null,true,5]},"\u2603":"ignored","jku":"https://keys.example/jwks""#, true),
        (r#""crit":null"#, false),
        (r#""b64":true"#, false),
        (r#""b64":false,"crit":["b64"]"#, false),
        (r#""zip":"DEF""#, false),
        (r#""cty":null"#, false),
        (r#""extension":null,"\u0065xtension":true"#, false),
    ] {
        let header = format!("{{\"alg\":\"HS256\",\"typ\":\"at+jwt\",\"kid\":\"{}\",{extra}}}", key_manager.key_id());
        let token = sign_raw_jwt_parts(&header, &payload, key_manager.as_ref())?;
        store_jwt_access_token(&store, &token)?;
        assert_eq!(validator.validate_bearer_token(&format!("Bearer {token}")).is_ok(), accepted, "{header}");
        if accepted {
            let limited = validator.clone().with_jose_header_max_len(1);
            assert!(limited.validate_bearer_token(&format!("Bearer {token}")).is_err());
        }
    }
    for field in ["alg","typ","kid"] {
        for value in [Value::Null,json!(true),json!(1),json!([]),json!({})] {
            let mut header=json!({"alg":"HS256","typ":"at+jwt","kid":key_manager.key_id()});
            header[field]=value;
            let token=sign_raw_jwt_parts(&header.to_string(),&payload,key_manager.as_ref())?;
            store_jwt_access_token(&store,&token)?;
            assert!(validator.validate_bearer_token(&format!("Bearer {token}")).is_err());
        }
    }
    Ok(())
}
