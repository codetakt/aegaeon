use super::*;

async fn namespace_isolation(state: &AppState, sid: &str) -> TestResult {
    let uri = push(state, sid, Some("form_post"), None, false).await?;
    let request_uri = query(&uri)?
        .into_iter()
        .find(|(k, _)| k == "request_uri")
        .ok_or("URI")?
        .1;
    let raw: String = redis::cmd("GET")
        .arg(request_key(state, &request_uri, "v3"))
        .query(&mut connection()?)?;
    let old_uri = format!("urn:aegaeon:par:{}", Uuid::new_v4());
    let old_key = request_key(state, &old_uri, "v1");
    let old_reservation = old_key.replace(":req:", ":reservation:");
    let mut legacy: Value = serde_json::from_str(&raw)?;
    legacy["request"]
        .as_object_mut()
        .ok_or("request")?
        .remove("response_mode");
    let legacy = legacy.to_string();
    for (key, value) in [
        (&old_key, legacy.as_str()),
        (&old_reservation, "old-continuation"),
    ] {
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(90)
            .query::<()>(&mut connection()?)?;
    }
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let before = state.tokens.issuer.code_store.snapshot().codes.len();
    for continuation in [None, Some("old-continuation")] {
        let mut pairs = vec![("client_id", CLIENT), ("request_uri", old_uri.as_str())];
        if let Some(value) = continuation {
            pairs.push(("aeg_par_continue", value));
        }
        let page = browser
            .request(
                state,
                &format!("/authorize?{}", serde_urlencoded::to_string(pairs)?),
                None,
            )
            .await?;
        no_cache(&page);
        assert!(page.status.is_client_error());
        assert_eq!(
            state.tokens.issuer.code_store.snapshot().codes.len(),
            before
        );
    }
    let old_reader: Option<String> = redis::cmd("GET")
        .arg(request_key(state, &request_uri, "v1"))
        .query(&mut connection()?)?;
    assert!(old_reader.is_none(), "old reader cannot find new records");
    let page = browser.request(state, &uri, None).await?;
    redeem_response(state, &browser, &page, "form_post", &request_uri).await?;
    assert!(keys(state, "v3")?.is_empty());
    let original: String = redis::cmd("GET").arg(old_key).query(&mut connection()?)?;
    assert_eq!(original, legacy);
    let reservation: String = redis::cmd("GET")
        .arg(old_reservation)
        .query(&mut connection()?)?;
    assert_eq!(reservation, "old-continuation");
    Ok(())
}
async fn refusal_and_expiry(state: &AppState, sid: &str) -> TestResult {
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let uri = push(state, sid, Some("form_post"), Some("consent"), false).await?;
    let request_uri = query(&uri)?
        .into_iter()
        .find(|(k, _)| k == "request_uri")
        .ok_or("URI")?
        .1;
    let before = state.tokens.issuer.code_store.snapshot().codes.len();
    let page = browser.request(state, &uri, None).await?;
    let transaction = transaction(&page.body)?.to_string();
    assert_eq!(
        keys(state, "v3")?.len(),
        2,
        "request and reservation coexist"
    );
    // Current client policy is rechecked before the normal atomic grant commit.
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=ARRAY['openid'] WHERE environment_id=$1 AND client_identifier=$2").bind(state.environment_id).bind(CLIENT).execute(&state.db_pool).await?;
    let page = browser
        .request(
            state,
            "/auth/consent",
            Some(vec![("transaction", &transaction), ("decision", "approve")]),
        )
        .await?;
    no_cache(&page);
    assert!(!page.body.contains("name=\"code\""));
    assert_eq!(field(&page.body, "error")?, "invalid_scope");
    assert_eq!(
        state.tokens.issuer.code_store.snapshot().codes.len(),
        before
    );
    assert!(stored(state, &request_uri)?.is_some());
    assert_eq!(keys(state, "v3")?.len(), 2);
    let _ = state
        .protocol
        .par_store
        .try_consume_request(&request_uri)
        .map_err(|e| format!("{e:?}"))?;
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=$1 WHERE environment_id=$2 AND client_identifier=$3").bind(SCOPE.split(' ').collect::<Vec<_>>()).bind(state.environment_id).bind(CLIENT).execute(&state.db_pool).await?;
    state.protocol.par_store.set_expires_in(1);
    let uri = push(state, sid, Some("form_post"), None, false).await?;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let page = browser.request(state, &uri, None).await?;
    no_cache(&page);
    assert!(page.status.is_client_error());
    assert_eq!(
        state.tokens.issuer.code_store.snapshot().codes.len(),
        before
    );
    state.protocol.par_store.set_expires_in(90);
    Ok(())
}
async fn inconsistent_signed_record(state: &AppState, sid: &str) -> TestResult {
    let uri = push(state, sid, Some("form_post"), None, true).await?;
    let request_uri = query(&uri)?
        .into_iter()
        .find(|(k, _)| k == "request_uri")
        .ok_or("URI")?
        .1;
    let key = request_key(state, &request_uri, "v3");
    let raw: String = redis::cmd("GET").arg(&key).query(&mut connection()?)?;
    let mut value: Value = serde_json::from_str(&raw)?;
    value["request"]["response_mode"] = json!("query");
    redis::cmd("SET")
        .arg(&key)
        .arg(value.to_string())
        .arg("KEEPTTL")
        .query::<()>(&mut connection()?)?;
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let before = state.tokens.issuer.code_store.snapshot().codes.len();
    let page = browser.request(state, &uri, None).await?;
    no_cache(&page);
    assert!(page.status.is_client_error());
    assert!(page.body.contains("disagrees with Request Object"));
    assert_eq!(
        state.tokens.issuer.code_store.snapshot().codes.len(),
        before
    );
    let raw: String = redis::cmd("GET").arg(&key).query(&mut connection()?)?;
    assert_eq!(
        serde_json::from_str::<Value>(&raw)?["request"]["request_object_claims"]["response_mode"],
        "form_post"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn pushed_response_modes_namespace_expiry_and_precommit_refusals() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let (mut state, sid) = fixture(&pool, &env).await?;
        update_test_policy(&mut state, |p| p.strict_authorize_redirect = true).await?;
        request_objects::shared_protocol_stores(&mut state)?;
        namespace_isolation(&state, &sid).await?;
        refusal_and_expiry(&state, &sid).await?;
        inconsistent_signed_record(&state, &sid).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
