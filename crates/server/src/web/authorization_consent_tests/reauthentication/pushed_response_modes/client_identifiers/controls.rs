use super::*;

pub(super) async fn register_other(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let mut client = sample_registered_client(OTHER_CLIENT);
    client.allowed_scopes = SCOPE.split(' ').map(str::to_string).collect();
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".to_string()],
        "other-consent-registration",
        "consent-test",
    )
    .await?;
    let registered: String = sqlx::query_scalar(
        "SELECT client_identifier FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2"
    ).bind(env.environment_id).bind(OTHER_CLIENT).fetch_one(pool).await?;
    assert_eq!(registered, OTHER_CLIENT);
    Ok(())
}

pub(super) async fn wrong_continuation(
    state: &AppState,
    browser: &mut Browser,
    uri: &str,
    request_uri: &str,
) -> TestResult {
    let retained = par_pair(state, request_uri)?;
    let mut pairs = query(uri)?;
    for (key, value) in &mut pairs {
        if key == "aeg_par_continue" {
            *value = "wrong".into();
        }
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
    assert!(page.location.is_none());
    assert_eq!(par_pair(state, request_uri)?, retained);
    Ok(())
}

pub(super) async fn direct_and_empty_controls(state: &AppState, sid: &str) -> TestResult {
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    for signed in [false, true] {
        let uri = if signed {
            let jwt = request_objects::signed_request(state, "jar-query-mode-no-prompt")?;
            request_objects::authorization_uri(state, sid, &jwt, "jar-no-prompt").await?
        } else {
            authorize_uri(state, None)?
        };
        let before = state.tokens.issuer.code_store.snapshot().codes.len();
        for padded in [format!("+{CLIENT}"), format!("{CLIENT}%20")] {
            let uri = uri.replace(
                &format!("client_id={CLIENT}"),
                &format!("client_id={padded}"),
            );
            let page = browser.request(state, &uri, None).await?;
            no_cache(&page);
            assert_eq!(page.status, StatusCode::BAD_REQUEST, "{}", page.body);
            assert!(page.location.is_none());
            assert_eq!(
                state.tokens.issuer.code_store.snapshot().codes.len(),
                before
            );
        }
        let page = browser.request(state, &uri, None).await?;
        let state_value = if signed {
            let jwt = query(&uri)?
                .into_iter()
                .find(|(k, _)| k == "request")
                .ok_or("JWT")?
                .1;
            let claims: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).ok_or("claims")?)?,
            )?;
            claims["state"].as_str().ok_or("state")?.to_string()
        } else {
            query(&uri)?
                .into_iter()
                .find(|(k, _)| k == "state")
                .ok_or("state")?
                .1
        };
        exact_grant(state, &browser, &page, "query", &state_value).await?;
    }
    let uri = push(state, sid, Some("query"), None, false).await?;
    let request_uri = query(&uri)?
        .into_iter()
        .find(|(k, _)| k == "request_uri")
        .ok_or("request URI")?
        .1;
    let retained = stored(state, &request_uri)?.ok_or("pushed request")?;
    let page = browser
        .request(state, &format!("{uri}&client_id="), None)
        .await?;
    exact_grant(
        state,
        &browser,
        &page,
        "query",
        retained.state.as_deref().ok_or("state")?,
    )
    .await?;
    assert_eq!(par_pair(state, &request_uri)?, vec![None, None]);
    Ok(())
}
