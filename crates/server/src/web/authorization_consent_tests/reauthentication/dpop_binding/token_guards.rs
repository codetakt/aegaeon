use super::*;

pub(super) async fn bound_code(state: &AppState, sid: &str, key: &Key) -> TestResult<String> {
    let mut pairs = fields(state, None)?;
    pairs.push(("dpop_jkt".into(), key.jkt.clone()));
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let page = authorize(&mut browser, state, &pairs, false).await?;
    finish(&mut browser, state, page, Some(&key.jkt)).await
}
pub(super) fn code_fields(code: &str) -> Vec<(String, String)> {
    [
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT),
        ("code", code),
        ("redirect_uri", "https://client.example.com/callback"),
        ("code_verifier", VERIFIER),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}
pub(super) async fn refusal(
    state: &AppState,
    code: &str,
    pairs: &[(String, String)],
    headers: HeaderMap,
    error: &str,
) -> TestResult {
    let before = serde_json::to_value(state.tokens.issuer.code_store.try_get_code(code)?)?;
    let counts = state.tokens.store.try_snapshot()?;
    let (status, body) = json_reply(
        raw(
            state,
            "",
            Method::POST,
            "/token",
            serde_urlencoded::to_string(pairs)?,
            headers,
        )
        .await?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], error);
    assert_eq!(
        serde_json::to_value(state.tokens.issuer.code_store.try_get_code(code)?)?,
        before
    );
    let after = state.tokens.store.try_snapshot()?;
    assert_eq!(counts.access_tokens.len(), after.access_tokens.len());
    assert_eq!(counts.refresh_tokens.len(), after.refresh_tokens.len());
    Ok(())
}
pub(super) async fn mtls(original: &AppState, sid: &str) -> TestResult {
    let key = Key::new(original)?;
    let code = bound_code(original, sid, &key).await?;
    let mut state = original.clone();
    Arc::make_mut(&mut state.cfg).mtls_enabled = true;
    state.transport =
        crate::middleware::tls::TransportSecurity::new(crate::config::TransportSecurityConfig {
            require_tls_proxy: true,
            trusted_proxies: vec!["127.0.0.1/32".parse()?],
            ..crate::config::TransportSecurityConfig::default()
        });
    let mut headers = request_headers(&state, None)?;
    headers.insert("x-forwarded-proto", "https".parse()?);
    headers.insert(
        "x-forwarded-client-cert",
        format!("SHA256:{}", "AB".repeat(32)).parse()?,
    );
    let pairs = code_fields(&code);
    for profile in ["NONE", "MTLS"] {
        sqlx::query("UPDATE aegaeon.oauth_profiles SET sender_constrained=$1::aegaeon.oauth_sender_constraint,enforce_refresh_sender_binding=false WHERE environment_id=$2").bind(profile).bind(state.environment_id).execute(&state.db_pool).await?;
        refusal(&state, &code, &pairs, headers.clone(), "invalid_grant").await?;
    }
    let proof = key.proof(&state, "/token", json!({}))?;
    let mut both = headers.clone();
    both.insert("DPoP", proof.parse()?);
    refusal(&state, &code, &pairs, both, "invalid_request").await?;
    native_dpop::set_minimum(&state, CLIENT, "consent-test-registration", true).await?;
    refusal(&state, &code, &pairs, headers, "unauthorized_client").await?;
    native_dpop::set_minimum(&state, CLIENT, "consent-test-registration", false).await?;
    sqlx::query(
        "UPDATE aegaeon.oauth_profiles SET sender_constrained='NONE' WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .execute(&state.db_pool)
    .await?;
    redeem_bound(original, &code, &key).await
}
pub(super) async fn grant_guards(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    let code = bound_code(state, sid, &key).await?;
    for (field, value) in [
        ("redirect_uri", "https://client.example.com/wrong"),
        (
            "code_verifier",
            "wrong-but-valid-length-aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ("code", "missing-code"),
    ] {
        let mut pairs = code_fields(&code);
        pairs.iter_mut().find(|(k, _)| k == field).ok_or("field")?.1 = value.into();
        let proof = key.proof(state, "/token", json!({}))?;
        refusal(
            state,
            &code,
            &pairs,
            request_headers(state, Some(&proof))?,
            "invalid_grant",
        )
        .await?;
    }
    sqlx::query("UPDATE aegaeon.clients SET allowed_grant_types=ARRAY['refresh_token'] WHERE environment_id=$1 AND client_identifier=$2").bind(state.environment_id).bind(CLIENT).execute(&state.db_pool).await?;
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(&state.db_pool, state.clients.as_ref())
        .await?;
    let proof = key.proof(state, "/token", json!({}))?;
    refusal(
        state,
        &code,
        &code_fields(&code),
        request_headers(state, Some(&proof))?,
        "unauthorized_client",
    )
    .await?;
    sqlx::query("UPDATE aegaeon.clients SET allowed_grant_types=ARRAY['authorization_code','refresh_token'] WHERE environment_id=$1 AND client_identifier=$2").bind(state.environment_id).bind(CLIENT).execute(&state.db_pool).await?;
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(&state.db_pool, state.clients.as_ref())
        .await?;
    redeem_bound(state, &code, &key).await
}
