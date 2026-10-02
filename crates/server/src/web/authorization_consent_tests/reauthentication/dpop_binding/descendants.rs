use super::*;
use crate::policy::TOKEN_EXCHANGE_GRANT_TYPE;

async fn prepare(state: &mut AppState) -> TestResult {
    let grants = vec![
        "authorization_code",
        "refresh_token",
        TOKEN_EXCHANGE_GRANT_TYPE,
    ];
    let mut scopes = SCOPE.split(' ').collect::<Vec<_>>();
    scopes.push("api.read");
    sqlx::query("UPDATE aegaeon.clients SET allowed_grant_types=$1,allowed_scopes=$2 WHERE environment_id=$3 AND client_identifier=$4")
        .bind(&grants).bind(scopes).bind(state.environment_id).bind(CLIENT).execute(&state.db_pool).await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1,enforce_refresh_sender_binding=false WHERE environment_id=$2")
        .bind(grants).bind(state.environment_id).execute(&state.db_pool).await?;
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(&state.db_pool, state.clients.as_ref())
        .await?;
    let policy = serde_json::from_value(
        json!({"version":1,"targets":[{"audience":"internal-api","resourceAliases":[]}],"rules":[{"clientId":CLIENT,"sourceAudience":format!("{}/userinfo",state.issuer),"targetAudience":"internal-api","scopes":[{"targetScope":"api.read","sourceScopes":["profile"]}],"defaultScopes":["api.read"]}]}),
    )?;
    update_test_policy(state, |document| {
        document.token_exchange = policy;
        document
            .allowed_grant_types
            .push(TOKEN_EXCHANGE_GRANT_TYPE.into());
        document.enforce_refresh_sender_binding = false;
    })
    .await?;
    state.tokens.issuer = Arc::new(
        crate::authcode::TokenIssuer::with_stores(
            state.keys.access_token.clone(),
            state.tokens.issuer.code_store.clone(),
            state.tokens.store.as_ref().clone(),
        )
        .with_oidc(state.oidc.config.as_deref().cloned())
        .with_issuer(state.issuer.to_string())
        .with_jwt_access_tokens_enabled(true)
        .with_token_exchange_policy(state.cfg.token_exchange.clone()),
    );
    native_dpop::set_minimum(state, CLIENT, "consent-test-registration", true).await
}
async fn grant(
    state: &AppState,
    fields: &[(&str, &str)],
    proof: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    json_reply(
        raw(
            state,
            "",
            Method::POST,
            "/token",
            serde_urlencoded::to_string(fields)?,
            request_headers(state, proof)?,
        )
        .await?,
    )
    .await
}
fn assert_binding(state: &AppState, value: &Value, key: &Key) -> TestResult<String> {
    assert_eq!(value["token_type"], "DPoP");
    let access = value["access_token"].as_str().ok_or("access")?;
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(access.split('.').nth(1).ok_or("claims")?)?,
    )?;
    assert_eq!(claims["cnf"]["jkt"], key.jkt);
    let meta = state
        .tokens
        .store
        .try_get_bearer_meta(access)?
        .ok_or("meta")?;
    assert_eq!(
        meta.sender_binding,
        Some(SenderBinding::DPoP {
            jkt: key.jkt.clone()
        })
    );
    lifecycle::validate(state, access, &meta.audience, key)?;
    Ok(access.into())
}
async fn reject_then_grant(
    state: &AppState,
    fields: &[(&str, &str)],
    key: &Key,
) -> TestResult<Value> {
    let wrong = Key::new(state)?;
    for proof in [None, Some(wrong.proof(state, "/token", json!({}))?)] {
        let before = state.tokens.store.try_snapshot()?;
        let (status, body) = grant(state, fields, proof.as_deref()).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        if fields
            .iter()
            .any(|(name, value)| *name == "grant_type" && *value == "refresh_token")
        {
            assert_eq!(body["error"], "invalid_grant");
            assert_eq!(
                body["error_description"],
                if proof.is_some() {
                    "sender_binding_mismatch"
                } else {
                    "sender_binding_missing"
                }
            );
        } else {
            assert_eq!(body["error"], "invalid_request");
            assert_eq!(
                body["error_description"],
                "subject_token sender binding mismatch"
            );
        }
        assert!(body.get("access_token").is_none());
        let after = state.tokens.store.try_snapshot()?;
        assert_eq!(before.access_tokens.len(), after.access_tokens.len());
        assert_eq!(before.refresh_tokens.len(), after.refresh_tokens.len());
    }
    let proof = key.proof(state, "/token", json!({}))?;
    let (status, body) = grant(state, fields, Some(&proof)).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body)
}
pub(super) async fn run(state: &mut AppState, sid: &str) -> TestResult {
    prepare(state).await?;
    lifecycle::prepare(state).await?;
    let key = Key::new(state)?;
    let mut pairs = fields(state, Some("consent"))?;
    pairs.push(("dpop_jkt".into(), key.jkt.clone()));
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let page = authorize(&mut browser, state, &pairs, true).await?;
    let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
    // Current registration and refresh enforcement are both lowered after the
    // server-owned code has committed its independently supplied expectation.
    native_dpop::set_minimum(state, CLIENT, "consent-test-registration", false).await?;
    let proof = key.proof(state, "/token", json!({}))?;
    let (status, initial) = token(state, &code, Some(&proof)).await?;
    assert_eq!(status, StatusCode::OK, "{initial}");
    let initial_access = assert_binding(state, &initial, &key)?;
    let userinfo = format!("{}/userinfo", state.issuer);
    assert!(state.cfg.security_policy.retain_refresh_chain());
    lifecycle::observe(state, &initial_access, &userinfo, &key, true).await?;
    let refresh = initial["refresh_token"].as_str().ok_or("refresh")?;
    let refreshed = reject_then_grant(
        state,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT),
            ("refresh_token", refresh),
        ],
        &key,
    )
    .await?;
    let subject = assert_binding(state, &refreshed, &key)?;
    // The configured parent-retention policy invalidates the older access
    // token after rotation, independently of the retained sender binding.
    assert!(matches!(
        lifecycle::validate(state, &initial_access, &userinfo, &key),
        Err(crate::authcode::TokenPolicyError::RefreshParentRevoked)
    ));
    lifecycle::observe(state, &initial_access, &userinfo, &key, false).await?;
    let next = refreshed["refresh_token"].as_str().ok_or("next refresh")?;
    assert_eq!(
        state
            .tokens
            .store
            .try_get_refresh_token(next)?
            .ok_or("next")?
            .sender_binding,
        Some(SenderBinding::DPoP {
            jkt: key.jkt.clone()
        })
    );
    let exchange_fields = [
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("client_id", CLIENT),
        ("subject_token", subject.as_str()),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("audience", "internal-api"),
    ];
    authenticate_exchange(state, &exchange_fields, &key).await?;
    let exchanged = reject_then_grant(state, &exchange_fields, &key).await?;
    let exchanged_access = assert_binding(state, &exchanged, &key)?;
    let lineage = [
        (initial_access.as_str(), userinfo.as_str()),
        (subject.as_str(), userinfo.as_str()),
        (exchanged_access.as_str(), "internal-api"),
    ];
    for (access, audience) in &lineage[1..] {
        lifecycle::observe(state, access, audience, &key, true).await?;
    }
    lifecycle::revoke_and_observe(state, next, &lineage, &key).await?;
    Ok(())
}

async fn authenticate_exchange(state: &AppState, fields: &[(&str, &str)], key: &Key) -> TestResult {
    if state
        .clients
        .try_get(CLIENT)?
        .ok_or("client")?
        .token_endpoint_auth_method
        != "none"
    {
        return Ok(());
    }
    // Public-origin code and refresh succeed above. Aegaeon's exchange policy
    // independently requires confidential authentication; a valid proof cannot
    // replace it. Transition the same registered owner, retaining its lineage.
    let before = state.tokens.store.try_snapshot()?;
    let proof = key.proof(state, "/token", json!({}))?;
    let (status, body) = grant(state, fields, Some(&proof)).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    let after = state.tokens.store.try_snapshot()?;
    assert_eq!(before.access_tokens.len(), after.access_tokens.len());
    assert_eq!(before.refresh_tokens.len(), after.refresh_tokens.len());
    let host = url::Url::parse(state.issuer.as_str())?
        .host_str()
        .ok_or("host")?
        .to_string();
    let registration = "consent-test-registration";
    let stored = crate::dcr_persistence::load_dynamic_registration_by_token(
        &state.db_pool,
        &host,
        CLIENT,
        registration,
    )
    .await?
    .ok_or("registration")?;
    let mut client = stored.client.clone();
    client.token_endpoint_auth_method = "client_secret_basic".into();
    crate::dcr_persistence::update_dynamic_registration(
        &state.db_pool,
        &stored,
        &client,
        &stored.response_types,
        registration,
        crate::dcr_persistence::DcrClientSecretChange::ReplaceWithPlaintext(CLIENT_SECRET.into()),
        None,
        "binding-confidential-exchange",
    )
    .await?;
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(&state.db_pool, state.clients.as_ref())
        .await?;
    let current = crate::dcr_persistence::load_dynamic_registration_by_token(
        &state.db_pool,
        &host,
        CLIENT,
        registration,
    )
    .await?
    .ok_or("updated registration")?;
    assert_eq!(current.database_client_id, stored.database_client_id);
    assert_eq!(
        current.registration_access_token_hash,
        stored.registration_access_token_hash
    );
    assert_eq!(current.client.client_id, CLIENT);
    assert!(!current.client.dpop_bound_access_tokens);
    Ok(())
}
