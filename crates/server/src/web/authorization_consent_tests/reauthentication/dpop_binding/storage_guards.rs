use super::*;

pub(super) fn stored_code(
    state: &AppState,
    code: &str,
) -> TestResult<(redis::Connection, String, String)> {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let prefix = namespace.redis_atomic_group_prefix(
        crate::config::RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
        "authcode",
        "v3",
    );
    let mut hash = aegaeon_crypto::hash::Sha256Hasher::new();
    hash.update(b"aegaeon:authcode:v3");
    hash.update(&(code.len() as u64).to_be_bytes());
    hash.update(code.as_bytes());
    let storage = format!("{prefix}:code:{}", URL_SAFE_NO_PAD.encode(hash.finalize()));
    let mut conn =
        redis::Client::open(std::env::var("AEGAEON_AUTH_CODE_REDIS_URL")?)?.get_connection()?;
    let bytes: String = redis::cmd("GET").arg(&storage).query(&mut conn)?;
    Ok((conn, storage, bytes))
}
async fn unavailable(state: &AppState, code: &str, key: &Key, description: &str) -> TestResult {
    let (mut conn, storage, before) = stored_code(state, code)?;
    let counts = state.tokens.store.try_snapshot()?;
    let proof = key.proof(state, "/token", json!({}))?;
    let (status, body) = token(state, code, Some(&proof)).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(body["error_description"]
        .as_str()
        .ok_or("description")?
        .contains(description));
    let after: String = redis::cmd("GET").arg(storage).query(&mut conn)?;
    assert_eq!(before, after);
    let after = state.tokens.store.try_snapshot()?;
    assert_eq!(counts.access_tokens.len(), after.access_tokens.len());
    assert_eq!(counts.refresh_tokens.len(), after.refresh_tokens.len());
    Ok(())
}
pub(super) async fn run(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    let code = token_guards::bound_code(state, sid, &key).await?;
    wrong_client(state, &code, &key).await?;
    let trigger = format!("binding_audit_{}", Uuid::new_v4().simple());
    let sql=format!("CREATE FUNCTION aegaeon.{trigger}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id = '{}'::uuid AND NEW.event_type='oauth.token.issue.requested.v1' THEN RAISE EXCEPTION 'isolated audit storage failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER {trigger} BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.{trigger}()",state.environment_id);
    sqlx::raw_sql(&sql).execute(&state.db_pool).await?;
    let rejected = unavailable(state, &code, &key, "audit").await;
    sqlx::raw_sql(&format!(
        "DROP TRIGGER {trigger} ON aegaeon.audit_events; DROP FUNCTION aegaeon.{trigger}()"
    ))
    .execute(&state.db_pool)
    .await?;
    rejected?;
    application_guard(state, &code, &key).await?;
    redeem_bound(state, &code, &key).await?;
    let expired = token_guards::bound_code(state, sid, &key).await?;
    let (mut conn, storage, _) = stored_code(state, &expired)?;
    redis::cmd("PEXPIREAT")
        .arg(storage)
        .arg(1)
        .query::<()>(&mut conn)?;
    let before = state.tokens.store.try_snapshot()?;
    let proof = key.proof(state, "/token", json!({}))?;
    let (status, body) = token(state, &expired, Some(&proof)).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    let after = state.tokens.store.try_snapshot()?;
    assert_eq!(before.access_tokens.len(), after.access_tokens.len());
    assert_eq!(before.refresh_tokens.len(), after.refresh_tokens.len());
    Ok(())
}
async fn wrong_client(state: &AppState, code: &str, key: &Key) -> TestResult {
    let issuer = url::Url::parse(state.issuer.as_str())?;
    let host = issuer.host_str().ok_or("host")?;
    let client = sample_registered_client("other-binding-client");
    crate::dcr_persistence::create_dynamic_registration(
        &state.db_pool,
        host,
        &client,
        &["code".into()],
        "other-binding-registration",
        "code-owner-test",
    )
    .await?;
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(&state.db_pool, state.clients.as_ref())
        .await?;
    let mut pairs = token_guards::code_fields(code);
    pairs
        .iter_mut()
        .find(|(k, _)| k == "client_id")
        .ok_or("client")?
        .1 = client.client_id;
    let proof = key.proof(state, "/token", json!({}))?;
    token_guards::refusal(
        state,
        code,
        &pairs,
        form_headers(Some(&proof))?,
        "invalid_grant",
    )
    .await
}
async fn application_guard(state: &AppState, code: &str, key: &Key) -> TestResult {
    assert!(state.application_authority.is_none());
    let (mut conn, storage, original) = stored_code(state, code)?;
    let mut changed: Value = serde_json::from_str(&original)?;
    // Seed a structurally valid server-owned application grant to isolate the
    // unavailable-current-authority branch. This does not test its producer.
    changed["application_grant"] = json!({"version":1,"environment_id":state.environment_id,"issuer":state.issuer.as_str(),"client_id":CLIENT,"subject":"consent-user","revision":1,"audiences":[format!("{}/userinfo",state.issuer)],"selected_organization":null,"claims":{"roles":["USER"],"organization_roles":[]}});
    let decoded: crate::authcode::types::AuthorizationCode =
        serde_json::from_value(changed.clone())?;
    decoded
        .application_grant
        .as_ref()
        .ok_or("grant")?
        .validate()?;
    redis::cmd("SET")
        .arg(&storage)
        .arg(changed.to_string())
        .arg("KEEPTTL")
        .query::<()>(&mut conn)?;
    let rejected = unavailable(state, code, key, "application authority").await;
    redis::cmd("SET")
        .arg(&storage)
        .arg(original)
        .arg("KEEPTTL")
        .query::<()>(&mut conn)?;
    rejected
}
