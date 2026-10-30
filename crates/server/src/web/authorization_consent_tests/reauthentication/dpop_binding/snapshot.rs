use super::*;
use crate::web::par_endpoint::snapshot_test_hook::{self, Phase};
use tokio::sync::Barrier;

async fn reload(state: &AppState) -> TestResult {
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(&state.db_pool, state.clients.as_ref())
        .await?;
    Ok(())
}
async fn mutate(state: &AppState) -> TestResult {
    let hash = crate::local_credentials::hash_password("changed-private-snapshot-secret")?;
    let mut tx = state.db_pool.begin().await?;
    sqlx::query("UPDATE aegaeon.clients SET token_endpoint_authentication_method='client_secret_post',allowed_scopes=ARRAY['other.read']::text[],redirect_uris=ARRAY['https://changed.example/cb']::text[],dpop_bound_access_tokens=true WHERE environment_id=$1 AND client_identifier=$2")
        .bind(state.environment_id).bind(CLIENT).execute(&mut *tx).await?;
    sqlx::query("UPDATE aegaeon.client_secrets SET secret_hash=$1 WHERE client_id IN (SELECT id FROM aegaeon.clients WHERE environment_id=$2 AND client_identifier=$3)")
        .bind(hash).bind(state.environment_id).bind(CLIENT).execute(&mut *tx).await?;
    sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=NULL,jwks_uri=NULL WHERE client_id IN (SELECT id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2)")
        .bind(state.environment_id).bind(CLIENT).execute(&mut *tx).await?;
    tx.commit().await?;
    reload(state).await
}
async fn restore(
    state: &AppState,
    client: &crate::client_registry::RegisteredClient,
) -> TestResult {
    let secret = CLIENT_SECRET.to_string();
    let hash = crate::local_credentials::hash_password(&secret)?;
    let mut tx = state.db_pool.begin().await?;
    sqlx::query("UPDATE aegaeon.clients SET token_endpoint_authentication_method=$1,allowed_scopes=$2,redirect_uris=$3,dpop_bound_access_tokens=false WHERE environment_id=$4 AND client_identifier=$5")
        .bind(&client.token_endpoint_auth_method).bind(&client.allowed_scopes).bind(&client.redirect_uris).bind(state.environment_id).bind(CLIENT).execute(&mut *tx).await?;
    sqlx::query("UPDATE aegaeon.client_secrets SET secret_hash=$1 WHERE client_id IN (SELECT id FROM aegaeon.clients WHERE environment_id=$2 AND client_identifier=$3)")
        .bind(hash).bind(state.environment_id).bind(CLIENT).execute(&mut *tx).await?;
    sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=$1 WHERE client_id IN (SELECT id FROM aegaeon.clients WHERE environment_id=$2 AND client_identifier=$3)")
        .bind(client.inline_jwks.as_ref().map(|j|j.as_value())).bind(state.environment_id).bind(CLIENT).execute(&mut *tx).await?;
    tx.commit().await?;
    reload(state).await
}
pub(super) async fn run(state: &AppState, sid: &str, after: bool, jar: bool) -> TestResult {
    let client = state.clients.try_get(CLIENT)?.ok_or("client")?;
    let key = Key::new(state)?;
    let pairs = if jar {
        vec![
            ("client_id".into(), CLIENT.into()),
            ("request".into(), signed(state, None, None)?),
        ]
    } else {
        fields(state, None)?
    };
    let observed = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let proof = key.proof(state, "/par", json!({}))?;
    let body = serde_urlencoded::to_string(&pairs)?;
    let headers = request_headers(state, Some(&proof))?;
    let phase = if after {
        Phase::AfterAuthentication
    } else {
        Phase::BeforeAuthentication
    };
    let request = snapshot_test_hook::OBSERVATION.scope(
        (phase, observed.clone(), resume.clone()),
        raw(
            state,
            sid,
            Method::POST,
            "/par",
            body.clone(),
            headers.clone(),
        ),
    );
    let mutation = async {
        observed.wait().await;
        let result = mutate(state).await;
        resume.wait().await;
        result
    };
    let (response, changed) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        tokio::join!(request, mutation)
    })
    .await?;
    changed?;
    let (status, value) = json_reply(response?).await?;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    // New requests see the changed authentication method; possession cannot replace it.
    let (status, error) =
        json_reply(raw(state, sid, Method::POST, "/par", body, headers).await?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error["error"], "invalid_client");
    let request_uri = value["request_uri"].as_str().ok_or("uri")?;
    let pairs = vec![
        ("client_id".into(), CLIENT.into()),
        ("request_uri".into(), request_uri.into()),
    ];
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let page = authorize(&mut browser, state, &pairs, true).await?;
    assert!(
        page.status.is_client_error()
            || page
                .location
                .as_deref()
                .is_some_and(|p| p.contains("error=")),
        "current policy must reject old redirect/scope"
    );
    restore(state, &client).await?;
    // The first rejected front-channel request may reserve the URI, so inspect the
    // accepted server-owned record and continue using its real reservation token.
    let (record, continuation) = stored_par(state, request_uri)?;
    assert_eq!(record["request"]["dpop_jkt"], key.jkt);
    let mut pairs = pairs;
    if let Some(continuation) = continuation {
        pairs.push(("aeg_par_continue".into(), continuation));
    }
    let page = authorize(&mut browser, state, &pairs, false).await?;
    let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
    redeem_bound(state, &code, &key).await
}

pub(super) async fn later_profile(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    let pairs = vec![
        ("client_id".into(), CLIENT.into()),
        ("request".into(), signed(state, Some(json!(key.jkt)), None)?),
    ];
    let observed = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let selected = snapshot_test_hook::OBSERVATION.scope(
        (Phase::AfterAuthentication, observed.clone(), resume.clone()),
        par::submit(state, sid, &pairs, None),
    );
    let update = async {
        observed.wait().await;
        let result=sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=ARRAY['none'] WHERE environment_id=$1").bind(state.environment_id).execute(&state.db_pool).await;
        resume.wait().await;
        result
    };
    let (response, updated) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        tokio::join!(selected, update)
    })
    .await?;
    updated?;
    let (status, body) = response?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(par::saved_count(state)?, 0);
    sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=ARRAY['client_secret_basic'] WHERE environment_id=$1").bind(state.environment_id).execute(&state.db_pool).await?;
    // The authenticated client snapshot does not freeze the later profile. Its
    // refusal precedes JAR jti admission, so the exact signed object still works.
    let (status, body) = par::submit(state, sid, &pairs, None).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let pairs = vec![
        ("client_id".into(), CLIENT.into()),
        (
            "request_uri".into(),
            body["request_uri"].as_str().ok_or("uri")?.into(),
        ),
    ];
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let page = authorize(&mut browser, state, &pairs, false).await?;
    let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
    redeem_bound(state, &code, &key).await
}
