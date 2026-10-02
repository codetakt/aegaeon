use super::*;
use crate::middleware::dpop::DpopNonceStore;
use std::time::Duration;

pub(super) async fn run(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    token_proofs(state, sid, &key).await?;
    stored_outer_keys(state, sid, &key).await?;
    expired_nonce(state, sid, &key).await?;
    concurrent_par(state, sid, &key).await
}

async fn authorize_pushed(
    state: &AppState,
    sid: &str,
    uri: &str,
    outer: Option<&str>,
    expected: Option<&str>,
    post: bool,
) -> TestResult<String> {
    let mut pairs = vec![
        ("client_id".into(), CLIENT.into()),
        ("request_uri".into(), uri.into()),
    ];
    if let Some(key) = outer {
        pairs.push(("dpop_jkt".into(), key.into()));
    }
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let page = authorize(&mut browser, state, &pairs, post).await?;
    finish(&mut browser, state, page, expected).await
}

async fn token_proofs(state: &AppState, sid: &str, key: &Key) -> TestResult {
    let raw_par_proof = key.proof(state, "/par", json!({}))?;
    let (status, body) =
        par::submit(state, sid, &fields(state, None)?, Some(&raw_par_proof)).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let code = authorize_pushed(
        state,
        sid,
        body["request_uri"].as_str().ok_or("uri")?,
        None,
        Some(&key.jkt),
        false,
    )
    .await?;
    let valid = key.proof(state, "/token", json!({}))?;
    let (input, signature) = valid.rsplit_once('.').ok_or("signature")?;
    let mut bytes = URL_SAFE_NO_PAD.decode(signature)?;
    bytes[0] ^= 1;
    let invalid_signature = format!("{input}.{}", URL_SAFE_NO_PAD.encode(bytes));
    let (mut conn, storage, original) = storage_guards::stored_code(state, &code)?;
    let before = state.tokens.store.try_snapshot()?;
    for proof in [raw_par_proof, invalid_signature] {
        let (status, body) = token(state, &code, Some(&proof)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_dpop_proof");
        let retained: String = redis::cmd("GET").arg(&storage).query(&mut conn)?;
        assert_eq!(retained, original);
        let after = state.tokens.store.try_snapshot()?;
        assert_eq!(before.access_tokens.len(), after.access_tokens.len());
        assert_eq!(before.refresh_tokens.len(), after.refresh_tokens.len());
    }
    redeem_bound(state, &code, key).await
}

async fn stored_outer_keys(state: &AppState, sid: &str, key: &Key) -> TestResult {
    let other = Key::new(state)?;
    for bound in [false, true] {
        for post in [false, true] {
            for outer in [&key.jkt, &other.jkt] {
                let mut pairs = fields(state, None)?;
                if bound {
                    pairs.push(("dpop_jkt".into(), key.jkt.clone()));
                }
                let (status, body) = par::submit(state, sid, &pairs, None).await?;
                assert_eq!(status, StatusCode::CREATED, "{body}");
                let uri = body["request_uri"].as_str().ok_or("uri")?;
                let expected = bound.then_some(key.jkt.as_str());
                assert_eq!(
                    stored_par(state, uri)?.0["request"]["dpop_jkt"],
                    json!(expected)
                );
                let code = authorize_pushed(state, sid, uri, Some(outer), expected, post).await?;
                if bound {
                    redeem_bound(state, &code, key).await?;
                } else {
                    assert_eq!(token(state, &code, None).await?.0, StatusCode::OK);
                }
            }
        }
    }
    Ok(())
}

async fn expired_nonce(original: &AppState, sid: &str, key: &Key) -> TestResult {
    let mut state = original.clone();
    let store = DpopNonceStore::redis(
        &std::env::var("AEGAEON_TEST_REDIS_URL")?,
        format!("binding-expiry-{}", state.environment_id),
        Duration::from_secs(1),
    )?;
    state.dpop = Arc::new(
        state
            .dpop
            .as_ref()
            .clone()
            .with_nonce_store(Arc::new(store)),
    );
    let nonce = state
        .dpop
        .current_nonce()
        .map_err(|e| format!("nonce: {e:?}"))?
        .ok_or("nonce")?;
    let proof = key.proof(&state, "/par", json!({"nonce":nonce}))?;
    assert_eq!(
        par::submit(&state, sid, &fields(&state, None)?, Some(&proof))
            .await?
            .0,
        StatusCode::CREATED
    );
    // Redis retains a nonce for twice its rotation TTL. Let the real record expire.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let fresh_proof = key.proof(&state, "/par", json!({"nonce":nonce}))?;
    let before = par::saved_count(&state)?;
    let pairs = fields(&state, None)?;
    let response = raw(
        &state,
        sid,
        Method::POST,
        "/par",
        serde_urlencoded::to_string(&pairs)?,
        request_headers(&state, Some(&fresh_proof))?,
    )
    .await?;
    let next = response
        .headers()
        .get("DPoP-Nonce")
        .ok_or("challenge")?
        .to_str()?
        .to_string();
    assert_ne!(nonce, next);
    let (status, body) = json_reply(response).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "use_dpop_nonce");
    assert_eq!(par::saved_count(&state)?, before);
    let proof = key.proof(&state, "/par", json!({"nonce":next}))?;
    assert_eq!(
        par::submit(&state, sid, &pairs, Some(&proof)).await?.0,
        StatusCode::CREATED
    );
    Ok(())
}

async fn race_authorize(
    state: &AppState,
    sid: &str,
    request_uri: &str,
    continuation: &str,
    barrier: &tokio::sync::Barrier,
) -> TestResult<axum::response::Response> {
    // Each attempt independently resumes valid authority before the start barrier.
    state
        .protocol
        .par_store
        .resume_request_for_client(request_uri, CLIENT, continuation)
        .map_err(|e| format!("resume: {}", e.error))?;
    let uri = format!(
        "/authorize?{}",
        serde_urlencoded::to_string([
            ("client_id", CLIENT),
            ("request_uri", request_uri),
            ("aeg_par_continue", continuation)
        ])?
    );
    barrier.wait().await;
    raw(
        state,
        sid,
        Method::GET,
        &uri,
        String::new(),
        HeaderMap::new(),
    )
    .await
}

async fn concurrent_par(original: &AppState, sid: &str, key: &Key) -> TestResult {
    let mut state = original.clone();
    update_test_policy(&mut state, |policy| policy.require_state_parameter = false).await?;
    assert!(!state.cfg.require_state);
    let state = &state;
    // This isolated OAuth profile permits absent state; production/default policy
    // is unchanged. Keep client, session, PKCE and DPoP requirements intact.
    let changed = sqlx::query(
        "UPDATE aegaeon.oauth_profiles SET require_state_parameter=false WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .execute(&state.db_pool)
    .await?;
    assert!(changed.rows_affected() > 0);
    let required: Vec<bool> = sqlx::query_scalar(
        "SELECT require_state_parameter FROM aegaeon.oauth_profiles WHERE environment_id=$1",
    )
    .bind(state.environment_id)
    .fetch_all(&state.db_pool)
    .await?;
    assert!(!required.is_empty() && required.iter().all(|required| !required));
    let mut pairs = fields(state, None)?;
    // Isolate PAR single-use from the independent state/nonce replay indexes.
    pairs.retain(|(name, _)| name != "state" && name != "nonce");
    pairs
        .iter_mut()
        .find(|(name, _)| name == "scope")
        .ok_or("scope")?
        .1 = "email".into();
    assert!(!pairs
        .iter()
        .any(|(name, _)| name == "state" || name == "nonce"));
    pairs.push(("dpop_jkt".into(), key.jkt.clone()));
    let (status, body) = par::submit(state, sid, &pairs, None).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let uri = body["request_uri"].as_str().ok_or("uri")?.to_string();
    let (mut conn, request_key, reservation_key) = par_keys(state, &uri)?;
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers = (0..2)
        .map(|_| {
            let store = state.protocol.par_store.clone();
            let uri = uri.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.reserve_request_for_client(&uri, CLIENT)
            })
        })
        .collect::<Vec<_>>();
    let mut winners = Vec::new();
    for worker in workers {
        match worker.join().map_err(|_| "reservation worker")? {
            Ok(reserved) => winners.push(reserved),
            Err(error) => assert_eq!(error.error, "invalid_request_uri"),
        }
    }
    assert_eq!(winners.len(), 1);
    let continuation = &winners[0].continuation;
    assert_eq!(
        stored_par(state, &uri)?.1.as_deref(),
        Some(continuation.as_str())
    );
    let before = state.tokens.issuer.code_store.snapshot().codes.len();
    let counts = state.tokens.store.try_snapshot()?;
    let barrier = tokio::sync::Barrier::new(2);
    let (left, right) = tokio::join!(
        race_authorize(state, sid, &uri, continuation, &barrier),
        race_authorize(state, sid, &uri, continuation, &barrier)
    );
    let mut codes = Vec::new();
    for response in [left?, right?] {
        if response.status() == StatusCode::FOUND {
            let location = url::Url::parse(response.headers()[header::LOCATION].to_str()?)?;
            let fields: std::collections::HashMap<_, _> =
                location.query_pairs().into_owned().collect();
            if let Some(code) = fields.get("code") {
                codes.push(code.clone());
            } else {
                assert_eq!(
                    fields.get("error").map(String::as_str),
                    Some("invalid_request_uri"),
                    "{:?}",
                    fields.get("error_description")
                );
            }
        } else {
            let (status, body) = json_reply(response).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["error"], "invalid_request_uri");
        }
    }
    assert_eq!(codes.len(), 1);
    assert_eq!(
        state.tokens.issuer.code_store.snapshot().codes.len(),
        before + 1
    );
    let missing: Vec<Option<String>> = redis::cmd("MGET")
        .arg(&[request_key, reservation_key])
        .query(&mut conn)?;
    assert_eq!(missing, vec![None, None]);
    let after = state.tokens.store.try_snapshot()?;
    assert_eq!(counts.access_tokens.len(), after.access_tokens.len());
    assert_eq!(counts.refresh_tokens.len(), after.refresh_tokens.len());
    redeem_bound(state, &codes[0], key).await
}
