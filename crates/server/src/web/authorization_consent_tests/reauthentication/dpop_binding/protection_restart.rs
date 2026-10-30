use super::*;
fn protection(state: &mut AppState) -> TestResult {
    native_dpop::install(state)?;
    let nonces = crate::middleware::dpop::DpopNonceStore::redis(
        &std::env::var("AEGAEON_TEST_REDIS_URL")?,
        format!("binding-retained-nonce-{}", state.environment_id),
        std::time::Duration::from_secs(300),
    )?;
    state.dpop = Arc::new(
        state
            .dpop
            .as_ref()
            .clone()
            .with_nonce_store(Arc::new(nonces)),
    );
    Ok(())
}
pub(super) async fn run(original: &AppState, sid: &str) -> TestResult {
    let mut state = original.clone();
    protection(&mut state)?;
    state.oidc.userinfo_endpoint = Some(Arc::new(crate::oidc::userinfo::UserinfoEndpoint::new(
        state.tokens.validator.as_ref().clone(),
        state.db_pool.clone(),
        state.issuer.to_string(),
    )));
    let key = Key::new(&state)?;
    let nonce = state
        .dpop
        .current_nonce()
        .map_err(|e| format!("{e:?}"))?
        .ok_or("nonce")?;
    let jti = Uuid::new_v4().to_string();
    let proof = key.proof(&state, "/par", json!({"jti":jti,"nonce":nonce}))?;
    let (status, body) = par::submit(&state, sid, &fields(&state, None)?, Some(&proof)).await?;
    assert_eq!(status, StatusCode::CREATED);
    let pairs = vec![
        ("client_id".into(), CLIENT.into()),
        (
            "request_uri".into(),
            body["request_uri"].as_str().ok_or("uri")?.into(),
        ),
    ];
    // Reconstruct independent middleware and all pending stores using the same
    // actual Redis namespace. No replay/nonce or lineage entry is cleared.
    let mut restarted = state.clone();
    request_objects::shared_protocol_stores(&mut restarted)?;
    protection(&mut restarted)?;
    reject_old_pending(&restarted, sid, &pairs).await?;
    assert_eq!(
        restarted
            .dpop
            .current_nonce()
            .map_err(|e| format!("{e:?}"))?
            .as_deref(),
        Some(nonce.as_str())
    );
    let (status, body) =
        par::submit(&restarted, sid, &fields(&restarted, None)?, Some(&proof)).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_dpop_proof");
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let page = authorize(&mut browser, &restarted, &pairs, false).await?;
    let code = finish(&mut browser, &restarted, page, Some(&key.jkt)).await?;
    let token_proof = key.proof(&restarted, "/token", json!({"jti":jti,"nonce":nonce}))?;
    assert_eq!(
        token(&restarted, &code, Some(&token_proof)).await?.1["error"],
        "invalid_dpop_proof"
    );
    let fresh = key.proof(&restarted, "/token", json!({"nonce":nonce}))?;
    let (status, tokens) = token(&restarted, &code, Some(&fresh)).await?;
    assert_eq!(status, StatusCode::OK);
    let access = tokens["access_token"].as_str().ok_or("access")?;
    let ath = URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(access.as_bytes()));
    let proof = key.proof(
        &restarted,
        "/userinfo",
        json!({"htm":"GET","ath":ath,"nonce":nonce}),
    )?;
    let mut headers = form_headers(Some(&proof))?;
    headers.insert(header::AUTHORIZATION, format!("DPoP {access}").parse()?);
    let response = raw(
        &restarted,
        sid,
        Method::GET,
        "/userinfo",
        String::new(),
        headers,
    )
    .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "UserInfo must reach native resource verifier"
    );
    let rs_nonce = response
        .headers()
        .get("DPoP-Nonce")
        .ok_or("RS nonce")?
        .to_str()?
        .to_string();
    assert_ne!(rs_nonce, nonce);
    let (status, body) = json_reply(response).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "use_dpop_nonce");
    let proof = key.proof(
        &restarted,
        "/userinfo",
        json!({"htm":"GET","ath":ath,"nonce":rs_nonce}),
    )?;
    let mut headers = form_headers(Some(&proof))?;
    headers.insert(header::AUTHORIZATION, format!("DPoP {access}").parse()?);
    let (status, body) = json_reply(
        raw(
            &restarted,
            sid,
            Method::GET,
            "/userinfo",
            String::new(),
            headers,
        )
        .await?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

async fn reject_old_pending(state: &AppState, sid: &str, pairs: &[(String, String)]) -> TestResult {
    let uri = &pairs
        .iter()
        .find(|(k, _)| k == "request_uri")
        .ok_or("uri")?
        .1;
    let (mut old, _) = stored_par(state, uri)?;
    old.as_object_mut().ok_or("record")?.remove("version");
    old["request"]
        .as_object_mut()
        .ok_or("request")?
        .remove("dpop_jkt");
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let (mut conn, _, _) = par_keys(state, uri)?;
    for version in ["v1", "v2"] {
        let uri = format!("urn:aegaeon:par:{}", Uuid::new_v4());
        let prefix = namespace.redis_atomic_group_prefix(
            crate::config::RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
            "par",
            version,
        );
        let mut hash = aegaeon_crypto::hash::Sha256Hasher::new();
        hash.update(format!("aegaeon:par:{version}").as_bytes());
        hash.update(&(uri.len() as u64).to_be_bytes());
        hash.update(uri.as_bytes());
        let storage = format!("{prefix}:req:{}", URL_SAFE_NO_PAD.encode(hash.finalize()));
        redis::cmd("SET")
            .arg(&storage)
            .arg(old.to_string())
            .arg("EX")
            .arg(90)
            .query::<()>(&mut conn)?;
        let mut browser = Browser::default();
        browser
            .cookies
            .insert("aegaeon_auth_session".into(), sid.into());
        let page = authorize(
            &mut browser,
            state,
            &[
                ("client_id".into(), CLIENT.into()),
                ("request_uri".into(), uri),
            ],
            false,
        )
        .await?;
        assert!(page.status.is_client_error());
        let retained: String = redis::cmd("GET").arg(&storage).query(&mut conn)?;
        assert_eq!(retained, old.to_string());
        let ttl: i64 = redis::cmd("TTL").arg(&storage).query(&mut conn)?;
        assert!(ttl > 0 && ttl <= 90);
        // Fixture-only cleanup of precisely the seeded old pending entry.
        redis::cmd("DEL").arg(storage).query::<()>(&mut conn)?;
    }
    Ok(())
}
