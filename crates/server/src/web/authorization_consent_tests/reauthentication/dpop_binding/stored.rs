use super::*;

async fn push_mode(
    state: &AppState,
    sid: &str,
    key: &Key,
    mode: Option<&str>,
    jar: bool,
    login: bool,
) -> TestResult<Vec<(String, String)>> {
    let mut pairs = fields(state, login.then_some("login consent"))?;
    pairs.push(("dpop_jkt".into(), key.jkt.clone()));
    if login {
        pairs.push(("max_age".into(), "0".into()));
    }
    if let Some(mode) = mode {
        pairs.push(("response_mode".into(), mode.into()));
    }
    if jar {
        let jwt = signed(
            state,
            Some(json!(key.jkt)),
            login.then_some("login consent"),
        )?;
        let mut claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).ok_or("claims")?)?,
        )?;
        if let Some(mode) = mode {
            claims["response_mode"] = json!(mode);
        } else {
            claims
                .as_object_mut()
                .ok_or("object")?
                .remove("response_mode");
        }
        pairs = vec![
            ("client_id".into(), CLIENT.into()),
            ("request".into(), sign_claims(&claims)?),
        ];
    }
    let (status, body) = json_reply(
        raw(
            state,
            sid,
            Method::POST,
            "/par",
            serde_urlencoded::to_string(pairs)?,
            request_headers(state, None)?,
        )
        .await?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    Ok(vec![
        ("client_id".into(), CLIENT.into()),
        (
            "request_uri".into(),
            body["request_uri"].as_str().ok_or("uri")?.into(),
        ),
        ("dpop_jkt".into(), "ignored outer".into()),
    ])
}
fn browser(sid: &str) -> Browser {
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    browser
}
fn request_uri(pairs: &[(String, String)]) -> TestResult<&str> {
    Ok(pairs
        .iter()
        .find(|(k, _)| k == "request_uri")
        .ok_or("uri")?
        .1
        .as_str())
}
async fn no_code(
    state: &AppState,
    browser: &mut Browser,
    pairs: &[(String, String)],
) -> TestResult {
    let before = state.tokens.issuer.code_store.snapshot().codes.len();
    let page = authorize(browser, state, pairs, true).await?;
    assert!(
        page.status.is_client_error() || page.status.is_server_error(),
        "{} {} {:?}",
        page.status,
        page.body,
        page.location
    );
    assert_eq!(
        state.tokens.issuer.code_store.snapshot().codes.len(),
        before
    );
    Ok(())
}
pub(super) async fn modes(state: &AppState, sid: &str, login: bool) -> TestResult {
    let key = Key::new(state)?;
    for jar in [false, true] {
        for mode in [None, Some("query"), Some("form_post")] {
            let pairs = push_mode(state, sid, &key, mode, jar, login).await?;
            let mut browser = browser(sid);
            let page = authorize(&mut browser, state, &pairs, jar).await?;
            if !login {
                assert_eq!(
                    page.status,
                    if mode == Some("form_post") {
                        StatusCode::OK
                    } else {
                        StatusCode::FOUND
                    }
                );
            }
            let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
            redeem_bound(state, &code, &key).await?;
            no_code(state, &mut browser, &pairs).await?;
        }
    }
    Ok(())
}
pub(super) async fn records(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    let other = Key::new(state)?;
    for mutation in [
        "key",
        "mode",
        "missing-key",
        "bad-key",
        "missing-version",
        "old-version",
        "expiry",
        "client",
    ] {
        let mut pairs = push_mode(state, sid, &key, Some("form_post"), true, false).await?;
        let uri = request_uri(&pairs)?.to_owned();
        let (mut conn, storage_key, _) = par_keys(state, &uri)?;
        let original: String = redis::cmd("GET").arg(&storage_key).query(&mut conn)?;
        let mut changed: Value = serde_json::from_str(&original)?;
        match mutation {
            "key" => changed["request"]["dpop_jkt"] = json!(other.jkt),
            "mode" => changed["request"]["response_mode"] = json!("query"),
            "missing-key" => {
                changed["request"]
                    .as_object_mut()
                    .ok_or("request")?
                    .remove("dpop_jkt");
            }
            "bad-key" => changed["request"]["dpop_jkt"] = json!("bad"),
            "missing-version" => {
                changed.as_object_mut().ok_or("record")?.remove("version");
            }
            "old-version" => changed["version"] = json!(2),
            "expiry" => changed["expires_at_epoch_secs"] = json!(1),
            _ => changed["client_id"] = json!("other-client"),
        }
        redis::cmd("SET")
            .arg(&storage_key)
            .arg(changed.to_string())
            .arg("KEEPTTL")
            .query::<()>(&mut conn)?;
        let mut browser = browser(sid);
        no_code(state, &mut browser, &pairs).await?;
        let retained: Option<String> = redis::cmd("GET").arg(&storage_key).query(&mut conn)?;
        // Expired records are removed by the existing expiry contract.
        if mutation == "expiry" {
            assert!(retained.is_none());
            continue;
        }
        assert_eq!(retained.as_deref(), Some(changed.to_string().as_str()));
        redis::cmd("SET")
            .arg(&storage_key)
            .arg(&original)
            .arg("KEEPTTL")
            .query::<()>(&mut conn)?;
        if let Some(continuation) = stored_par(state, &uri)?.1 {
            pairs.push(("aeg_par_continue".into(), continuation));
        }
        let page = authorize(&mut browser, state, &pairs, false).await?;
        let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
        redeem_bound(state, &code, &key).await?;
    }
    reservation(state, sid, &key).await
}
async fn reservation(state: &AppState, sid: &str, key: &Key) -> TestResult {
    let pairs = push_mode(state, sid, key, None, false, true).await?;
    let uri = request_uri(&pairs)?;
    let mut browser = browser(sid);
    let page = authorize(&mut browser, state, &pairs, false).await?;
    let (_, saved) = stored_par(state, uri)?;
    assert!(saved.is_some());
    let mut bad = pairs.clone();
    bad.push(("aeg_par_continue".into(), "fabricated".into()));
    no_code(state, &mut browser, &bad).await?;
    assert_eq!(stored_par(state, uri)?.1, saved);
    let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
    redeem_bound(state, &code, key).await
}

pub(super) async fn legacy(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    let pairs = push_mode(state, sid, &key, None, false, false).await?;
    let uri = request_uri(&pairs)?;
    let (original, _) = stored_par(state, uri)?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let (mut conn, _, _) = par_keys(state, uri)?;
    for version in ["v1", "v2"] {
        let key_for = |uri: &str| {
            let prefix = namespace.redis_atomic_group_prefix(
                crate::config::RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
                "par",
                version,
            );
            let mut hash = aegaeon_crypto::hash::Sha256Hasher::new();
            hash.update(format!("aegaeon:par:{version}").as_bytes());
            hash.update(&(uri.len() as u64).to_be_bytes());
            hash.update(uri.as_bytes());
            format!("{prefix}:req:{}", URL_SAFE_NO_PAD.encode(hash.finalize()))
        };
        let absent: Option<String> = redis::cmd("GET").arg(key_for(uri)).query(&mut conn)?;
        assert!(absent.is_none(), "old reader cannot locate bound v3 record");
        let old_uri = format!("urn:aegaeon:par:{}", Uuid::new_v4());
        let old_key = key_for(&old_uri);
        let mut old = original.clone();
        old.as_object_mut().ok_or("record")?.remove("version");
        old["request"]
            .as_object_mut()
            .ok_or("request")?
            .remove("dpop_jkt");
        if version == "v1" {
            old["request"]
                .as_object_mut()
                .ok_or("request")?
                .remove("response_mode");
        }
        let old = old.to_string();
        redis::cmd("SET")
            .arg(&old_key)
            .arg(&old)
            .arg("EX")
            .arg(90)
            .query::<()>(&mut conn)?;
        let mut browser = browser(sid);
        no_code(
            state,
            &mut browser,
            &[
                ("client_id".into(), CLIENT.into()),
                ("request_uri".into(), old_uri),
            ],
        )
        .await?;
        let retained: String = redis::cmd("GET").arg(&old_key).query(&mut conn)?;
        assert_eq!(retained, old);
        let ttl: i64 = redis::cmd("TTL").arg(&old_key).query(&mut conn)?;
        assert!(ttl > 0 && ttl <= 90);
        redis::cmd("DEL").arg(old_key).query::<()>(&mut conn)?;
    }
    let mut browser = browser(sid);
    let page = authorize(&mut browser, state, &pairs, false).await?;
    let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
    redeem_bound(state, &code, &key).await
}
