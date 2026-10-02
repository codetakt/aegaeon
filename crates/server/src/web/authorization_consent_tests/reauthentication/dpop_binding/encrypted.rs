use super::*;
use request_objects::encrypted_headers::EnvelopeFixture;

fn header(kid: Option<&str>) -> Value {
    let mut value = json!({"alg":"RSA-OAEP","enc":"A256GCM","cty":"JWT"});
    if let Some(kid) = kid {
        value["kid"] = json!(kid);
    }
    value
}
async fn prepare(state: &mut AppState) -> TestResult<(EnvelopeFixture, EnvelopeFixture)> {
    let old = EnvelopeFixture::new()?;
    let active = EnvelopeFixture::second_key()?;
    crate::web::test_support::seed_request_object_encryption_key(state, "binding-old", &old.key)
        .await?;
    sqlx::query("UPDATE aegaeon.runtime_keys SET status='RETIRING',retiring_expires_at=now()+interval '10 minutes' WHERE environment_id=$1 AND kid='binding-old'")
        .bind(state.environment_id).execute(&state.db_pool).await?;
    crate::web::test_support::seed_request_object_encryption_key(
        state,
        "binding-active",
        &active.key,
    )
    .await?;
    request_objects::shared_protocol_stores(state)?;
    native_dpop::install(state)?;
    Ok((old, active))
}
async fn pushed(
    state: &AppState,
    sid: &str,
    jwe: &str,
    key: &Key,
) -> TestResult<Vec<(String, String)>> {
    let proof = key.proof(state, "/par", json!({}))?;
    let (status, body) = json_reply(
        raw(
            state,
            sid,
            Method::POST,
            "/par",
            serde_urlencoded::to_string([("client_id", CLIENT), ("request", jwe)])?,
            form_headers(Some(&proof))?,
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
    ])
}
async fn denied(state: &AppState, sid: &str, jwe: &str, par: bool) -> TestResult {
    let encoded = serde_urlencoded::to_string([("client_id", CLIENT), ("request", jwe)])?;
    let (method, uri, body) = if par {
        (Method::POST, "/par".into(), encoded)
    } else {
        (Method::GET, format!("/authorize?{encoded}"), String::new())
    };
    let (status, body) =
        json_reply(raw(state, sid, method, &uri, body, form_headers(None)?).await?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request_object");
    Ok(())
}
pub(super) async fn run(state: &mut AppState, sid: &str) -> TestResult {
    let (old, active) = prepare(state).await?;
    let key = Key::new(state)?;
    for post in [false, true] {
        for par in [false, true] {
            for (envelope, kid) in [
                (&old, Some("binding-old")),
                (&active, Some("binding-active")),
            ] {
                let jwt = signed(state, Some(json!(key.jkt)), Some("login consent"))?;
                let jwe = envelope.seal(&header(kid).to_string(), jwt.as_bytes())?;
                let pairs = if par {
                    pushed(state, sid, &jwe, &key).await?
                } else {
                    vec![
                        ("client_id".into(), CLIENT.into()),
                        ("request".into(), jwe.clone()),
                    ]
                };
                let mut browser = Browser::default();
                browser
                    .cookies
                    .insert("aegaeon_auth_session".into(), sid.into());
                let page = authorize(&mut browser, state, &pairs, post).await?;
                let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
                let stored = state
                    .tokens
                    .issuer
                    .code_store
                    .try_get_code(&code)?
                    .ok_or("code")?;
                assert_eq!(
                    stored.dpop_jkt.as_ref().map(DpopKeyThumbprint::as_str),
                    Some(key.jkt.as_str())
                );
                redeem_bound(state, &code, &key).await?;
            }
        }
    }
    for par in [false, true] {
        for bad_header in [
            header(None),
            json!({"alg":"RSA-OAEP","enc":"A256GCM","kid":"binding-active"}),
            json!({"alg":"RSA-OAEP","enc":"A256GCM","cty":"other","kid":"binding-active"}),
            header(Some("unknown")),
        ] {
            let jwt = signed(state, Some(json!(key.jkt)), None)?;
            denied(
                state,
                sid,
                &active.seal(&bad_header.to_string(), jwt.as_bytes())?,
                par,
            )
            .await?;
        }
        let jwt = signed(state, Some(json!(key.jkt)), None)?;
        let (input, sig) = jwt.rsplit_once('.').ok_or("signature")?;
        let mut sig = URL_SAFE_NO_PAD.decode(sig)?;
        sig[0] ^= 1;
        let bad = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig));
        denied(
            state,
            sid,
            &active.seal(&header(Some("binding-active")).to_string(), bad.as_bytes())?,
            par,
        )
        .await?;
        denied(
            state,
            sid,
            &active.seal(
                &header(Some("binding-active")).to_string(),
                br#"{"dpop_jkt":"untrusted"}"#,
            )?,
            par,
        )
        .await?;
    }
    // An admitted pushed object retains its exact original encrypted bytes and key
    // after retirement; a fresh object must still pass the current keyring.
    let jwt = signed(state, Some(json!(key.jkt)), None)?;
    let jwe = old.seal(&header(Some("binding-old")).to_string(), jwt.as_bytes())?;
    let pairs = pushed(state, sid, &jwe, &key).await?;
    sqlx::query("UPDATE aegaeon.runtime_keys SET retiring_expires_at=now()-interval '1 second' WHERE environment_id=$1 AND kid='binding-old'")
        .bind(state.environment_id).execute(&state.db_pool).await?;
    reload_authorization_runtime(state).await?;
    denied(state, sid, &jwe, false).await?;
    let fresh_sid = state
        .browser_auth
        .auth_sessions
        .create(
            "consent-user",
            AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?),
            None,
            None,
            None,
        )
        .ok_or("session")?;
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), fresh_sid);
    let page = authorize(&mut browser, state, &pairs, true).await?;
    let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
    redeem_bound(state, &code, &key).await
}

pub(super) async fn positive_age(state: &mut AppState, _sid: &str) -> TestResult {
    let (_, active) = prepare(state).await?;
    let key = Key::new(state)?;
    for (post, par) in [(false, false), (false, true), (true, false), (true, true)] {
        let sid = super::positive_age::old_session(state)?;
        let jwt = super::positive_age::signed_age(state, Some(&key))?;
        let jwe = active.seal(&header(Some("binding-active")).to_string(), jwt.as_bytes())?;
        let pairs = if par {
            pushed(state, &sid, &jwe, &key).await?
        } else {
            vec![("client_id".into(), CLIENT.into()), ("request".into(), jwe)]
        };
        let mut browser = Browser::default();
        browser.cookies.insert("aegaeon_auth_session".into(), sid);
        let page = authorize(&mut browser, state, &pairs, post).await?;
        assert!(page
            .location
            .as_deref()
            .is_some_and(|location| location.starts_with("/auth/login")));
        let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
        redeem_bound(state, &code, &key).await?;
    }
    Ok(())
}
