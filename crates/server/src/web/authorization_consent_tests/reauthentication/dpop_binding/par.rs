use super::*;

pub(super) fn saved_count(state: &AppState) -> TestResult<usize> {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let prefix = namespace.redis_atomic_group_prefix(
        crate::config::RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
        "par",
        "v3",
    );
    let mut conn =
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?.get_connection()?;
    Ok(redis::cmd("KEYS")
        .arg(format!("{prefix}:req:*"))
        .query::<Vec<String>>(&mut conn)?
        .len())
}
pub(super) async fn submit(
    state: &AppState,
    sid: &str,
    pairs: &[(String, String)],
    proof: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    json_reply(
        raw(
            state,
            sid,
            Method::POST,
            "/par",
            serde_urlencoded::to_string(pairs)?,
            request_headers(state, proof)?,
        )
        .await?,
    )
    .await
}
pub(super) async fn push(
    state: &AppState,
    sid: &str,
    mode: &str,
    key: &Key,
    prompt: Option<&str>,
) -> TestResult<Vec<(String, String)>> {
    let header = mode.contains("header") || mode.ends_with("both");
    let parameter = mode.contains("parameter") || mode.contains("claim") || mode.ends_with("both");
    let pairs = if mode.contains("jar") {
        vec![
            ("client_id".into(), CLIENT.into()),
            (
                "request".into(),
                signed(state, parameter.then(|| json!(key.jkt)), prompt)?,
            ),
        ]
    } else {
        let mut pairs = fields(state, prompt)?;
        if parameter {
            pairs.push(("dpop_jkt".into(), key.jkt.clone()));
        }
        if prompt.is_some() {
            pairs.push(("max_age".into(), "0".into()));
        }
        pairs
    };
    let proof = header
        .then(|| key.proof(state, "/par", json!({})))
        .transpose()?;
    let (status, body) = submit(state, sid, &pairs, proof.as_deref()).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    Ok(vec![
        ("client_id".into(), CLIENT.into()),
        (
            "request_uri".into(),
            body["request_uri"].as_str().ok_or("PAR URI")?.into(),
        ),
        ("dpop_jkt".into(), "ignored-outer-key".into()),
    ])
}
async fn reject(
    state: &AppState,
    sid: &str,
    pairs: &[(String, String)],
    proof: Option<&str>,
    error: &str,
) -> TestResult {
    let before = saved_count(state)?;
    let (status, body) = submit(state, sid, pairs, proof).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], error);
    assert_eq!(saved_count(state)?, before);
    Ok(())
}
pub(super) async fn run(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    let wrong = Key::new(state)?;
    for jar in [false, true] {
        let pairs = if jar {
            vec![
                ("client_id".into(), CLIENT.into()),
                ("request".into(), signed(state, Some(json!(key.jkt)), None)?),
            ]
        } else {
            let mut pairs = fields(state, None)?;
            pairs.push(("dpop_jkt".into(), key.jkt.clone()));
            pairs
        };
        let proof = wrong.proof(state, "/par", json!({}))?;
        reject(state, sid, &pairs, Some(&proof), "invalid_request").await?;
        // The wrong DPoP proof was spent; the same valid JAR can still be admitted.
        reject(state, sid, &pairs, Some(&proof), "invalid_dpop_proof").await?;
        let proof = key.proof(state, "/par", json!({}))?;
        assert_eq!(
            submit(state, sid, &pairs, Some(&proof)).await?.0,
            StatusCode::CREATED
        );
    }
    for outer in [&key.jkt, &wrong.jkt, "malformed"] {
        let jwt = signed(state, Some(json!(key.jkt)), None)?;
        let mut pairs = vec![("client_id".into(), CLIENT.into()), ("request".into(), jwt)];
        pairs.push(("dpop_jkt".into(), outer.into()));
        reject(state, sid, &pairs, None, "invalid_request").await?;
        pairs.pop();
        assert_eq!(
            submit(state, sid, &pairs, None).await?.0,
            StatusCode::CREATED
        );
    }
    let pairs = fields(state, None)?;
    for extra in [
        json!({"htm":"GET"}),
        json!({"htu":"https://wrong.example/par"}),
        json!({"jti":""}),
        json!({"iat":0}),
    ] {
        let proof = key.proof(state, "/par", extra)?;
        reject(state, sid, &pairs, Some(&proof), "invalid_dpop_proof").await?;
    }
    reject(state, sid, &pairs, Some("malformed"), "invalid_dpop_proof").await?;
    let proof = key.proof(state, "/par", json!({}))?;
    let (input, signature) = proof.rsplit_once('.').ok_or("signature")?;
    let mut signature = URL_SAFE_NO_PAD.decode(signature)?;
    signature[0] ^= 1;
    reject(
        state,
        sid,
        &pairs,
        Some(&format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))),
        "invalid_dpop_proof",
    )
    .await?;
    let jti = Uuid::new_v4().to_string();
    let proof = key.proof(state, "/par", json!({"jti":jti}))?;
    assert_eq!(
        submit(state, sid, &pairs, Some(&proof)).await?.0,
        StatusCode::CREATED
    );
    reject(state, sid, &pairs, Some(&proof), "invalid_dpop_proof").await?;
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let mut pairs = fields(state, None)?;
    pairs.push(("dpop_jkt".into(), key.jkt.clone()));
    let page = authorize(&mut browser, state, &pairs, false).await?;
    let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
    let token_proof = key.proof(state, "/token", json!({"jti":jti}))?;
    assert_eq!(
        token(state, &code, Some(&token_proof)).await?.1["error"],
        "invalid_dpop_proof"
    );
    redeem_bound(state, &code, &key).await?;
    strict_forms(state, sid, &key).await
}
async fn strict_forms(state: &AppState, sid: &str, key: &Key) -> TestResult {
    empty_values(state, sid, key).await?;
    let encoded = serde_urlencoded::to_string(fields(state, None)?)?;
    for suffix in [
        "&unknown=%GG".into(),
        "&unknown=%FF".into(),
        "&%FF=known".into(),
        format!("&dpop_jkt={}&%64pop_jkt={}", key.jkt, key.jkt),
    ] {
        let response = raw(
            state,
            sid,
            Method::POST,
            "/par",
            format!("{encoded}{suffix}"),
            request_headers(state, None)?,
        )
        .await?;
        assert_eq!(json_reply(response).await?.1["error"], "invalid_request");
    }
    let mut wrong_type = request_headers(state, None)?;
    wrong_type.insert(header::CONTENT_TYPE, "application/json".parse()?);
    let before = saved_count(state)?;
    let (status, body) = json_reply(
        raw(
            state,
            sid,
            Method::POST,
            "/par",
            encoded.clone(),
            wrong_type,
        )
        .await?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(saved_count(state)?, before);
    let mut headers = request_headers(state, None)?;
    headers.append(
        header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse()?,
    );
    assert_eq!(
        json_reply(raw(state, sid, Method::POST, "/par", encoded.clone(), headers).await?)
            .await?
            .1["error"],
        "invalid_request"
    );
    for duplicate in [false, true] {
        let mut headers = request_headers(state, None)?;
        headers.append("DPoP", axum::http::HeaderValue::from_bytes(&[0xff])?);
        if duplicate {
            headers.append("DPoP", "second".parse()?);
        }
        assert_eq!(
            json_reply(raw(state, sid, Method::POST, "/par", encoded.clone(), headers).await?)
                .await?
                .1["error"],
            "invalid_dpop_proof"
        );
    }
    // A PAR form exceeds the front-channel 16 KiB cap without acquiring that cap.
    let body = format!("{encoded}&unknown={}", "x".repeat(32 * 1024));
    let response = raw(
        state,
        sid,
        Method::POST,
        &format!("/par?dpop_jkt={}", key.jkt),
        body,
        request_headers(state, None)?,
    )
    .await?;
    let (status, value) = json_reply(response).await?;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let pairs = vec![
        ("client_id".into(), CLIENT.into()),
        (
            "request_uri".into(),
            value["request_uri"].as_str().ok_or("request_uri")?.into(),
        ),
    ];
    let mut browser = Browser::default();
    browser
        .cookies
        .insert("aegaeon_auth_session".into(), sid.into());
    let page = authorize(&mut browser, state, &pairs, false).await?;
    let code = finish(&mut browser, state, page, None).await?;
    assert_eq!(token(state, &code, None).await?.0, StatusCode::OK);
    Ok(())
}

async fn empty_values(state: &AppState, sid: &str, key: &Key) -> TestResult {
    for values in [["", key.jkt.as_str()], [key.jkt.as_str(), ""], ["", ""]] {
        let mut pairs = fields(state, None)?;
        pairs.extend(values.map(|value| ("dpop_jkt".to_string(), value.to_string())));
        let (status, value) = submit(state, sid, &pairs, None).await?;
        assert_eq!(status, StatusCode::CREATED, "{value}");
        let uri = value["request_uri"].as_str().ok_or("uri")?;
        let expected = values
            .iter()
            .any(|value| !value.is_empty())
            .then_some(key.jkt.as_str());
        assert_eq!(
            stored_par(state, uri)?.0["request"]["dpop_jkt"],
            json!(expected)
        );
        let pairs = vec![
            ("client_id".into(), CLIENT.into()),
            ("request_uri".into(), uri.into()),
        ];
        let mut browser = Browser::default();
        browser
            .cookies
            .insert("aegaeon_auth_session".into(), sid.into());
        let page = authorize(&mut browser, state, &pairs, false).await?;
        let code = finish(&mut browser, state, page, expected).await?;
        if expected.is_some() {
            redeem_bound(state, &code, key).await?;
        } else {
            assert_eq!(token(state, &code, None).await?.0, StatusCode::OK);
        }
    }
    Ok(())
}
