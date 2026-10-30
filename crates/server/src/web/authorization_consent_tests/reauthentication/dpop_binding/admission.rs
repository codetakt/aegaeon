use super::*;

pub(super) async fn rejected(
    state: &AppState,
    sid: &str,
    post: bool,
    pairs: &[(String, String)],
    suffix: &str,
    error: &str,
) -> TestResult {
    let encoded = format!("{}{suffix}", serde_urlencoded::to_string(pairs)?);
    let (uri, body) = if post {
        ("/authorize".to_string(), encoded)
    } else {
        (format!("/authorize?{encoded}"), String::new())
    };
    let before = state.tokens.issuer.code_store.snapshot().codes.len();
    let response = raw(
        state,
        sid,
        if post { Method::POST } else { Method::GET },
        &uri,
        body,
        form_headers(None)?,
    )
    .await?;
    // Error delivery uses JSON when strict redirects are disabled in this fixture.
    let (status, value) = json_reply(response).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
    assert_eq!(value["error"], error);
    assert_eq!(
        state.tokens.issuer.code_store.snapshot().codes.len(),
        before
    );
    Ok(())
}
pub(super) async fn run(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    let other = Key::new(state)?;
    let invalid = [
        key.jkt[..42].to_owned(),
        format!("{}A", key.jkt),
        format!("{}=", key.jkt),
        format!(" {}", key.jkt),
        format!("urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}", key.jkt),
        "!".repeat(43),
        format!("{}B", &key.jkt[..42]),
    ];
    for post in [false, true] {
        for value in &invalid {
            rejected(
                state,
                sid,
                post,
                &fields(state, None)?,
                &format!(
                    "&dpop_jkt={}",
                    url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
                ),
                "invalid_request",
            )
            .await?;
        }
        for suffix in [
            format!("&dpop_jkt={}&%64pop_jkt={}", key.jkt, key.jkt),
            format!("&dpop_jkt={}&dpop_jkt={}", key.jkt, other.jkt),
            "&unknown=%GG".into(),
            "&%FF=value".into(),
            "&unknown=%FF".into(),
        ] {
            rejected(
                state,
                sid,
                post,
                &fields(state, None)?,
                &suffix,
                "invalid_request",
            )
            .await?;
        }
        for suffix in [
            format!("&dpop_jkt=&%64pop_jkt={}", key.jkt),
            format!("&dpop_jkt={}&dpop_jkt=", key.jkt),
            "&dpop_jkt=&dpop_jkt=".into(),
        ] {
            let mut pairs = fields(state, None)?;
            pairs.extend(serde_urlencoded::from_str::<Vec<(String, String)>>(
                &suffix[1..],
            )?);
            let mut browser = Browser::default();
            browser
                .cookies
                .insert("aegaeon_auth_session".into(), sid.into());
            let page = authorize(&mut browser, state, &pairs, post).await?;
            let bound = suffix.contains(&key.jkt);
            let code = finish(&mut browser, state, page, bound.then_some(key.jkt.as_str())).await?;
            if bound {
                redeem_bound(state, &code, &key).await?;
            } else {
                assert_eq!(token(state, &code, None).await?.0, StatusCode::OK);
            }
        }
        for value in [
            json!(""),
            Value::Null,
            json!(7),
            json!([]),
            json!({}),
            json!("bad"),
        ] {
            let pairs = vec![
                ("client_id".into(), CLIENT.into()),
                ("request".into(), signed(state, Some(value), None)?),
            ];
            rejected(state, sid, post, &pairs, "", "invalid_request").await?;
        }
        for outer in [
            None,
            Some(key.jkt.as_str()),
            Some(other.jkt.as_str()),
            Some("malformed!"),
        ] {
            let mut pairs = vec![
                ("client_id".into(), CLIENT.into()),
                ("request".into(), signed(state, Some(json!(key.jkt)), None)?),
            ];
            if let Some(value) = outer {
                pairs.push(("dpop_jkt".into(), value.into()));
            }
            let mut browser = Browser::default();
            browser
                .cookies
                .insert("aegaeon_auth_session".into(), sid.into());
            let page = authorize(&mut browser, state, &pairs, post).await?;
            let code = finish(&mut browser, state, page, Some(&key.jkt)).await?;
            redeem_bound(state, &code, &key).await?;
        }
    }
    direct_headers(state, sid, &key).await?;
    valid_direct_headers(state, sid, &key, &other).await
}
async fn direct_headers(state: &AppState, sid: &str, key: &Key) -> TestResult {
    for parameter in [false, true] {
        for duplicate in [false, true] {
            let mut pairs = fields(state, None)?;
            if parameter {
                pairs.push(("dpop_jkt".into(), key.jkt.clone()));
            }
            let mut headers = HeaderMap::new();
            headers.append("DPoP", "invalid proof".parse()?);
            if duplicate {
                headers.append("DPoP", "second invalid proof".parse()?);
            }
            let response = raw(
                state,
                sid,
                Method::GET,
                &format!("/authorize?{}", serde_urlencoded::to_string(pairs)?),
                String::new(),
                headers,
            )
            .await?;
            assert_eq!(response.status(), StatusCode::FOUND);
            let url = url::Url::parse(response.headers()[header::LOCATION].to_str()?)?;
            let code = url
                .query_pairs()
                .find(|(k, _)| k == "code")
                .ok_or("code")?
                .1
                .into_owned();
            let record = state
                .tokens
                .issuer
                .code_store
                .try_get_code(&code)?
                .ok_or("stored code")?;
            assert_eq!(
                record.dpop_jkt.as_ref().map(DpopKeyThumbprint::as_str),
                parameter.then_some(key.jkt.as_str())
            );
        }
    }
    Ok(())
}

async fn valid_direct_headers(state: &AppState, sid: &str, key: &Key, other: &Key) -> TestResult {
    for post in [false, true] {
        for parameter in [false, true] {
            let mut pairs = fields(state, None)?;
            if parameter {
                pairs.push(("dpop_jkt".into(), key.jkt.clone()));
            }
            let header_key = if parameter { other } else { key };
            let method = if post { Method::POST } else { Method::GET };
            let proof = header_key.proof(state, "/authorize", json!({"htm":method.as_str()}))?;
            let encoded = serde_urlencoded::to_string(&pairs)?;
            let (uri, body) = if post {
                ("/authorize".to_string(), encoded)
            } else {
                (format!("/authorize?{encoded}"), String::new())
            };
            let response = raw(state, sid, method, &uri, body, form_headers(Some(&proof))?).await?;
            assert_eq!(response.status(), StatusCode::FOUND);
            let url = url::Url::parse(response.headers()[header::LOCATION].to_str()?)?;
            let code = url
                .query_pairs()
                .find(|(k, _)| k == "code")
                .ok_or("code")?
                .1
                .into_owned();
            let record = state
                .tokens
                .issuer
                .code_store
                .try_get_code(&code)?
                .ok_or("record")?;
            assert_eq!(
                record.dpop_jkt.as_ref().map(DpopKeyThumbprint::as_str),
                parameter.then_some(key.jkt.as_str())
            );
            if parameter {
                redeem_bound(state, &code, key).await?;
            } else {
                assert_eq!(token(state, &code, None).await?.0, StatusCode::OK);
            }
        }
    }
    Ok(())
}
