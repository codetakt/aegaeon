use super::*;

fn altered_proof(state: &AppState, key: &Key, change: &str) -> TestResult<String> {
    let proof = key.proof(state, "/par", json!({}))?;
    let mut parts = proof.split('.');
    let mut header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next().ok_or("header")?)?)?;
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next().ok_or("claims")?)?)?;
    match change {
        "typ" => header["typ"] = json!("JWT"),
        "alg" => header["alg"] = json!("HS256"),
        "private" => header["jwk"]["d"] = json!(URL_SAFE_NO_PAD.encode([7; 32])),
        "jwk" => header["jwk"]["x"] = json!("not-a-public-key"),
        "missing-jti" => {
            claims.as_object_mut().ok_or("claims")?.remove("jti");
        }
        _ => return Err("unknown mutation".into()),
    }
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
    );
    let signing = aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(&key.material.pkcs8)?;
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signing.sign(input.as_bytes())?)
    ))
}
pub(super) async fn proofs(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    let pairs = fields(state, None)?;
    for change in ["typ", "alg", "private", "jwk", "missing-jti"] {
        let proof = altered_proof(state, &key, change)?;
        let count = par::saved_count(state)?;
        let (status, body) = par::submit(state, sid, &pairs, Some(&proof)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{change}: {body}");
        assert_eq!(body["error"], "invalid_dpop_proof");
        assert_eq!(par::saved_count(state)?, count);
    }
    let proof = key.proof(state, "/par", json!({}))?;
    let headers = request_headers(state, Some(&proof))?;
    if headers.contains_key(header::AUTHORIZATION) {
        let mut invalid = headers.clone();
        invalid.insert(
            header::AUTHORIZATION,
            "Basic Y29uc2VudC1jbGllbnQ6d3Jvbmc=".parse()?,
        );
        let (status, body) = json_reply(
            raw(
                state,
                sid,
                Method::POST,
                "/par",
                serde_urlencoded::to_string(&pairs)?,
                invalid,
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client");
    }
    assert_eq!(
        par::submit(state, sid, &pairs, Some(&proof)).await?.0,
        StatusCode::CREATED
    );
    Ok(())
}
pub(super) async fn duplicate_claims(state: &AppState, sid: &str) -> TestResult {
    let key = Key::new(state)?;
    for name in ["dpop_jkt", r"\u0064pop_jkt"] {
        let jwt = signed(state, Some(json!(key.jkt)), None)?;
        let mut parts = jwt.split('.');
        let header = parts.next().ok_or("header")?;
        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next().ok_or("payload")?)?)?;
        let payload = format!(
            r#"{},"{}":"{}"}}"#,
            payload.strip_suffix('}').ok_or("json")?,
            name,
            key.jkt
        );
        let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(payload));
        let encoding = jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../../../../../tests/fixtures/rsa2048-private.pk8.pem"
        ))?;
        let signature = jsonwebtoken::crypto::sign(
            input.as_bytes(),
            &encoding,
            jsonwebtoken::Algorithm::RS256,
        )?;
        let pairs = vec![
            ("client_id".into(), CLIENT.into()),
            ("request".into(), format!("{input}.{signature}")),
        ];
        for post in [false, true] {
            admission::rejected(state, sid, post, &pairs, "", "invalid_request").await?;
        }
        let (status, body) = par::submit(state, sid, &pairs, None).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
    }
    Ok(())
}
