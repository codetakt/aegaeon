use super::*;

fn authorization_pairs(
    state: &AppState,
    challenge: Option<&str>,
    method: Option<&str>,
) -> Vec<(String, String)> {
    let mut pairs = vec![
        ("client_id", BASIC.to_owned()),
        ("response_type", "code".into()),
        ("redirect_uri", REDIRECT.into()),
        ("scope", "api.read".into()),
        ("iss", state.issuer.to_string()),
        ("state", Uuid::new_v4().to_string()),
    ];
    if let Some(value) = challenge {
        pairs.push(("code_challenge", value.into()));
    }
    if let Some(value) = method {
        pairs.push(("code_challenge_method", value.into()));
    }
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}
fn signed(state: &AppState, pairs: &[(String, String)]) -> TestResult<String> {
    let now = crate::util::now_unix_epoch_secs()?;
    let mut claims = json!({"iss":BASIC,"aud":state.issuer.as_str(),"iat":now,"exp":now+60,"jti":Uuid::new_v4().to_string()});
    for (key, value) in pairs {
        if key != "iss" {
            claims[key] = json!(value);
        }
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.typ = Some("oauth-authz-req+jwt".into());
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(PEM)?,
    )?)
}
async fn authorize(
    state: &AppState,
    sid: &str,
    pairs: &[(String, String)],
) -> TestResult<(StatusCode, Value)> {
    let app = super::super::router::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let response = app
        .oneshot(
            Request::get(format!(
                "/authorize?{}",
                serde_urlencoded::to_string(pairs)?
            ))
            .header(header::COOKIE, format!("aegaeon_auth_session={sid}"))
            .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    Ok((
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?,
    ))
}
async fn attempt(
    state: &AppState,
    sid: &str,
    mode: &str,
    challenge: Option<&str>,
    method: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    let pairs = authorization_pairs(state, challenge, method);
    let request;
    let resolved = if mode.contains("jar") {
        request = signed(state, &pairs)?;
        vec![
            ("client_id".into(), BASIC.into()),
            ("request".into(), request),
        ]
    } else {
        pairs
    };
    if mode.starts_with("par") {
        // Signed PAR allows only request plus authentication parameters.
        let pairs: Vec<(&str, &str)> = resolved
            .iter()
            .filter(|(key, _)| !mode.contains("jar") || key != "client_id")
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        send(state, "/par", &pairs, Some(&basic())).await
    } else {
        authorize(state, sid, &resolved).await
    }
}
async fn exchange(
    state: &AppState,
    code: &str,
    verifier: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT),
    ];
    if let Some(value) = verifier {
        pairs.push(("code_verifier", value));
    }
    send(state, "/token", &pairs, Some(&basic())).await
}
async fn admission(state: &AppState, sid: &str) -> TestResult {
    for mode in ["plain", "jar", "par", "par-jar"] {
        for challenge in [
            String::new(),
            "A".repeat(42),
            "A".repeat(129),
            format!("{}é", "A".repeat(42)),
            format!("{}=", "A".repeat(42)),
            format!("{}\n", "A".repeat(42)),
        ] {
            let codes = state.tokens.issuer.code_store.snapshot().codes.len();
            let pushed = par_count(state)?;
            let (status, body) = attempt(state, sid, mode, Some(&challenge), Some("S256")).await?;
            assert!(status.is_client_error(), "{mode} {body}");
            assert_eq!(body["error"], "invalid_request", "{mode} {body}");
            assert!(body.get("code").is_none() && body.get("request_uri").is_none());
            assert_eq!(state.tokens.issuer.code_store.snapshot().codes.len(), codes);
            assert_eq!(par_count(state)?, pushed);
        }
        for (challenge, method) in [
            (Some(CHALLENGE), None),
            (None, Some("S256")),
            (Some(CHALLENGE), Some("plain")),
            (Some(CHALLENGE), Some("")),
        ] {
            let (status, body) = attempt(state, sid, mode, challenge, method).await?;
            assert!(status.is_client_error(), "{mode} {body}");
            assert_eq!(body["error"], "invalid_request", "{mode} {body}");
        }
        for length in [43, 128] {
            let challenge = format!("{}.~_-", "A".repeat(length - 4));
            let (status, body) = attempt(state, sid, mode, Some(&challenge), Some("S256")).await?;
            assert!(status.is_success(), "{mode} {body}");
            if mode.starts_with("par") {
                let uri = body["request_uri"].as_str().ok_or("request_uri")?;
                let stored = state
                    .protocol
                    .par_store
                    .try_consume_request(uri)
                    .map_err(|e| format!("{e:?}"))?
                    .ok_or("pushed request")?;
                assert_eq!(stored.code_challenge.as_deref(), Some(challenge.as_str()));
            } else {
                let code = body["code"].as_str().ok_or("code")?;
                assert_eq!(
                    state
                        .tokens
                        .issuer
                        .code_store
                        .try_get_code(code)?
                        .ok_or("retained code")?
                        .code_challenge
                        .as_deref(),
                    Some(challenge.as_str())
                );
                let (status, body) = exchange(state, code, Some(VERIFIER)).await?;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
                assert_eq!(body["error"], "invalid_grant");
            }
        }
    }
    Ok(())
}
async fn bindings(state: &AppState, sid: &str) -> TestResult {
    for mode in ["plain", "jar"] {
        let (status, body) = attempt(state, sid, mode, Some(CHALLENGE), Some("S256")).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let code = body["code"].as_str().ok_or("code")?;
        for verifier in [None, Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] {
            let (status, body) = exchange(state, code, verifier).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["error"], "invalid_grant");
            assert!(body.get("access_token").is_none());
        }
        let (status, body) = exchange(state, code, Some(VERIFIER)).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["access_token"].is_string());
        assert!(exchange(state, code, Some(VERIFIER))
            .await?
            .0
            .is_client_error());
    }
    // Persisted profiles require PKCE. Exercise the existing optional public
    // issuer API without fabricating a profile that the schema cannot admit.
    assert!(attempt(state, sid, "plain", None, None)
        .await?
        .0
        .is_client_error());
    let request = serde_json::from_value(
        json!({"response_type":"code","client_id":BASIC,"redirect_uri":REDIRECT,"scope":"api.read"}),
    )?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code_with_pkce_required(request, "pkce-user".into(), false, 0, None)?;
    let code = code.as_str();
    let (status, body) = exchange(state, code, Some(VERIFIER)).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("access_token").is_none());
    let (status, body) = exchange(state, code, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());
    for mode in ["jar", "par", "par-jar"] {
        assert!(attempt(state, sid, mode, None, None)
            .await?
            .0
            .is_client_error());
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn pkce_admission_http_plain_par_signed_and_optional_retained_binding() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        update_test_policy(&mut state, |policy| {
            policy.strict_authorize_redirect = false;
        })
        .await?;
        let sid = state
            .browser_auth
            .auth_sessions
            .create(
                "pkce-user",
                crate::web::AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?),
                None,
                None,
                None,
            )
            .ok_or("session")?;
        admission(&state, &sid).await?;
        bindings(&state, &sid).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
